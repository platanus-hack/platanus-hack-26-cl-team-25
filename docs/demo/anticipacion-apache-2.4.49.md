# Anticipación — Apache HTTP Server 2.4.49

Fecha: 2026-11-21 15:06 · duración 34 s · modelo `opus`

Análisis defensivo de **código fuente público** en un laboratorio aislado. No se ejecutó el servidor ni se envió tráfico.

## Resultado

| Versión | Propiedades del normalizador |
|---|---|
| 2.4.49 (publicada) | 14/21 |
| **Parche sugerido** | **21/21** |
| 2.4.50 (parche oficial) | 21/21 |

Comportamiento del sugerido frente al oficial: **21/21 vectores idénticos**.

Ubicación: sugerido en server/util.c:ap_normalize_path; oficial en server/util.c:ap_normalize_path; misma función: **sí**; líneas superpuestas: sí; tamaño 15 vs 20 líneas.

## Hallazgos del modelo

- **server/util.c:571 `ap_normalize_path`** — Percent-decoding of unreserved characters is applied only at the current read position, so a dot-segment whose second dot is percent-encoded is not recognised as a parent-directory segment and survives normalization.
  - Precondición: AP_NORMALIZE_DECODE_UNRESERVED is set (as it is for every request) and the request path has a segment made of a literal dot followed by a percent-encoded dot, ending at a slash or the end of the path.
  - Impacto: The normalized URI keeps real parent-directory segments and the not-above-root check is skipped, so mapping it to the filesystem escapes the document root or alias directory. This can disclose files outside the served tree, or execute arbitrary programs if CGI is enabled for an aliased directory.
  - Arreglo: In the dot-segment branch, when unreserved decoding is enabled and the dot is followed by an encoded dot and then a separator or the end of the path, the encoded dot is decoded in place before the existing '..' check, so the normal parent-segment removal and NOT_ABOVE_ROOT failure apply. This fixes the root cause, which was the look-ahead reading undecoded data. (confianza high)

## Parche sugerido

```diff
diff --git a/server/util.c b/server/util.c
index 2a7fdda..d8bc2b2 100644
--- a/server/util.c
+++ b/server/util.c
@@ -567,7 +567,20 @@ AP_DECLARE(int) ap_normalize_path(char *path, unsigned int flags)
                     continue;
                 }
 
-                /* Remove /xx/../ segments */
+                /* Remove /xx/../ segments (or /xx/.%2e/ when
+                 * AP_NORMALIZE_DECODE_UNRESERVED is set, since only the
+                 * current char was decoded above and the second dot may
+                 * still be encoded)
+                 */
+                if ((flags & AP_NORMALIZE_DECODE_UNRESERVED)
+                        && path[l + 1] == '%' && path[l + 2] == '2'
+                        && (path[l + 3] == 'e' || path[l + 3] == 'E')
+                        && IS_SLASH_OR_NUL(path[l + 4])) {
+                    /* Decode in place so that the check below applies */
+                    l += 2;
+                    path[l] = '.';
+                    path[l + 1] = '.';
+                }
                 if (path[l + 1] == '.' && IS_SLASH_OR_NUL(path[l + 2])) {
                     /* Wind w back to remove the previous segment */
                     if (w > 1) {
```

## Parche oficial (2.4.49 → 2.4.50, mismos archivos)

```diff
diff --git a/server/util.c b/server/util.c
index 2a7fdda..896574b 100644
--- a/server/util.c
+++ b/server/util.c
@@ -502,7 +502,8 @@ static char x2c(const char *what);
 AP_DECLARE(int) ap_normalize_path(char *path, unsigned int flags)
 {
     int ret = 1;
-    apr_size_t l = 1, w = 1;
+    apr_size_t l = 1, w = 1, n;
+    int decode_unreserved = (flags & AP_NORMALIZE_DECODE_UNRESERVED) != 0;
 
     if (!IS_SLASH(path[0])) {
         /* Besides "OPTIONS *", a request-target should start with '/'
@@ -529,7 +530,7 @@ AP_DECLARE(int) ap_normalize_path(char *path, unsigned int flags)
          *  be decoded to their corresponding unreserved characters by
          *  URI normalizers.
          */
-        if ((flags & AP_NORMALIZE_DECODE_UNRESERVED)
+        if (decode_unreserved
                 && path[l] == '%' && apr_isxdigit(path[l + 1])
                                   && apr_isxdigit(path[l + 2])) {
             const char c = x2c(&path[l + 1]);
@@ -567,8 +568,17 @@ AP_DECLARE(int) ap_normalize_path(char *path, unsigned int flags)
                     continue;
                 }
 
-                /* Remove /xx/../ segments */
-                if (path[l + 1] == '.' && IS_SLASH_OR_NUL(path[l + 2])) {
+                /* Remove /xx/../ segments (or /xx/.%2e/ when
+                 * AP_NORMALIZE_DECODE_UNRESERVED is set since we
+                 * decoded only the first dot above).
+                 */
+                n = l + 1;
+                if ((path[n] == '.' || (decode_unreserved
+                                        && path[n] == '%'
+                                        && path[++n] == '2'
+                                        && (path[++n] == 'e'
+                                            || path[n] == 'E')))
+                        && IS_SLASH_OR_NUL(path[n + 1])) {
                     /* Wind w back to remove the previous segment */
                     if (w > 1) {
                         do {
@@ -585,7 +595,7 @@ AP_DECLARE(int) ap_normalize_path(char *path, unsigned int flags)
                     }
 
                     /* Move l forward to the next segment */
-                    l += 2;
+                    l = n + 1;
                     if (path[l]) {
                         l++;
                     }
```

## Vectores

| Tipo | Entrada | Esperado | vulnerable | suggested | official |
|---|---|---|---|---|---|
| legit | `/index.html` | ret=1 /index.html | ✅ `ret=1 /index.html` | ✅ `ret=1 /index.html` | ✅ `ret=1 /index.html` |
| legit | `/docs/v1.2/guide.html` | ret=1 /docs/v1.2/guide.html | ✅ `ret=1 /docs/v1.2/guide.html` | ✅ `ret=1 /docs/v1.2/guide.html` | ✅ `ret=1 /docs/v1.2/guide.html` |
| legit | `/a/./b` | ret=1 /a/b | ✅ `ret=1 /a/b` | ✅ `ret=1 /a/b` | ✅ `ret=1 /a/b` |
| legit | `/a/b/../c` | ret=1 /a/c | ✅ `ret=1 /a/c` | ✅ `ret=1 /a/c` | ✅ `ret=1 /a/c` |
| legit | `/a//b///c` | ret=1 /a/b/c | ✅ `ret=1 /a/b/c` | ✅ `ret=1 /a/b/c` | ✅ `ret=1 /a/b/c` |
| legit | `/~user/file` | ret=1 /~user/file | ✅ `ret=1 /~user/file` | ✅ `ret=1 /~user/file` | ✅ `ret=1 /~user/file` |
| legit | `/a/%41%62c` | ret=1 /a/Abc | ✅ `ret=1 /a/Abc` | ✅ `ret=1 /a/Abc` | ✅ `ret=1 /a/Abc` |
| legit | `/a/b%2Fc` | ret=1 /a/b%2Fc | ✅ `ret=1 /a/b%2Fc` | ✅ `ret=1 /a/b%2Fc` | ✅ `ret=1 /a/b%2Fc` |
| legit | `/a/...b/c` | ret=1 /a/...b/c | ✅ `ret=1 /a/...b/c` | ✅ `ret=1 /a/...b/c` | ✅ `ret=1 /a/...b/c` |
| legit | `/a/.hidden` | ret=1 /a/.hidden | ✅ `ret=1 /a/.hidden` | ✅ `ret=1 /a/.hidden` | ✅ `ret=1 /a/.hidden` |
| legit | `/a/%2ehidden` | ret=1 /a/.hidden | ✅ `ret=1 /a/.hidden` | ✅ `ret=1 /a/.hidden` | ✅ `ret=1 /a/.hidden` |
| legit | `/a/b/%2e/c` | ret=1 /a/b/c | ✅ `ret=1 /a/b/c` | ✅ `ret=1 /a/b/c` | ✅ `ret=1 /a/b/c` |
| dot-segment | `/a/b/.%2e/c` | no parent segment left | ❌ `ret=1 /a/b/../c` | ✅ `ret=1 /a/c` | ✅ `ret=1 /a/c` |
| dot-segment | `/a/b/%2e./c` | no parent segment left | ✅ `ret=1 /a/c` | ✅ `ret=1 /a/c` | ✅ `ret=1 /a/c` |
| dot-segment | `/a/b/%2e%2e/c` | no parent segment left | ❌ `ret=1 /a/b/../c` | ✅ `ret=1 /a/c` | ✅ `ret=1 /a/c` |
| dot-segment | `/a/b/.%2E/c` | no parent segment left | ❌ `ret=1 /a/b/../c` | ✅ `ret=1 /a/c` | ✅ `ret=1 /a/c` |
| dot-segment | `/a/b/%2E%2E/c` | no parent segment left | ❌ `ret=1 /a/b/../c` | ✅ `ret=1 /a/c` | ✅ `ret=1 /a/c` |
| dot-segment | `/a/.%2e` | no parent segment left | ❌ `ret=1 /a/..` | ✅ `ret=1 /` | ✅ `ret=1 /` |
| dot-segment | `/x/.%2e/.%2e/.%2e/y` | rejected (ret=0), no parent segment | ❌ `ret=1 /x/../../../y` | ✅ `ret=0 /y` | ✅ `ret=0 /y` |
| dot-segment | `/.%2e/y` | rejected (ret=0), no parent segment | ❌ `ret=1 /../y` | ✅ `ret=0 /y` | ✅ `ret=0 /y` |
| dot-segment | `/x/../../y` | rejected (ret=0), no parent segment | ✅ `ret=0 /y` | ✅ `ret=0 /y` | ✅ `ret=0 /y` |

## Qué sabía el modelo

- Se le dijo: el producto y la versión (Apache HTTP Server 2.4.49), el área («URL path normalization that runs on every request before the path is mapped to the filesystem. It decodes percent-encoded unreserved characters and removes dot-segments.»), la clase de defecto con su mecanismo (traversal), un alcance de 1 archivo(s) (server/util.c) y qué comportamiento legítimo conservar.
- No se le dijo: el identificador del aviso (CVE-2021-41773 — public advisory, fixed upstream in 2.4.50), la versión corregida ni el parche oficial.
- Los vectores de prueba los escribió el equipo; el modelo nunca los ve.
- El aviso es público y casi con certeza está en los datos de entrenamiento del modelo: esto no es una prueba ciega.

## Qué significa 21 de 21

- Para cada una de las entradas de la tabla de vectores, la función extraída (server/util.c) compilada contra un shim devuelve el mismo par (valor de retorno, búfer de salida) con el parche sugerido que con el oficial.
- No demuestra equivalencia de comportamiento de Apache HTTP Server 2.4.49: no se compila ni se ejecuta el servidor, y fuera de esas entradas no se afirma nada.

## Cómo leer esto

- La evidencia no es lo que dice el modelo: son las propiedades mecánicas, compiladas y ejecutadas en un contenedor sin red.
- Para una prueba ciega, usar un aviso posterior a la fecha de corte del modelo.
- Para software de terceros la acción correcta en producción es contener con la regla del gateway y actualizar a la versión corregida.
