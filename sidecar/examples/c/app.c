/* Demo app in C that exists only to test the sidecar observer. Statically linked, no libraries:
 * a tiny HTTP/1.0 server plus a minimal PostgreSQL client (simple and extended query protocol,
 * trust authentication only). Identity comes from an `x-user` header (set by the sidecar's
 * identity_command in the shadow). Vulnerable routes are paired with safe ones.
 *
 * build: gcc -O2 -static -o app app.c   (see build.sh)
 */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *STATIC_DIR = "/app/static";
static const char *PG_USER = "capp";
static const char *PG_DB = "clone";
static int PG_PORT = 5432;

/* ------------------------------------------------------------------ small buffer */
typedef struct { char *p; size_t n, cap; } buf_t;
static void bput(buf_t *b, const void *d, size_t n) {
  if (b->n + n + 1 > b->cap) { b->cap = (b->n + n + 1) * 2; b->p = realloc(b->p, b->cap); }
  memcpy(b->p + b->n, d, n); b->n += n; b->p[b->n] = 0;
}
static void bputs(buf_t *b, const char *s) { bput(b, s, strlen(s)); }
static void bprintf(buf_t *b, const char *fmt, ...) {
  char tmp[512]; va_list ap; va_start(ap, fmt); int n = vsnprintf(tmp, sizeof tmp, fmt, ap); va_end(ap);
  bput(b, tmp, n < (int)sizeof tmp ? (size_t)n : sizeof tmp - 1);
}
static void bjson(buf_t *b, const char *s, size_t n) {
  bputs(b, "\"");
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '"' || c == '\\') { char e[2] = {'\\', (char)c}; bput(b, e, 2); }
    else if (c < 0x20) bprintf(b, "\\u%04x", c);
    else bput(b, &c, 1);
  }
  bputs(b, "\"");
}

/* ------------------------------------------------------------------ postgres */
static int readn(int fd, void *d, size_t n) {
  size_t got = 0;
  while (got < n) { ssize_t r = read(fd, (char *)d + got, n - got); if (r <= 0) return -1; got += r; }
  return 0;
}
static void put32(buf_t *b, int v) { uint32_t x = htonl((uint32_t)v); bput(b, &x, 4); }
static void put16(buf_t *b, int v) { uint16_t x = htons((uint16_t)v); bput(b, &x, 2); }
static void msg(buf_t *out, char t, buf_t *payload) {
  bput(out, &t, 1); put32(out, (int)payload->n + 4); bput(out, payload->p, payload->n);
}

static int pg_connect(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(PG_PORT)};
  inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
  if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
  buf_t body = {0}, out = {0};
  put32(&body, 196608);
  bputs(&body, "user"); bput(&body, "", 1); bputs(&body, PG_USER); bput(&body, "", 1);
  bputs(&body, "database"); bput(&body, "", 1); bputs(&body, PG_DB); bput(&body, "", 1); bput(&body, "", 1);
  put32(&out, (int)body.n + 4); bput(&out, body.p, body.n);
  write(fd, out.p, out.n); free(body.p); free(out.p);
  for (;;) {  /* until ReadyForQuery */
    char t; uint32_t len;
    if (readn(fd, &t, 1) || readn(fd, &len, 4)) { close(fd); return -1; }
    len = ntohl(len) - 4;
    char *p = malloc(len + 1);
    if (readn(fd, p, len)) { free(p); close(fd); return -1; }
    if (t == 'R' && ntohl(*(uint32_t *)p) != 0) { free(p); close(fd); return -1; } /* only trust auth */
    if (t == 'E') { free(p); close(fd); return -1; }
    free(p);
    if (t == 'Z') return fd;
  }
}

/* Read results until ReadyForQuery; rows appended to json as arrays of strings. 0 = ok, -1 = error. */
static int pg_results(int fd, buf_t *json) {
  int err = 0, first = 1;
  for (;;) {
    char t; uint32_t len;
    if (readn(fd, &t, 1) || readn(fd, &len, 4)) return -1;
    len = ntohl(len) - 4;
    char *p = malloc(len + 1);
    if (readn(fd, p, len)) { free(p); return -1; }
    if (t == 'D') {
      uint16_t nf = ntohs(*(uint16_t *)p); size_t pos = 2;
      bputs(json, first ? "[" : ",["); first = 0;
      for (int i = 0; i < nf; i++) {
        int32_t fl = (int32_t)ntohl(*(uint32_t *)(p + pos)); pos += 4;
        if (i) bputs(json, ",");
        if (fl < 0) bputs(json, "null"); else { bjson(json, p + pos, fl); pos += fl; }
      }
      bputs(json, "]");
    } else if (t == 'E') err = 1;
    free(p);
    if (t == 'Z') return err ? -1 : 0;
  }
}

static int pg_simple(const char *sql, buf_t *json) {
  int fd = pg_connect(); if (fd < 0) return -1;
  buf_t pl = {0}, out = {0};
  bput(&pl, sql, strlen(sql) + 1); msg(&out, 'Q', &pl);
  write(fd, out.p, out.n); free(pl.p); free(out.p);
  int r = pg_results(fd, json);
  buf_t x = {0}, xo = {0}; msg(&xo, 'X', &x); write(fd, xo.p, xo.n); free(xo.p);
  close(fd); return r;
}

static int pg_params(const char *sql, int n, const char **vals, buf_t *json) {
  int fd = pg_connect(); if (fd < 0) return -1;
  buf_t out = {0}, p = {0};
  bput(&p, "", 1); bput(&p, sql, strlen(sql) + 1); put16(&p, 0); msg(&out, 'P', &p); p.n = 0;
  bput(&p, "", 1); bput(&p, "", 1); put16(&p, 0); put16(&p, n);
  for (int i = 0; i < n; i++) { put32(&p, (int)strlen(vals[i])); bputs(&p, vals[i]); }
  put16(&p, 0); msg(&out, 'B', &p); p.n = 0;
  bput(&p, "", 1); put32(&p, 0); msg(&out, 'E', &p); p.n = 0;
  msg(&out, 'S', &p);
  write(fd, out.p, out.n); free(out.p); free(p.p);
  int r = pg_results(fd, json);
  buf_t x = {0}, xo = {0}; msg(&xo, 'X', &x); write(fd, xo.p, xo.n); free(xo.p);
  close(fd); return r;
}

/* ------------------------------------------------------------------ http */
static void urldecode(char *s) {
  char *o = s;
  for (; *s; s++) {
    if (*s == '+') *o++ = ' ';
    else if (*s == '%' && s[1] && s[2]) { char h[3] = {s[1], s[2], 0}; *o++ = (char)strtol(h, NULL, 16); s += 2; }
    else *o++ = *s;
  }
  *o = 0;
}
static int param(const char *query, const char *name, char *out, size_t cap) {
  size_t nl = strlen(name);
  for (const char *q = query; q && *q;) {
    const char *amp = strchr(q, '&'); size_t len = amp ? (size_t)(amp - q) : strlen(q);
    if (len > nl && !strncmp(q, name, nl) && q[nl] == '=') {
      size_t vl = len - nl - 1; if (vl >= cap) vl = cap - 1;
      memcpy(out, q + nl + 1, vl); out[vl] = 0; urldecode(out); return 1;
    }
    q = amp ? amp + 1 : NULL;
  }
  out[0] = 0; return 0;
}
static void respond(int c, int status, const char *ctype, const char *body, size_t n) {
  char head[256];
  int hl = snprintf(head, sizeof head, "HTTP/1.0 %d X\r\ncontent-type: %s\r\ncontent-length: %zu\r\nconnection: close\r\n\r\n",
                    status, ctype, n);
  write(c, head, hl); write(c, body, n);
}
static void json(int c, int status, const char *body) { respond(c, status, "application/json", body, strlen(body)); }

static void serve_file(int c, const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) { json(c, 404, "{\"detail\":\"not found\"}"); return; }
  buf_t b = {0}; char tmp[4096]; size_t n;
  while ((n = fread(tmp, 1, sizeof tmp, f)) > 0) bput(&b, tmp, n);
  fclose(f);
  respond(c, 200, "application/octet-stream", b.p ? b.p : "", b.n); free(b.p);
}

static void handle(int c) {
  char req[16384]; size_t got = 0;
  while (got < sizeof req - 1) {
    ssize_t r = read(c, req + got, sizeof req - 1 - got); if (r <= 0) break; got += r; req[got] = 0;
    if (strstr(req, "\r\n\r\n")) break;
  }
  req[got] = 0;
  char method[16] = {0}, target[8192] = {0};
  if (sscanf(req, "%15s %8191s", method, target) != 2) return;
  char user[32] = {0};
  for (char *h = strstr(req, "\r\n"); h && h[2] && h[2] != '\r'; h = strstr(h + 2, "\r\n"))
    if (!strncasecmp(h + 2, "x-user:", 7)) { sscanf(h + 9, " %31[0-9]", user); }
  char *query = strchr(target, '?'); if (query) *query++ = 0; else query = "";
  char v[4096], sql[8192]; buf_t out = {0};
  int id;
  if (!strcmp(target, "/health")) { json(c, 200, "{\"ok\":true}"); return; }
  if (!strcmp(target, "/search")) {
    param(query, "q", v, sizeof v);
    snprintf(sql, sizeof sql, "SELECT id, name FROM items WHERE name ILIKE '%%%s%%' ORDER BY id", v);
    bputs(&out, "{\"items\":[");
    if (pg_simple(sql, &out) < 0) { json(c, 500, "{\"detail\":\"Internal Server Error\"}"); free(out.p); return; }
    bputs(&out, "]}"); json(c, 200, out.p); free(out.p); return;
  }
  if (!strcmp(target, "/safe-search")) {
    param(query, "q", v, sizeof v);
    char like[4200]; snprintf(like, sizeof like, "%%%s%%", v); const char *vals[] = {like};
    bputs(&out, "{\"items\":[");
    if (pg_params("SELECT id, name FROM items WHERE name ILIKE $1 ORDER BY id", 1, vals, &out) < 0) {
      json(c, 500, "{\"detail\":\"Internal Server Error\"}"); free(out.p); return;
    }
    bputs(&out, "]}"); json(c, 200, out.p); free(out.p); return;
  }
  if (!strcmp(target, "/download") || !strcmp(target, "/safe-download")) {
    param(query, "name", v, sizeof v);
    char path[PATH_MAX + 4200]; snprintf(path, sizeof path, "%s/%s", STATIC_DIR, v);
    if (!strcmp(target, "/safe-download")) {
      char real[PATH_MAX], root[PATH_MAX];
      if (!realpath(path, real) || !realpath(STATIC_DIR, root) || strncmp(real, root, strlen(root)) ||
          real[strlen(root)] != '/') { json(c, 404, "{\"detail\":\"not found\"}"); return; }
    }
    serve_file(c, path); return;
  }
  if (sscanf(target, "/notes/%d", &id) == 1 || sscanf(target, "/safe-notes/%d", &id) == 1) {
    if (!user[0]) { json(c, 401, "{\"detail\":\"unauthorized\"}"); return; }
    char ids[16]; snprintf(ids, sizeof ids, "%d", id); const char *vals[] = {ids, user};
    int safe = !strncmp(target, "/safe-notes/", 12);
    bputs(&out, "{\"rows\":[");
    int r = safe ? pg_params("SELECT id, user_id, body FROM notes WHERE id = $1 AND user_id = $2", 2, vals, &out)
                 : pg_params("SELECT id, user_id, body FROM notes WHERE id = $1", 1, vals, &out);
    if (r < 0) { json(c, 500, "{\"detail\":\"Internal Server Error\"}"); free(out.p); return; }
    if (!strcmp(out.p, "{\"rows\":[")) { json(c, 404, "{\"detail\":\"not found\"}"); free(out.p); return; }
    bputs(&out, "]}"); json(c, 200, out.p); free(out.p); return;
  }
  json(c, 404, "{\"detail\":\"Not Found\"}");
}

int main(void) {
  const char *port = getenv("PORT"), *st = getenv("APP_STATIC"), *pu = getenv("PGUSER"), *pp = getenv("PGPORT");
  if (st) STATIC_DIR = st;
  if (pu) PG_USER = pu;
  if (pp) PG_PORT = atoi(pp);
  int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port ? atoi(port) : 3000)};
  inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
  if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 64)) { perror("listen"); return 1; }
  fprintf(stderr, "c demo listening\n");
  for (;;) {
    int c = accept(s, NULL, NULL);
    if (c < 0) { if (errno == EINTR) continue; return 1; }
    handle(c);
    close(c);
  }
}
