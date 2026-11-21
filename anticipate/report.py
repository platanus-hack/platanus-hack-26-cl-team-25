"""Markdown + standalone HTML report (no external resources; every value escaped)."""
from __future__ import annotations

import html
import os
import time


def _check_rows(chk: dict) -> list[tuple]:
    return [(r["kind"], r["in"], r["expect"], f"ret={r['ret']} {r['out']}", r["ok"]) for r in chk.get("results", [])]


def _score(chk: dict) -> str:
    if not chk.get("compiled"):
        return f"no compila / no aplica: {chk.get('error', '')[:200]}"
    return f"{chk['passed']}/{chk['total']}"


def markdown(r: dict) -> str:
    t, c, rv = r["target"], r["checks"], r["review"]
    eq, loc = r.get("equivalence", {}), r.get("localisation", {})
    out = [f"# Anticipación — {t['name']}", "",
           f"Fecha: {time.strftime('%Y-%m-%d %H:%M', time.localtime(r['started']))} · duración {r['seconds']:.0f} s · modelo `{rv['model']}`", "",
           "Análisis defensivo de **código fuente público** en un laboratorio aislado. No se ejecutó el servidor ni se envió tráfico.", "",
           "## Resultado", "",
           "| Versión | Propiedades del normalizador |", "|---|---|",
           f"| {t['vulnerable_ref']} (publicada) | {_score(c['vulnerable'])} |",
           f"| **Parche sugerido** | **{_score(c['suggested'])}** |",
           f"| {t['fixed_ref']} (parche oficial) | {_score(c['official'])} |", ""]
    if eq.get("comparable"):
        out += [f"Comportamiento del sugerido frente al oficial: **{eq['same']}/{eq['total']} vectores idénticos**"
                + (f" (difieren: {', '.join('`'+x+'`' for x in eq['differ'])})" if eq["differ"] else "") + ".", ""]
    if loc:
        out += [f"Ubicación: sugerido en {', '.join(loc['our_functions']) or '—'}; oficial en {', '.join(loc['official_functions']) or '—'}; "
                f"misma función: **{'sí' if loc['same_function'] else 'no'}**; líneas superpuestas: {'sí' if loc['overlapping_lines'] else 'no'}; "
                f"tamaño {loc['our_changed_lines']} vs {loc['official_changed_lines']} líneas.", ""]
    out += ["## Hallazgos del modelo", ""]
    for f in rv["findings"] or [{"summary": "sin hallazgos estructurados"}]:
        out += [f"- **{f.get('file','')}:{f.get('line','')} `{f.get('function','')}`** — {f.get('summary','')}",
                f"  - Precondición: {f.get('precondition','')}", f"  - Impacto: {f.get('impact','')}",
                f"  - Arreglo: {f.get('fix','')} (confianza {f.get('confidence','')})"]
    out += ["", "## Parche sugerido", "", "```diff", r["diffs"]["suggested"].rstrip() or "(sin cambios)", "```", "",
            f"## Parche oficial ({t['vulnerable_ref']} → {t['fixed_ref']}, mismos archivos)", "", "```diff", r["diffs"]["official"].rstrip(), "```", "",
            "## Vectores", "", "| Tipo | Entrada | Esperado | " + " | ".join(k for k in ("vulnerable", "suggested", "official")) + " |",
            "|---|---|---|---|---|---|"]
    rows = {k: _check_rows(c[k]) for k in ("vulnerable", "suggested", "official")}
    n = max(len(v) for v in rows.values())
    for i in range(n):
        base = next(v[i] for v in rows.values() if len(v) > i)
        cells = [(("✅ " if v[i][4] else "❌ ") + f"`{v[i][3]}`") if len(v) > i else "—" for v in rows.values()]
        out.append(f"| {base[0]} | `{base[1]}` | {base[2]} | " + " | ".join(cells) + " |")
    out += ["", "## Cómo leer esto", "",
            f"- Al modelo se le dio el área ({len(t['scope'])} archivo(s) en alcance) y la clase de defecto, **no** el aviso ({t['advisory']}).",
            "- La evidencia no es lo que dice el modelo: son las propiedades mecánicas, compiladas y ejecutadas en un contenedor sin red.",
            "- Límite: el defecto es público y antiguo, así que el modelo pudo haberlo visto en su entrenamiento. Para una prueba ciega, usar un aviso posterior a la fecha de corte del modelo.",
            "- Para software de terceros la acción correcta en producción es contener con la regla del gateway y actualizar a la versión corregida."]
    return "\n".join(out) + "\n"


CSS = """
:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--ok:#3fb950;--bad:#f85149;--add:#12261e;--del:#2d1214;--card:#161b22;--line:#30363d}
@media (prefers-color-scheme: light){:root:not([data-theme=dark]){--bg:#fff;--fg:#1f2328;--mut:#59636e;--card:#f6f8fa;--line:#d0d7de;--add:#dafbe1;--del:#ffebe9}}
body{background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif;margin:0;padding:24px 16px}
main{max-width:1200px;margin:auto}h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
.mut{color:var(--mut)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px}.big{font-size:30px;font-weight:700}
.ok{color:var(--ok)}.bad{color:var(--bad)}.diffs{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width:800px){.diffs{grid-template-columns:1fr}}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px;overflow-x:auto;font:12.5px/1.4 ui-monospace,monospace;margin:0}
pre span{display:block;white-space:pre}.a{background:var(--add)}.d{background:var(--del)}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid var(--line);padding:5px 6px;text-align:left;vertical-align:top}
code{font:12.5px ui-monospace,monospace}.tw{overflow-x:auto}
"""


def _pre(diff: str) -> str:
    rows = []
    for l in (diff or "(sin cambios)").splitlines():
        cls = "a" if l.startswith("+") and not l.startswith("+++") else "d" if l.startswith("-") and not l.startswith("---") else ""
        rows.append(f'<span class="{cls}">{html.escape(l) or " "}</span>')
    return "<pre>" + "".join(rows) + "</pre>"


def html_page(r: dict) -> str:
    e = html.escape
    t, c, rv, eq, loc = r["target"], r["checks"], r["review"], r.get("equivalence", {}), r.get("localisation", {})

    def card(title, chk):
        good = chk.get("compiled") and chk["passed"] == chk["total"]
        return (f'<div class="card"><div class="mut">{e(title)}</div><div class="big {"ok" if good else "bad"}">'
                f'{e(_score(chk) if chk.get("compiled") else "—")}</div><div class="mut">propiedades</div></div>')

    find = "".join(f"<li><b>{e(str(f.get('file','')))}:{e(str(f.get('line','')))} <code>{e(str(f.get('function','')))}</code></b> — "
                   f"{e(str(f.get('summary','')))}<br><span class=mut>Precondición:</span> {e(str(f.get('precondition','')))}<br>"
                   f"<span class=mut>Arreglo:</span> {e(str(f.get('fix','')))}</li>" for f in rv["findings"]) or "<li>sin hallazgos estructurados</li>"
    rows = {k: _check_rows(c[k]) for k in ("vulnerable", "suggested", "official")}
    n = max(len(v) for v in rows.values())
    trs = []
    for i in range(n):
        base = next(v[i] for v in rows.values() if len(v) > i)
        tds = "".join(f'<td class="{"ok" if v[i][4] else "bad"}"><code>{e(v[i][3])}</code></td>' if len(v) > i else "<td>—</td>"
                      for v in rows.values())
        trs.append(f"<tr><td>{e(base[0])}</td><td><code>{e(base[1])}</code></td><td>{e(base[2])}</td>{tds}</tr>")
    eqs = (f"{eq['same']}/{eq['total']} vectores con resultado idéntico al oficial" if eq.get("comparable") else "no comparable")
    locs = (f"misma función: {'sí' if loc.get('same_function') else 'no'} · sugerido {e(', '.join(loc.get('our_functions', [])))} · "
            f"oficial {e(', '.join(loc.get('official_functions', [])))}") if loc else ""
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anticipación {e(t['name'])}</title><style>{CSS}</style></head><body><main>
<h1>Anticipación — {e(t['name'])}</h1>
<div class="mut">Análisis defensivo de código fuente público en laboratorio aislado · sin servidor en ejecución ni tráfico · modelo {e(rv['model'])} · {r['seconds']:.0f} s</div>
<h2>Resultado</h2><div class="grid">{card(t['vulnerable_ref'] + ' publicada', c['vulnerable'])}{card('Parche sugerido', c['suggested'])}{card(t['fixed_ref'] + ' oficial', c['official'])}
<div class="card"><div class="mut">Sugerido vs oficial</div><div>{e(eqs)}</div><div class="mut" style="margin-top:6px">{locs}</div></div></div>
<h2>Hallazgos del modelo</h2><ul>{find}</ul>
<h2>Parche sugerido vs parche oficial</h2><div class="diffs"><div><div class="mut">Sugerido (generado sin conocer el aviso)</div>{_pre(r['diffs']['suggested'])}</div>
<div><div class="mut">Oficial {e(t['vulnerable_ref'])} → {e(t['fixed_ref'])}</div>{_pre(r['diffs']['official'])}</div></div>
<h2>Vectores de prueba del normalizador</h2><div class="tw"><table><tr><th>Tipo</th><th>Entrada</th><th>Esperado</th><th>{e(t['vulnerable_ref'])}</th><th>Sugerido</th><th>{e(t['fixed_ref'])}</th></tr>{''.join(trs)}</table></div>
<h2>Cómo leer esto</h2><ul><li>Al modelo se le dio el área y la clase de defecto, no el aviso ({e(t['advisory'])}).</li>
<li>La evidencia son las propiedades mecánicas, compiladas y ejecutadas en un contenedor sin red; no la explicación del modelo.</li>
<li>Límite: el defecto es público y antiguo; el modelo pudo haberlo visto en su entrenamiento. Para una prueba ciega, usar un aviso posterior a su fecha de corte.</li>
<li>En producción, para software de terceros: contener con la regla del gateway y actualizar a la versión corregida.</li></ul>
</main></body></html>"""


def write(r: dict, out_dir: str) -> None:
    with open(os.path.join(out_dir, "report.md"), "w") as f:
        f.write(markdown(r))
    with open(os.path.join(out_dir, "report.html"), "w") as f:
        f.write(html_page(r))
