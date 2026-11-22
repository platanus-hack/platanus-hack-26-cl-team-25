/* DOM layer. Event data only enters the page through textContent. */
(function () {
  'use strict';
  var S = window.ImmuneState;
  var st = S.newState();
  var cards = Object.create(null);     // incident id -> {el, sig}
  var userOpen = Object.create(null);  // incident id -> detail open/closed chosen by the viewer
  var dirty = false;
  var CARDS_MAX = 40;                  // cards drawn; older closed incidents are only counted
  var DIFF_LINES_MAX = 300;
  var TICKER_ROWS = 14;

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function add(parent) { for (var i = 1; i < arguments.length; i++) if (arguments[i]) parent.appendChild(arguments[i]); return parent; }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function show(node, on) { if (on) node.removeAttribute('hidden'); else node.setAttribute('hidden', ''); }

  var NS = 'http://www.w3.org/2000/svg';
  function svg(cls, shapes) {
    var e = document.createElementNS(NS, 'svg');
    e.setAttribute('viewBox', '0 0 16 16'); e.setAttribute('class', cls); e.setAttribute('aria-hidden', 'true');
    shapes.forEach(function (sh) {
      var n = document.createElementNS(NS, sh[0]);
      for (var k in sh[1]) n.setAttribute(k, sh[1][k]);
      e.appendChild(n);
    });
    return e;
  }
  /* state of an incident as a 16 px mark; colour comes from the class (style.css) */
  var ICONS = {
    cured: [['circle', { cx: 8, cy: 8, r: 7, 'class': 'fill' }], ['path', { d: 'm5 8.2 2 2 4-4.2', 'class': 'cut' }]],
    contained: [['circle', { cx: 8, cy: 8, r: 6.25, 'class': 'ring' }], ['path', { d: 'M8 4.2a3.8 3.8 0 0 1 0 7.6z', 'class': 'fill' }]],
    open: [['circle', { cx: 8, cy: 8, r: 6.25, 'class': 'ring' }], ['circle', { cx: 8, cy: 8, r: 2.4, 'class': 'fill' }]],
    dismissed: [['circle', { cx: 8, cy: 8, r: 7, 'class': 'fill' }], ['path', { d: 'm5.7 5.7 4.6 4.6m0-4.6-4.6 4.6', 'class': 'cut' }]],
    queued: [['circle', { cx: 8, cy: 8, r: 6.25, 'class': 'ring dash' }]]
  };
  function statusIcon(kind) { return svg('ico s-' + kind, ICONS[kind] || ICONS.queued); }
  function chevron() { return svg('chev', [['path', { d: 'm6 3.8 4.2 4.2L6 12.2' }]]); }

  function hms(ts) {
    if (typeof ts !== 'number' || !ts) return '--:--:--';
    var d = new Date(ts * 1000);
    function p(n) { return n < 10 ? '0' + n : '' + n; }
    return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }
  function dec(x) { return x.toFixed(1).replace('.', ','); }   // 24,5
  function secs(x) { return typeof x === 'number' ? dec(x) + ' s' : '-'; }
  function clip(s, n) { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n) + ' ...' : s; }
  function host0(addr) { return String(addr || '?').replace(/:\d+$/, ''); }   // prod-green:8000 -> prod-green
  function json(v) { try { return JSON.stringify(v); } catch (e) { return String(v); } }

  function prRef(url) {
    if (S.isGithubUrl(url)) {
      var a = el('a', null, url);
      a.href = url; a.target = '_blank'; a.rel = 'noopener noreferrer';
      return a;
    }
    return el('span', null, S.prLabel(url));
  }

  /* one moment of the incident: a mark on the rail, a title, when it happened, then labelled rows */
  function section(title, inc, ts, state) {
    var s = el('div', 'ev ' + (state || 'done'));
    var h = el('h3');
    h.appendChild(el('span', 'tt', title));
    if (ts) {
      var when = el('span', 'when', hms(ts));
      if (inc.t.opened && ts >= inc.t.opened) when.appendChild(el('b', null, '+' + dec(ts - inc.t.opened) + ' s'));
      h.appendChild(when);
    }
    s.appendChild(h);
    return s;
  }
  /* label on the left in the UI face, value on the right in mono; `code` puts the value in a block */
  function rowOf(sec, label, value, cls) {
    if (value == null || value === '') return null;
    var rows = sec.lastChild && sec.lastChild.className === 'rows' ? sec.lastChild : sec.appendChild(el('dl', 'rows'));
    var dd = el('dd', cls || null);
    if (typeof value === 'object' && value.nodeType) dd.appendChild(value); else dd.textContent = String(value);
    add(rows, el('dt', null, label), dd);
    return dd;
  }
  var DETAIL_LABEL = { input: 'Entrada', location: 'Ubicación', param: 'Parámetro', reason: 'Motivo', statement: 'Consulta', path: 'Ruta pedida',
                       realpath: 'Archivo leído', owner: 'Dueño', uid: 'Usuario', table: 'Tabla', command: 'Comando', url: 'URL', host: 'Host' };
  var CODE_KEYS = { statement: 1, command: 1 };

  function renderDiff(diff) {
    var box = el('div', 'diff');
    var lines = String(diff).split('\n');
    var n = Math.min(lines.length, DIFF_LINES_MAX);
    for (var i = 0; i < n; i++) {
      var l = lines[i], c = '';
      if (l.indexOf('+++') === 0 || l.indexOf('---') === 0 || l.indexOf('diff ') === 0 || l.indexOf('index ') === 0) c = 'meta';
      else if (l.charAt(0) === '+') c = 'add';
      else if (l.charAt(0) === '-') c = 'del';
      else if (l.indexOf('@@') === 0) c = 'hunk';
      box.appendChild(el('div', c, l === '' ? ' ' : clip(l, 600)));
    }
    if (lines.length > n) box.appendChild(el('div', 'meta', '... ' + (lines.length - n) + ' líneas más'));
    return box;
  }

  function requestText(r) {
    r = r || {};
    var txt = (r.method || '?') + ' ' + (r.path || '?') + (r.query ? '?' + r.query : '');
    var body = S.decodeB64(r.body_b64);
    if (body) txt += '\n\n' + clip(body, 1500);
    else if (r.body_hidden) txt += '\n\n(cuerpo no publicado: ' + r.body_hidden + ')';
    return txt;
  }

  var STATUS_LABEL = { open: 'Abierta', contained: 'Contenida por regla', cured: 'Curada', dismissed: 'Descartada' };   // unknown: statusLabel()
  var GATE_LABEL = { policy: 'Política', properties: 'Propiedades', poc: 'PoC', tests: 'Tests', legit: 'Tráfico legítimo' };
  var CLASS = {
    sqli: ['Inyección SQL', 'El texto del request terminaba dentro de una consulta a la base de datos.'],
    traversal: ['Lectura de archivos ajenos', 'Un nombre de archivo del request permitía salir de la carpeta prevista.'],
    idor: ['Datos de otro usuario', 'Cambiando un id en la URL, un usuario leía datos que no eran suyos.']
  };
  function statusLabel(inc, status) { return status === 'unknown' ? 'Cerrado: ' + clip(S.unknownOutcome(inc), 60) : STATUS_LABEL[status]; }
  function storyOf(inc, status) {
    if (status === 'unknown') return 'El pipeline lo cerró con un resultado que este panel no conoce: ' + clip(S.unknownOutcome(inc), 60) + '.';
    if (status === 'cured') return inc.verify && inc.verify.blocked ? 'Parchada y verificada en producción.' : 'Parchada.';
    if (status === 'dismissed') return 'Descartada: no se pudo reproducir.';
    if (status === 'contained') return 'El gateway cierra este punto con una regla mientras se valida el parche.';
    if (!inc.opened) return 'En cola: el pipeline atiende un incidente a la vez.';
    return 'Confirmada en un clon. Todavía sin regla.';
  }
  var ROUTE_LABEL = { prod: 'prod', deny: 'rechazado', shadow_l1: 'clon L1', shadow_l2: 'clon L2', l0: 'L0' };

  function buildSteps(inc) {
    var box = el('div', 'steps');
    var gates = null;
    S.stages(inc).forEach(function (s) {
      var isGate = s.key.indexOf('gate:') === 0;
      var chip = el('span', 'step ' + s.state + (isGate ? ' g' : ''));
      chip.appendChild(el('i', 'sd'));
      chip.appendChild(el('b', null, isGate ? (GATE_LABEL[s.label] || s.label) : s.label));
      if (s.key === 'detect' && s.ts) chip.appendChild(el('span', 'ts', hms(s.ts)));
      else if (s.dt != null && s.key !== 'opened') chip.appendChild(el('span', 'd', '+' + dec(s.dt) + ' s'));
      if (s.note) chip.appendChild(el('span', 'note', s.note));
      if (isGate) {
        if (!gates) { gates = el('span', 'gate-group'); gates.appendChild(el('span', 'gl', '5 validaciones')); box.appendChild(gates); }
        gates.appendChild(chip);
      } else box.appendChild(chip);
    });
    return box;
  }

  function buildDetail(inc) {
    var box = el('div', 'detail');
    var o = inc.oracles[0];
    var rq = (o && o.data.request) || inc.request;

    var s1 = section(inc.origin === 'audit' ? 'Request que lo demuestra' : 'Request del atacante', inc, S.t0(inc), 'bad');
    if (rq) s1.appendChild(el('div', 'req', requestText(rq)));
    else rowOf(s1, 'Punto', (inc.method ? inc.method + ' ' : '') + (inc.route || ''));
    if (o && o.req) {
      var c = o.req;
      rowOf(s1, 'Gateway', (c.cls || 'Sospechoso') + (c.reasons && c.reasons.length ? ' (' + c.reasons.join(', ') + ')' : '') +
        (c.route ? ' \u2192 ' + (ROUTE_LABEL[c.route] || c.route) + (o.data.clone ? ' (' + o.data.clone + ')' : '') : '') +
        (c.ms != null ? ', ' + c.ms.toFixed(0) + ' ms' : ''));
    }
    if (inc.origin === 'audit') rowOf(s1, 'Origen', inc.opened ? 'Auto-auditoría en un clon; nadie lo envió al gateway' : 'En cola', 'plain');
    box.appendChild(s1);

    if (o) {
      var ev0 = o.data.events[0] || {};
      var fr = (ev0.stack && ev0.stack[0]) || null;
      var sink = inc.sink || fr;
      var s2 = section('Oráculo ' + (ev0.oracle || '') + (inc.hits > 1 ? ', ' + inc.hits + ' disparos' : ''), inc, o.ts, 'bad');
      if (sink && sink.file) rowOf(s2, 'Dónde', sink.file + ':' + sink.line + (fr && fr.func ? '  ' + fr.func + '()' : ''));
      rowOf(s2, 'Respuesta', 'HTTP ' + (o.data.status == null ? '?' : o.data.status) + (o.data.mode ? ', clon ' + o.data.mode : ''));
      var dt = ev0.detail;
      if (dt && typeof dt === 'object' && !Array.isArray(dt)) {
        Object.keys(dt).slice(0, 8).forEach(function (k) {
          var v = dt[k];
          rowOf(s2, DETAIL_LABEL[k] || k, clip(typeof v === 'string' ? v : json(v), 700), CODE_KEYS[k] ? 'code' : null);
        });
      } else if (dt != null) rowOf(s2, 'Detalle', clip(json(dt), 700));
      box.appendChild(s2);
    } else if (inc.sink && inc.sink.file) {
      rowOf(s1, 'Dónde', inc.sink.file + ':' + inc.sink.line);
    }

    if (inc.poc) {
      var sp = section('PoC', inc, inc.poc.ts, inc.poc.reproducible ? 'done' : 'bad');
      rowOf(sp, 'Resultado', (inc.poc.reproducible ? 'Reproducible' : 'No reproducible') + (inc.poc.runs == null ? '' : ' en ' + inc.poc.runs + ' corridas'), 'plain');
      box.appendChild(sp);
    }

    if (inc.rule) {
      var r = inc.rule;
      var sr = section('Regla en el gateway', inc, r.ts, 'warn');
      rowOf(sr, 'Punto', (r.method || '') + ' ' + (r.route || '') + (r.param ? '  [' + r.param.name + ']' : ''));
      rowOf(sr, 'Alcance', (r.scope || '?') + (r.ttl_s == null ? '' : ', expira en ' + r.ttl_s + ' s'));
      if (r.grammar) rowOf(sr, 'Gramática', clip(r.grammar, 200), 'code');
      if (inc.ruleExpired) rowOf(sr, 'Retirada', hms(inc.ruleExpired.ts) + (inc.prod ? ', el parche ya está en producción' : (inc.ruleExpired.reason ? ' (' + inc.ruleExpired.reason + ')' : '')), 'plain');
      box.appendChild(sr);
    }

    var stl = { pending: 'En curso', rejected: 'Rechazado', accepted: 'Aceptado' };
    inc.attempts.forEach(function (a) {
      var sa = section('Parche' + (inc.attempts.length > 1 ? ', intento ' + a.attempt : ''), inc, a.diffTs || a.ts,
        a.status === 'accepted' ? 'done' : a.status === 'rejected' ? 'bad' : 'run');
      var ab = el('div', 'attempt ' + a.status);
      var ah = el('div', 'attempt-head');
      add(ah, el('span', null, S.sourceLabel(a.source)), el('span', 'st', stl[a.status] || a.status));
      ab.appendChild(ah);
      if (a.diff) ab.appendChild(renderDiff(a.diff));
      var gates = el('div', 'gates');
      S.GATES.forEach(function (g) {
        var gr = a.gates[g];
        var ge = el('div', 'gate ' + gr.state);
        var gn = el('div', 'n');
        add(gn, el('i', 'sd'), el('span', null, GATE_LABEL[g] || g));
        add(ge, gn, gr.detail ? el('div', 'det', clip(gr.detail.replace(/^OK: /, ''), 400)) : null);
        gates.appendChild(ge);
      });
      ab.appendChild(gates);
      sa.appendChild(ab);
      box.appendChild(sa);
    });

    if (inc.pr || inc.merged) {
      var spr = section('Pull request', inc, (inc.merged || inc.pr).ts);
      var ref = el('span');
      add(ref, prRef((inc.merged || inc.pr).url));
      rowOf(spr, inc.merged ? 'Fusionado' : 'Abierto', ref);
      if (inc.pr && inc.pr.branch) rowOf(spr, 'Rama', inc.pr.branch);
      if (inc.merged) rowOf(spr, 'Commit', String(inc.merged.sha || '').slice(0, 12));
      box.appendChild(spr);
    }

    if (inc.deploy || inc.prod) {
      var d = inc.deploy || {};
      var failed = d.doneTs && !d.ok;
      var sd = section('Deploy blue/green', inc, (inc.prod && inc.prod.ts) || d.doneTs || d.startTs, failed ? 'bad' : inc.prod ? 'done' : 'run');
      rowOf(sd, 'Release', String(d.release || (inc.prod && inc.prod.release) || '?').slice(0, 12));
      if (inc.prod) rowOf(sd, 'Tráfico', 'Cambiado a ' + (inc.prod.addr || '?') + ' sin cortes', 'plain');
      if (failed) rowOf(sd, 'Resultado', 'Falló' + (d.rolled_back ? ', revertido' : '') + (d.detail ? ': ' + clip(d.detail, 300) : ''), 'plain');
      else if (d.doneTs && /not validated by traffic/.test(String(d.detail || ''))) rowOf(sd, 'Observación', 'Sin tráfico suficiente en la ventana: el despliegue no quedó validado por tráfico', 'plain');
      else if (!d.doneTs && d.startTs) rowOf(sd, 'Estado', inc.prod ? 'Retirando la versión anterior' : 'Levantando la versión nueva', 'plain');
      box.appendChild(sd);
    }

    if (inc.verify) {
      var sv = section('Verificación', inc, inc.verify.ts, inc.verify.blocked ? 'done' : 'bad');
      sv.appendChild(el('p', 'verdict', inc.verify.blocked ? 'El mismo ataque, repetido contra producción, ya no funciona.' : 'El ataque todavía funciona en producción.'));
      box.appendChild(sv);
    }
    if (inc.closed && inc.closed.outcome !== 'patched') {
      box.appendChild(section('Cerrado: ' + (inc.closed.outcome || '?'), inc, inc.closed.ts, 'mute'));
    }
    return box;
  }

  function cell(cls, value, na) { return el('span', 'c ' + cls + (na ? ' na' : ''), value); }

  /* one incident = one row of the list; opening it shows the whole story */
  function buildCard(inc, open) {
    var status = S.status(inc), phase = S.phase(inc);
    var live = !!(phase && inc.opened);
    var cls = CLASS[inc.vuln_class];
    var card = el('details', 'card' + (inc.origin === 'audit' ? ' audit' : '') + (live ? ' live' : ''));
    card.setAttribute('data-status', status);
    card.id = 'card-' + inc.id;

    var row = el('summary', 'row');
    row.appendChild(statusIcon(!inc.opened && status === 'open' ? 'queued' : status));
    row.appendChild(el('span', 'id', inc.id));
    var title = el('span', 'title');
    add(title, el('span', 'cls', cls ? cls[0] : (inc.vuln_class || 'Incidente')),
      el('span', 'route', (inc.method ? inc.method + ' ' : '') + (inc.route || '')),
      inc.origin === 'audit' ? el('span', 'tag', 'Auto-auditoría') : null);
    row.appendChild(title);
    var r = S.timeToRule(inc), p = S.timeToProd(inc);
    add(row, cell('t-rule', secs(r), r == null), cell('t-prod', secs(p), p == null));
    var stc = el('span', 'c state');
    if (live) stc.appendChild(el('i', 'pulse'));
    stc.appendChild(el('span', null, phase ? phase.charAt(0).toUpperCase() + phase.slice(1) : statusLabel(inc, status)));
    add(row, stc, chevron());
    card.appendChild(row);

    if (open) {
      card.open = true;
      var body = el('div', 'body');
      var story = el('p', 'story');
      if (cls) story.appendChild(el('span', 'what', cls[1] + ' '));
      story.appendChild(el('span', 'now', storyOf(inc, status)));
      body.appendChild(story);

      var props = el('dl', 'props');
      function prop(k, v, node) {
        if (v == null && !node) return;
        var d = el('div', 'p');
        var dd = el('dd', null, v);
        if (node) dd.appendChild(node);
        add(d, el('dt', null, k), dd); props.appendChild(d);
      }
      prop('Parámetro', inc.param ? inc.param.name : null);
      if (inc.origin === 'audit' && inc.parent) {
        var pa = el('a', null, inc.parent);
        pa.href = '#card-' + encodeURIComponent(inc.parent);
        prop('Hallado tras', null, pa);
      }
      [['En cola', S.queueTime(inc)], ['Regla', r], ['Parche escrito', S.timeToDiff(inc)], ['Merge', S.timeToMerged(inc)], ['En producción', p], ['Verificado', S.timeToVerified(inc)]].forEach(function (x) {
        if (x[1] != null) prop(x[0], secs(x[1]));
      });
      if (inc.attempts.length > 1) prop('Intentos', inc.attempts.length);
      if (inc.runs > 1) prop('Corridas del pipeline', inc.runs);
      props.title = 'Tiempos desde que el pipeline abre el incidente';
      body.appendChild(props);

      if (live) body.appendChild(buildSteps(inc));
      body.appendChild(buildDetail(inc));
      card.appendChild(body);
    }
    card.addEventListener('toggle', function () {
      if (card.open === open) return;
      userOpen[inc.id] = card.open;
      schedule();
    });
    return card;
  }

  /* an attack an oracle confirmed that is still waiting for the pipeline (no incident id yet) */
  function buildPendingCard(p) {
    var o = p.o, ev0 = o.data.events[0] || {};
    var card = el('details', 'card pending');
    card.setAttribute('data-status', 'open');
    card.open = true;
    var row = el('summary', 'row');
    var title = el('span', 'title');
    add(title, el('span', 'cls', 'Ataque confirmado'), el('span', 'route', p.key));
    var stc = el('span', 'c state');
    add(stc, el('i', 'pulse'), el('span', null, 'En cola'));
    add(row, statusIcon('queued'), el('span', 'id', hms(o.ts)), title, cell('t-rule', '-', true), cell('t-prod', '-', true), stc, chevron());
    card.appendChild(row);
    var body = el('div', 'body');
    body.appendChild(el('p', 'story', 'El oráculo ' + (ev0.oracle || '?') + ' lo confirmó en ' + (o.data.clone || 'un clon') +
      (p.hits > 1 ? ' (' + p.hits + ' disparos)' : '') + '. En cola: el pipeline atiende un incidente a la vez.'));
    body.appendChild(el('div', 'req', requestText(o.data.request)));
    card.appendChild(body);
    return card;
  }

  function errorCard(inc) {
    var card = el('details', 'card');
    card.id = 'card-' + inc.id;
    card.setAttribute('data-status', 'open');
    var row = el('summary', 'row');
    var title = el('span', 'title');
    title.appendChild(el('span', 'route', 'Este incidente trae datos que no se pudieron dibujar'));
    add(row, statusIcon('queued'), el('span', 'id', String(inc.id)), title);
    card.appendChild(row);
    return card;
  }

  function n1(x) { return x == null ? '-' : dec(x) + ' s'; }
  function count(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  function fact(id, parts) {
    var host = $(id);
    clear(host);
    parts.forEach(function (p, i) {
      if (!p) return;
      if (host.firstChild) host.appendChild(document.createTextNode(' · '));
      host.appendChild(typeof p === 'string' ? document.createTextNode(p) : p);
    });
  }

  /* the four stages of the system, each with its number from this run */
  function renderScore() {
    var s = S.scoreboard(st);
    var confirmed = s.seen - s.dismissed, live = confirmed - s.audit;
    $('fl-total').textContent = s.total.toLocaleString('es');
    fact('fl-detect-fact', [count(s.detonated, 'ejecutado en un clon', 'ejecutados en un clon'), s.deny ? count(s.deny, 'rechazado', 'rechazados') : null,
      s.prod ? s.prod.toLocaleString('es') + ' a producción' : null,
      s.captive ? count(s.captive, 'sesión cautiva', 'sesiones cautivas') : null,
      s.size != null && s.free != null ? 'clones: ' + s.free + ' de ' + s.size + ' libres' + (s.busy ? ', ' + count(s.busy, 'ocupado', 'ocupados') : '') : null]);
    $('fl-confirmed').textContent = confirmed;
    fact('fl-confirm-fact', [count(live, 'por ataque', 'por ataques'), s.audit ? s.audit + ' por auto-auditoría' : null,
      s.dismissed ? count(s.dismissed, 'descartada', 'descartadas') : null]);
    $('fl-rule').textContent = n1(s.ruleMedian);
    fact('fl-contain-fact', [s.open ? el('b', 'bad', count(s.open, 'abierta', 'abiertas') + ' sin regla') : null,
      s.contained ? el('b', 'warn', count(s.contained, 'contenida', 'contenidas') + ' esperando parche') : (s.open ? null : 'Nada esperando parche'),
      s.unknown ? count(s.unknown, 'cerrada', 'cerradas') + ' con resultado desconocido' : null,
      s.ruleN ? 'mediana de ' + count(s.ruleN, 'regla', 'reglas') : null]);
    $('fl-prod').textContent = n1(s.prodMedian);
    fact('fl-cure-fact', [el('b', s.cured === confirmed && confirmed ? 'ok' : null, s.cured + ' de ' + confirmed + ' curadas'),
      s.prodN ? 'mediana de ' + count(s.prodN, 'parche', 'parches') : null]);
    $('flow').setAttribute('data-open', s.open ? '1' : '0');
    $('inc-count').textContent = s.seen ? s.seen + (s.dismissed ? ' (' + s.dismissed + ' descartada' + (s.dismissed === 1 ? '' : 's') + ')' : '') : '';
    $('conn-info').textContent = st.events ? st.events + ' eventos' : '';
  }

  /* which run is on the page, and whether it is the scripted one (dashboard/demo_events.py): that is said in
     words for as long as its events are on the page, and the connection is then never called "En vivo" */
  function renderRun() {
    show($('run'), !!st.run);
    $('run-id').textContent = st.run || '';
    show($('scripted'), st.scripted);
    if (connected) $('conn-text').textContent = S.connLabel(st);
  }

  function renderIncidents() {
    var host = $('incidents');
    var all = S.displayOrder(st);
    var ids = all.slice(0, CARDS_MAX);
    show($('inc-empty'), !all.length);
    var more = $('inc-more');
    show(more, all.length > ids.length);
    more.textContent = all.length > ids.length ? 'y ' + (all.length - ids.length) + ' incidentes cerrados anteriores' : '';
    var keep = Object.create(null);
    var prevNode = null;
    var pending = Object.create(null);
    S.pendingAttacks(st).forEach(function (p) { pending[p.id] = p; });
    ids.forEach(function (id) {
      var pend = pending[id], inc = pend ? null : st.incidents[id], c = cards[id];
      var open = pend ? false : (id in userOpen ? userOpen[id] : !!(inc.opened && !inc.closed));
      var sig = pend ? 'p' + pend.hits : inc.rev + '|' + S.status(inc) + '|' + (open ? 1 : 0);
      keep[id] = true;
      if (!c || c.sig !== sig) {
        var fresh;
        try { fresh = pend ? buildPendingCard(pend) : buildCard(inc, open); } catch (e) { fresh = errorCard(inc || { id: 'ataque' }); }
        if (c && c.el.parentNode === host) host.replaceChild(fresh, c.el);
        c = cards[id] = { el: fresh, sig: sig };
      }
      var cur = prevNode ? prevNode.nextSibling : host.firstChild;
      if (cur !== c.el) host.insertBefore(c.el, cur);
      prevNode = c.el;
    });
    Object.keys(cards).forEach(function (id) {
      if (!keep[id]) { var n = cards[id].el; if (n.parentNode) n.parentNode.removeChild(n); delete cards[id]; }
    });
    Object.keys(userOpen).forEach(function (id) { if (!keep[id]) delete userOpen[id]; });
  }

  function renderProd() {
    var up = st.upstream;
    show($('upstream'), !!up);
    if (up) { $('up-addr').textContent = up.addr || '?'; $('up-rel').textContent = String(up.release || '?').slice(0, 7); }
    var host = $('prod');
    clear(host);
    if (!up) { host.appendChild(el('p', 'empty', 'Esperando al gateway')); return; }
    var now = el('div', 'prod-now');
    add(now, el('div', 'addr', up.addr || '?'), el('div', 'k', 'Release ' + String(up.release || '?').slice(0, 12) + ' desde las ' + hms(up.ts)));
    host.appendChild(now);
    var dep = st.deploy;
    if (dep && !dep.done) host.appendChild(el('div', 'kv deploying', 'deploy en curso: release ' + String(dep.release || '?').slice(0, 14)));
    else if (dep && !dep.ok) host.appendChild(el('div', 'kv bad', 'último deploy falló' + (dep.rolled_back ? ' (rollback)' : '') + ': release ' + String(dep.release || '?').slice(0, 14)));
    var sw = st.switches;
    for (var i = sw.length - 1; i >= 1 && i >= sw.length - 4; i--) {
      var row = el('div', 'sw');
      add(row, el('span', 'ts', hms(sw[i].ts)), el('span', 'path', host0(sw[i - 1].addr) + ' \u2192 ' + host0(sw[i].addr)), el('span', 'rel', String(sw[i].release || '').slice(0, 10)));
      host.appendChild(row);
    }
    if (sw.length > 1) host.appendChild(el('div', 'foot', (sw.length - 1) + (sw.length === 2 ? ' cambio' : ' cambios') + ' de versión sin cortes'));
  }

  function renderAudits() {
    var host = $('audits');
    show($('panel-audits'), st.auditOrder.length > 0);
    clear(host);
    for (var i = st.auditOrder.length - 1; i >= 0 && i >= st.auditOrder.length - 5; i--) {
      var au = st.audits[st.auditOrder[i]];
      var row = el('div', 'au' + (au.done ? '' : ' running'));
      var f = au.done && au.done.findings != null ? au.done.findings : au.found.length;
      add(row, el('div', 'au-head', (CLASS[au.vuln_class] ? CLASS[au.vuln_class][0] : (au.vuln_class || '?'))),
        el('div', 'au-sub', au.incident + ' \u00b7 ' + (au.done ? (au.done.checked == null ? '?' : au.done.checked) : (au.candidates == null ? '?' : au.candidates)) +
          (au.done ? ' rutas revisadas' : ' rutas, en curso') + (au.done && au.done.seconds != null ? ' \u00b7 ' + dec(au.done.seconds) + ' s' : '')),
        el('div', 'au-n' + (f ? ' hit' : ''), f + (f === 1 ? ' hallazgo' : ' hallazgos')));
      host.appendChild(row);
    }
    if (st.auditOrder.length > 5) host.appendChild(el('div', 'foot', 'y ' + (st.auditOrder.length - 5) + ' auditorías anteriores'));
  }

  function renderAttacks() {
    var host = $('attacks');
    show($('panel-attacks'), S.showAttacks(st));
    clear(host);
    if (!S.showAttacks(st)) return;
    st.attackOrder.slice(-12).forEach(function (v) {
      var list = st.attacks[v].slice(-24);
      var row = el('div', 'grid-row');
      var cells = el('div', 'cells');
      list.forEach(function (x) { cells.appendChild(el('div', 'cell ' + S.attackKind(x))); });
      var last = st.attacks[v].slice(-5), lok = 0;
      last.forEach(function (x) { if (x.ok) lok++; });
      var name = el('div', 'name', v); name.title = v;
      add(row, name, cells, el('div', 'rate', lok + '/' + last.length));
      host.appendChild(row);
    });
    host.appendChild(el('div', 'foot', 'Cada columna es un intento, del más viejo al más nuevo. El número son los éxitos en los últimos 5.'));
  }

  function renderTicker() {
    var host = $('ticker');
    clear(host);
    if (!st.ticker.length) { host.appendChild(el('p', 'empty', 'Sin tráfico todavía')); return; }
    st.ticker.slice(0, TICKER_ROWS).forEach(function (t) {
      var rc = t.route === 'prod' ? 'prod' : t.route === 'deny' ? 'deny' : t.route ? 'shadow' : '';
      var row = el('div', 'row cls-' + (/^[a-z]+$/.test(t.cls || '') ? t.cls : 'x') + (t.verdict === 'oracle' ? ' oracle' : ''));
      var path = el('span', 'path', (t.method || '') + ' ' + (t.path || ''));
      path.title = (t.method || '') + ' ' + (t.path || '') + (t.reasons && t.reasons.length ? '  [' + t.reasons.join(', ') + ']' : '');
      add(row, el('span', 'ts', hms(t.ts)), el('span', 'rt ' + rc, t.route ? (ROUTE_LABEL[t.route] || t.route) : (t.cls || '...')),
        path, el('span', 'st', t.verdict === 'oracle' ? 'oráculo' : (t.status == null ? '' : t.status)));
      host.appendChild(row);
    });
  }

  function render() {
    dirty = false;
    [renderScore, renderRun, renderIncidents, renderProd, renderAudits, renderAttacks, renderTicker].forEach(function (f) {
      try { f(); } catch (e) { /* one broken panel must not blank the rest */ }
    });
  }
  function schedule() {
    if (dirty) return;
    dirty = true;
    (window.requestAnimationFrame || function (f) { return setTimeout(f, 50); })(render);
    // background tabs do not get animation frames: make sure the state is drawn anyway
    setTimeout(function () { if (dirty) render(); }, 500);
  }

  var connected = false;
  function setConn(on, text) {
    connected = on;
    $('conn').setAttribute('data-state', on ? 'on' : 'off');
    $('conn-text').textContent = on ? S.connLabel(st) : text;
  }

  function resetState() {
    st = S.newState();
    Object.keys(cards).forEach(function (id) { var n = cards[id].el; if (n.parentNode) n.parentNode.removeChild(n); });
    cards = Object.create(null);
    userOpen = Object.create(null);
    schedule();
  }

  /* Connection: one EventSource at a time, re-created by hand so that a proxy error (which closes a native
     EventSource for good) or a silent half-open socket cannot leave the page frozen. `gen` identifies the
     event store: a different one means the bus was cleared or replaced while we were away. */
  var es = null, gen = null, retryMs = 1000, retryTimer = 0, lastBeat = 0;
  var SILENCE_MS = 40000;   // the server sends a heartbeat every 15 s

  function reconnectSoon() {
    if (es) { es.close(); es = null; }
    setConn(false, 'Reconectando');
    clearTimeout(retryTimer);
    retryTimer = setTimeout(connect, retryMs);
    retryMs = Math.min(Math.round(retryMs * 1.6), 5000);
  }

  function connect() {
    clearTimeout(retryTimer);
    if (es) es.close();
    var src;
    try { src = es = new EventSource('/events/stream?since=' + st.lastSeq); } catch (e) { es = null; reconnectSoon(); return; }
    lastBeat = Date.now();
    src.onopen = function () { if (src !== es) return; lastBeat = Date.now(); retryMs = 1000; setConn(true); };
    src.onerror = function () { if (src === es) reconnectSoon(); };
    src.onmessage = function (m) {
      if (src !== es) return;
      lastBeat = Date.now();
      var ev;
      try { ev = JSON.parse(m.data); } catch (e) { return; }
      if (!ev || typeof ev !== 'object') return;
      if (typeof ev.seq === 'number' && ev.seq <= st.lastSeq) return;      // already applied
      try { S.reduce(st, ev, ev.seq); } catch (e) { /* never let one bad event stop the stream */ }
      schedule();
    };
    src.addEventListener('hb', function () { if (src === es) lastBeat = Date.now(); });
    src.addEventListener('hello', function (m) {
      if (src !== es) return;
      lastBeat = Date.now();
      var h;
      try { h = JSON.parse(m.data); } catch (e) { return; }
      if (!h || typeof h.gen !== 'string') return;
      var stale = st.lastSeq > 0 && ((gen !== null && h.gen !== gen) || (typeof h.seq === 'number' && h.seq < st.lastSeq));
      gen = h.gen;
      if (stale) { resetState(); connect(); }
    });
    src.addEventListener('reset', function () { if (src === es) resetState(); });
  }

  setInterval(function () {
    if (es && Date.now() - lastBeat > SILENCE_MS) reconnectSoon();
  }, 5000);
  window.addEventListener('online', function () { if (!es || es.readyState !== 1) { retryMs = 1000; reconnectSoon(); } });

  render();
  connect();
})();
