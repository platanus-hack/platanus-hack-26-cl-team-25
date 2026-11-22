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

  var pollingFuxaRequests = false;
  var fuxaReasons = {
    device_control: 'Control de dispositivo',
    tag_write: 'Escritura de tag',
    historian_query: 'Consulta del histórico',
    scheduler_without_token: 'Cambio de programación sin token',
    scheduler_authorization: 'Cambio de programación sin autorización',
    'repeated-denied-operations': 'Operaciones denegadas de forma repetida',
    ttl: 'Restricción vencida'
  };
  var verdictLabels = {
    authorized: 'Permitida',
    blocked: 'Bloqueada',
    unavailable: 'Evaluación no disponible',
    restricted: 'Sesión restringida',
    released: 'Restricción vencida'
  };

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
      if ((!inc.fuxa || inc.fuxa.timed) && inc.t.opened && ts >= inc.t.opened) when.appendChild(el('b', null, '+' + dec(ts - inc.t.opened) + ' s'));
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
                       realpath: 'Archivo leído', owner: 'Dueño', uid: 'Usuario', table: 'Tabla', command: 'Comando', url: 'URL', host: 'Host',
                       operation: 'Operación', role: 'Rol', session: 'Sesión', boundary: 'Efecto', decision: 'Qué pasó', expected: 'Esperado' };
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
    return txt;
  }

  var STATUS_LABEL = { open: 'Abierta', contained: 'Contenida por regla', cured: 'Curada', dismissed: 'Descartada' };
  var GATE_LABEL = { policy: 'Política', properties: 'Propiedades', poc: 'PoC', tests: 'Tests', legit: 'Tráfico legítimo' };
  var CLASS = {
    sqli: ['Inyección SQL', 'El texto del request terminaba dentro de una consulta a la base de datos.'],
    traversal: ['Lectura de archivos ajenos', 'Un nombre de archivo del request permitía salir de la carpeta prevista.'],
    idor: ['Datos de otro usuario', 'Cambiando un id en la URL, un usuario leía datos que no eran suyos.']
  };
  function storyOf(inc, status) {
    if (inc.fuxa) {
      var head = inc.fuxa.synthetic ? 'Evidencia simulada. ' : 'Un rol sin permiso alcanzó una operación administrativa. ';
      var outcome = inc.closed && inc.closed.outcome;
      if (outcome === 'patched') return head + 'El control quedó en enforce y verificado en el gateway.';
      if (outcome === 'rolled_back') return head + 'El candidato falló tras el cambio y se restauró la revisión anterior.';
      if (outcome === 'rejected') return head + 'El candidato no pasó las validaciones.';
      if (inc.awaitingReview) return head + 'El candidato está validado y espera aprobación.';
      if (inc.rule && !inc.ruleExpired) return head + 'Una regla temporal contiene la operación mientras se valida el parche.';
      return head + 'Inmune está validando el parche.';
    }
    if (status === 'cured') return inc.verify && inc.verify.blocked ? 'Parchada y verificada en producción.' : 'Parchada.';
    if (status === 'dismissed') return 'Descartada: no se pudo reproducir.';
    if (inc.closed && inc.closed.outcome === 'rule_only') return 'El incidente cerró con la regla del gateway.';
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
        if (!gates) { gates = el('span', 'gate-group'); gates.appendChild(el('span', 'gl', inc.fuxa ? 'Validaciones' : '5 validaciones')); box.appendChild(gates); }
        gates.appendChild(chip);
      } else box.appendChild(chip);
    });
    return box;
  }

  function buildDetail(inc, php) {
    var box = el('div', 'detail');
    var o = inc.oracles[0];
    var rq = (o && o.data.request) || inc.request;

    var s1 = section(inc.fuxa ? 'Evidencia' : inc.origin === 'audit' ? 'Request que lo demuestra' : 'Request del atacante', inc, S.t0(inc), 'bad');
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
      var sink = php || inc.sink || fr;
      var s2 = section('Oráculo ' + (ev0.oracle || '') + (inc.hits > 1 ? ', ' + inc.hits + ' disparos' : ''), inc, o.ts, 'bad');
      var fn = php ? php.func : fr && fr.func;
      if (sink && sink.file) rowOf(s2, 'Dónde', sink.file + (sink.line == null ? '' : ':' + sink.line) + (fn ? '  ' + fn + '()' : ''));
      if (inc.fuxa) rowOf(s2, 'Origen', (o.data.mode || 'producción') + (o.data.status == null ? ', evento Socket.IO' : ', HTTP ' + o.data.status), 'plain');
      else rowOf(s2, 'Respuesta', 'HTTP ' + (o.data.status == null ? '?' : o.data.status) + (o.data.mode ? ', clon ' + o.data.mode : ''));
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
      var result = inc.fuxa && inc.deploy && inc.deploy.doneTs
        ? (inc.deploy.ok || inc.deploy.rolled_back ? 'accepted' : 'rejected') : a.status;
      var sa = section((inc.fuxa ? 'Parche local' : 'Parche') + (inc.attempts.length > 1 ? ', intento ' + a.attempt : ''), inc, a.diffTs || a.ts,
        result === 'accepted' ? 'done' : result === 'rejected' ? 'bad' : 'run');
      var ab = el('div', 'attempt ' + result);
      var ah = el('div', 'attempt-head');
      add(ah, el('span', null, a.source === 'llm' ? 'Escrito por el LLM' : 'Fuente: ' + (a.source || '?')), el('span', 'st', stl[result] || result));
      ab.appendChild(ah);
      if (a.diff) ab.appendChild(renderDiff(a.diff));
      var gates = el('div', 'gates');
      S.GATES.forEach(function (g) {
        var gr = a.gates[g];
        if (inc.fuxa && gr.state === 'pending') return;
        var ge = el('div', 'gate ' + gr.state);
        var gn = el('div', 'n');
        add(gn, el('i', 'sd'), el('span', null, GATE_LABEL[g] || g));
        add(ge, gn, gr.detail ? el('div', 'det', clip(gr.detail.replace(/^OK: /, ''), 400)) : null);
        gates.appendChild(ge);
      });
      if (gates.firstChild) ab.appendChild(gates);
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
      var sd = section(inc.fuxa ? (d.rolled_back ? 'Reversión' : 'Redespliegue') : 'Deploy blue/green', inc, (inc.prod && inc.prod.ts) || d.doneTs || d.startTs, failed ? 'bad' : inc.prod ? 'done' : 'run');
      rowOf(sd, 'Release', String(d.release || (inc.prod && inc.prod.release) || '?').slice(0, 12));
      var cn = canaryText(d.canary);
      if (cn) rowOf(sd, 'Canario', cn, 'plain');
      if (inc.prod) rowOf(sd, 'Tráfico', 'Cambiado a ' + (inc.prod.addr || '?') + ' sin cortes', 'plain');
      if (inc.fuxa && d.doneTs) {
        rowOf(sd, 'Resultado', (d.ok ? 'Verificado' : d.rolled_back ? 'Reversión verificada' : 'Falló') +
          (d.detail ? ': ' + clip(d.detail, 300) : ''), 'plain');
      } else if (failed) rowOf(sd, 'Resultado', 'Falló' + (d.rolled_back ? ', revertido' : '') + (d.detail ? ': ' + clip(d.detail, 300) : ''), 'plain');
      else if (!d.doneTs && d.startTs) rowOf(sd, 'Estado', inc.prod ? 'Retirando la versión anterior' : 'Levantando la versión nueva', 'plain');
      box.appendChild(sd);
    }

    if (inc.verify) {
      var sv = section('Verificación', inc, inc.verify.ts, inc.verify.blocked ? 'done' : 'bad');
      sv.appendChild(el('p', 'verdict', inc.verify.blocked ? 'El mismo ataque, repetido contra producción, ya no funciona.' : 'El ataque todavía funciona en producción.'));
      box.appendChild(sv);
    }
    if (!inc.fuxa && inc.closed && inc.closed.outcome !== 'patched') {
      box.appendChild(section('Cerrado: ' + (inc.closed.outcome || '?'), inc, inc.closed.ts, 'mute'));
    }
    return box;
  }

  function cell(cls, value, na) { return el('span', 'c ' + cls + (na ? ' na' : ''), value); }

  /* one incident = one row of the list; opening it shows the whole story */
  function buildCard(inc, open) {
    var status = S.status(inc), phase = S.phase(inc);
    var label = phase ? phase.charAt(0).toUpperCase() + phase.slice(1) : STATUS_LABEL[status];
    if (inc.fuxa) {
      var outcome = inc.closed && inc.closed.outcome;
      if (outcome === 'rejected') label = 'Requiere revisión';
      else if (outcome === 'rolled_back') label = 'Reversión verificada';
      else if (inc.awaitingReview) label = 'Pendiente de aprobación';
      else if (inc.deploy && inc.deploy.ok) label = 'Parche verificado';
      else label = inc.deploy ? 'Redesplegando' : inc.attempts.length ? 'Validando parche local' : 'Evidencia registrada';
    }
    var live = !!(phase && inc.opened);
    var cls = CLASS[inc.vuln_class];
    var card = el('details', 'card' + (inc.origin === 'audit' ? ' audit' : '') + (live ? ' live' : ''));
    card.setAttribute('data-status', status);
    card.id = 'card-' + inc.id;

    var row = el('summary', 'row');
    row.appendChild(statusIcon(!inc.opened && status === 'open' ? 'queued' : status === 'rolledBack' ? 'contained' : status));
    row.appendChild(el('span', 'id', inc.id));
    var title = el('span', 'title');
    var php = inc.closed && inc.closed.outcome === 'rule_only' ? S.phpLocation(inc) : null;
    add(title, el('span', 'cls', cls ? cls[0] : (inc.vuln_class || 'Incidente')),
      el('span', 'route', (inc.method ? inc.method + ' ' : '') + (inc.route || '')),
      php ? el('span', 'tag source-location', php.file + ':' + php.line) : null,
      inc.origin === 'audit' ? el('span', 'tag', 'Auto-auditoría') : null);
    row.appendChild(title);
    var r = S.timeToRule(inc), p = S.timeToProd(inc);
    add(row, cell('t-rule', secs(r), r == null), cell('t-prod', secs(p), p == null));
    var stc = el('span', 'c state');
    if (live) stc.appendChild(el('i', 'pulse'));
    stc.appendChild(el('span', null, label));
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
      var timings = inc.fuxa ? [['Tiempo a parche', p]] : [['En cola', S.queueTime(inc)], ['Regla', r], ['Parche escrito', S.timeToDiff(inc)], ['Merge', S.timeToMerged(inc)], ['En producción', p], ['Verificado', S.timeToVerified(inc)]];
      timings.forEach(function (x) {
        if (x[1] != null) prop(x[0], secs(x[1]));
      });
      if (inc.attempts.length > 1) prop('Intentos', inc.attempts.length);
      if (inc.runs > 1) prop('Corridas del pipeline', inc.runs);
      props.title = 'Tiempos desde que el pipeline abre el incidente';
      body.appendChild(props);

      if (live || inc.fuxa) body.appendChild(buildSteps(inc));
      body.appendChild(buildDetail(inc, php));
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
  // What the canary saw, in one line. Nothing when it was off: an empty row would only be noise.
  function canaryText(c) {
    if (!c || (c.verdict === 'skipped' && !c.requests && !c.seconds)) return null;
    var share = (typeof c.weight === 'number' ? Math.round(c.weight * 100) + '% del tráfico real' : 'Parte del tráfico real') +
      (typeof c.seconds === 'number' ? ' durante ' + secs(c.seconds) : '');
    var seen = count(c.requests, 'request', 'requests');
    if (c.verdict === 'ok') return share + ': ' + seen + ', mismo comportamiento que la versión anterior';
    if (c.verdict === 'worse') {
      var what = c.e5 ? c.e5 + ' con error del servidor (la versión anterior: ' + c.stableE5 + ' de ' + c.stableRequests + ')'
        : c.e4 + ' rechazados (la versión anterior: ' + c.stableE4 + ' de ' + c.stableRequests + ')';
      return share + ': ' + seen + ', ' + what + '. Se descartó antes de recibir todo el tráfico';
    }
    return share + ': ' + seen + ', muy pocos para comparar. Se vigiló después del cambio';
  }

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
    if (st.fuxa) {
      $('inc-count').textContent = s.seen ? s.seen + ' · ' + s.cured + ' corregidos' : '';
      $('conn-info').textContent = st.events ? st.events + ' eventos' : '';
      return;
    }
    var confirmed = s.seen - s.dismissed, live = confirmed - s.audit;
    $('fl-total').textContent = s.total.toLocaleString('es');
    fact('fl-detect-fact', [count(s.detonated, 'ejecutado en un clon', 'ejecutados en un clon'), s.deny ? count(s.deny, 'rechazado', 'rechazados') : null]);
    $('fl-confirmed').textContent = confirmed;
    fact('fl-confirm-fact', [count(live, 'por ataque', 'por ataques'), s.audit ? s.audit + ' por auto-auditoría' : null,
      s.dismissed ? count(s.dismissed, 'descartada', 'descartadas') : null]);
    $('fl-rule').textContent = n1(s.ruleMedian);
    fact('fl-contain-fact', [s.open ? el('b', 'bad', count(s.open, 'abierta', 'abiertas') + ' sin regla') : null,
      s.contained ? el('b', 'warn', count(s.contained, 'contenida', 'contenidas') + ' esperando parche') : (s.open ? null : 'Nada esperando parche')]);
    $('fl-prod').textContent = n1(s.prodMedian);
    fact('fl-cure-fact', [el('b', s.cured === confirmed && confirmed ? 'ok' : null, s.cured + ' de ' + confirmed + ' curadas')]);
    $('flow').setAttribute('data-open', s.open ? '1' : '0');
    $('inc-count').textContent = s.seen ? s.seen + (s.dismissed ? ' (' + s.dismissed + ' descartada' + (s.dismissed === 1 ? '' : 's') + ')' : '') : '';
    $('conn-info').textContent = st.events ? st.events + ' eventos' : '';
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
    show($('upstream'), !!up && !st.fuxa);
    show($('panel-prod'), !st.fuxa);
    if (up) { $('up-addr').textContent = up.addr || '?'; $('up-rel').textContent = String(up.release || '?').slice(0, 7); }
    var host = $('prod');
    clear(host);
    if (!up) { host.appendChild(el('p', 'empty', 'Esperando al gateway')); return; }
    var now = el('div', 'prod-now');
    add(now, el('div', 'addr', up.addr || '?'), el('div', 'k', 'Release ' + String(up.release || '?').slice(0, 12) + ' desde las ' + hms(up.ts)));
    host.appendChild(now);
    var dep = st.deploy;
    if (st.canary) host.appendChild(el('div', 'kv deploying', 'canario: ' + (typeof st.canary.weight === 'number' ? Math.round(st.canary.weight * 100) + '% del tráfico' : 'parte del tráfico') + ' en la release ' + String(st.canary.release || '?').slice(0, 14)));
    else if (dep && !dep.done) host.appendChild(el('div', 'kv deploying', 'deploy en curso: release ' + String(dep.release || '?').slice(0, 14)));
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
    show($('panel-attacks'), !st.fuxa && st.attackOrder.length > 0);
    clear(host);
    if (!st.attackOrder.length) return;
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
    var fuxaLabels = { suspect: 'Sospechoso', evidence: 'Ataque confirmado', blocked: 'Ataque bloqueado', simulation: 'Simulación' };
    var ticker = st.fuxa ? st.ticker.slice().sort(function (a, b) { return b.ts - a.ts; }) : st.ticker;
    ticker.slice(0, TICKER_ROWS).forEach(function (t) {
      var rc = t.route === 'prod' ? 'prod' : t.route === 'deny' ? 'deny' : t.route ? 'shadow' : '';
      var row = el('div', 'row cls-' + (/^[a-z]+$/.test(t.cls || '') ? t.cls : 'x') + (t.verdict === 'oracle' ? ' oracle' : ''));
      var path = el('span', 'path', (t.method || '') + ' ' + (t.path || ''));
      path.title = (t.method || '') + ' ' + (t.path || '') + (t.reasons && t.reasons.length ? '  [' + t.reasons.join(', ') + ']' : '');
      if (st.fuxa && fuxaReasons[t.reason]) {
        path.textContent += ' · ' + fuxaReasons[t.reason];
        path.title = path.textContent;
      }
      var label = st.fuxa ? (fuxaLabels[t.cls] || verdictLabels[t.cls]) : (ROUTE_LABEL[t.route] || t.route);
      add(row, el('span', 'ts', hms(t.ts)), el('span', 'rt ' + rc, label || t.cls || '…'),
        path, el('span', 'st', t.verdict === 'oracle' ? 'oráculo' : (t.status == null ? '' : t.status)));
      host.appendChild(row);
    });
  }

  var projectSubtitle = '';

  function renderFuxa() {
    var live = st.fuxa;
    document.body.classList.toggle('fuxa', !!live);
    var subtitle = live ? 'Estación Delta · FUXA v1.2.9' : projectSubtitle;
    $('dashboard-subtitle').textContent = subtitle;
    show($('dashboard-subtitle'), !!subtitle);
    show($('fuxa-summary'), !!live);
    show($('traffic-legend'), !live);
    $('production-column').textContent = live ? 'Tiempo a parche' : 'En producción';
    $('traffic-title').textContent = live ? 'Detecciones de Inmune' : 'Tráfico';
    show($('fuxa-requests-panel'), !!live);
    if (!live) return;
    if (!pollingFuxaRequests) {
      pollingFuxaRequests = true;
      pollFuxaRequests();
    }
    $('fuxa-revision').textContent = live.active ? 'Revisión activa ' + live.active : 'FUXA sin revisión activa';
    $('fuxa-monitor').textContent = live.monitor ? 'Monitor activo' : 'Monitor sin señal reciente';
    var persistence = $('fuxa-persistence');
    persistence.hidden = !live.persistent;
    persistence.textContent = 'Proyecto y sesiones persistentes';
    var patchMode = $('fuxa-patch-mode');
    patchMode.hidden = !live.patch_mode;
    if (live.patch_mode) {
      patchMode.textContent = live.patch_mode === 'review' ?
        'Parches sujetos a aprobación' : 'Parches con despliegue automático';
    }
    var validation = $('fuxa-validation');
    validation.hidden = !live.validation;
    if (live.validation) {
      validation.textContent = 'Validación aislada · ' + live.validation.checks + ' comprobaciones con ' +
        live.validation.identities + ' identidades sintéticas' +
        (live.validation.evaluator === 'metadata' ? ' · Autorización aislada antes del efecto' : '');
    }
    var legitimate = $('fuxa-legitimate');
    legitimate.hidden = !live.legitimate;
    if (live.legitimate) {
      var flows = { project: 'proyecto HMI', guest_access: 'acceso de invitados', realtime: 'conexión en vivo' };
      legitimate.textContent = 'Flujos verificados · ' +
        live.legitimate.flows.map(function (flow) { return flows[flow] || flow; }).join(', ');
    }
    $('fuxa-pending').textContent = live.pending + ' entradas del inventario con cobertura pendiente' +
      (live.partial ? ' · ' + live.partial + ' con cobertura parcial' : '');
    var audit = $('fuxa-audit');
    audit.hidden = !live.coverage_audit;
    if (live.coverage_audit) {
      audit.textContent = 'Auditoría de cobertura · ' + live.coverage_audit.write_review + ' rutas de escritura, ' +
        live.coverage_audit.read_review + ' rutas de lectura y ' + live.coverage_audit.event_review +
        ' eventos por revisar';
    }
    var list = $('fuxa-coverage');
    var labels = { 'settings.write': 'Escritura de configuración', 'system-function.run': 'Funciones del sistema' };
    clear(list);
    live.coverage.forEach(function (id) {
      list.appendChild(el('li', null, (labels[id] || id) + ' · ' + (live.enforced.indexOf(id) >= 0 ? 'control activo' : 'en observación')));
    });
    (live.protected || []).forEach(function (id) {
      list.appendChild(el('li', null, (fuxaReasons[id] || id) + ' · control activo'));
    });
  }

  function renderRestrictions() {
    var host = $('restrictions');
    if (!host) return;
    var active = Object.keys(st.restrictions).map(function (key) { return st.restrictions[key]; });
    active.sort(function (a, b) { return (a.expires || 0) - (b.expires || 0); });
    var countLabel = $('fuxa-restricted-count');
    countLabel.hidden = !st.fuxa || active.length === 0;
    countLabel.textContent = count(active.length, 'sesión restringida', 'sesiones restringidas');
    var panel = $('restrictions-panel');
    if (panel) panel.hidden = !st.fuxa || active.length === 0;
    clear(host);
    if (!st.fuxa || !active.length) {
      if (st.fuxa) host.appendChild(el('p', 'empty', 'Sin restricciones de sesión.'));
      return;
    }
    var now = Date.now() / 1000;
    active.forEach(function (r) {
      var row = el('div', 'row cls-blocked');
      var ops = (r.operations || []).map(function (op) { return fuxaReasons[op] || op; }).join(', ');
      var left = typeof r.expires === 'number' ? Math.max(0, Math.round(r.expires - now)) : null;
      var path = el('span', 'path', ops || 'operación restringida');
      path.title = fuxaReasons[r.reason] || r.reason || '';
      add(row, el('span', null, hms(r.ts || r.expires)), el('span', 'rt deny', 'Restringida'),
        path, el('span', null, left == null ? '—' : 'vence en ' + left + ' s'));
      host.appendChild(row);
    });
  }

  async function pollFuxaRequests() {
    var host = $('fuxa-requests');
    try {
      var response = await fetch('/fuxa/requests', { cache: 'no-store' });
      if (!response.ok) throw new Error('Request feed unavailable');
      var feed = await response.json();
      clear(host);
      if (!feed.available || !feed.requests.length) {
        host.appendChild(el('p', 'empty', feed.available ?
          'Esperando peticiones al gateway de FUXA.' : 'Gateway no disponible.'));
      }
      feed.requests.slice(0, 15).forEach(function (request) {
        var row = el('div', 'row cls-' + request.class);
        var status = request.status == null ? '—' : request.status;
        var labels = { suspect: 'Sospechosa', blocked: 'Bloqueada', clean: 'Sin señales', uninspected: 'Sin cobertura' };
        var verdict = verdictLabels[request.verdict];
        var classification = el('span', 'rt', verdict || labels[request.class] || labels.uninspected);
        var reason = fuxaReasons[request.reason];
        if (request.class === 'suspect' || request.class === 'blocked') {
          classification.title = reason || 'El servidor rechazó el acceso (' + status + ')';
        }
        var requestText = (request.transport === 'websocket' ? 'WS' : request.method) + ' ' + request.path;
        var path = el('span', 'path', reason ? requestText + ' · ' + reason : requestText);
        if (reason) path.title = path.textContent;
        add(row, el('span', null, hms(request.ts)),
          classification, path,
          el('span', null, status), el('span', null, request.ms + ' ms'));
        host.appendChild(row);
      });
    } catch {
      clear(host);
      host.appendChild(el('p', 'empty', 'No se pudo cargar el tráfico del gateway.'));
    } finally {
      window.setTimeout(pollFuxaRequests, 2000);
    }
  }

  function render() {
    dirty = false;
    [renderFuxa, renderScore, renderIncidents, renderProd, renderAudits, renderAttacks, renderTicker, renderRestrictions].forEach(function (f) {
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

  function setConn(on, text) {
    $('conn').setAttribute('data-state', on ? 'on' : 'off');
    $('conn-text').textContent = text;
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
    src.onopen = function () { if (src !== es) return; lastBeat = Date.now(); retryMs = 1000; setConn(true, 'En vivo'); };
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
      var subtitle = typeof h.subtitle === 'string' ? h.subtitle : '';
      if (projectSubtitle !== subtitle) { projectSubtitle = subtitle; schedule(); }
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
