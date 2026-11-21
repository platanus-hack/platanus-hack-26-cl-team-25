/* DOM layer. Event data only enters the page through textContent. */
(function () {
  'use strict';
  var S = window.ImmuneState;
  var st = S.newState();
  var cards = {};          // incident id -> {el, rev}
  var dirty = false, rafId = 0;

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function add(parent) { for (var i = 1; i < arguments.length; i++) if (arguments[i]) parent.appendChild(arguments[i]); return parent; }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function hms(ts) {
    if (typeof ts !== 'number' || !ts) return '--:--:--';
    var d = new Date(ts * 1000);
    function p(n) { return n < 10 ? '0' + n : '' + n; }
    return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }
  function secs(x) { return typeof x === 'number' ? x.toFixed(1) + ' s' : '-'; }
  function delta(prev, ts) { return (typeof prev === 'number' && typeof ts === 'number') ? '+' + Math.max(0, ts - prev).toFixed(1) + ' s' : ''; }
  function clip(s, n) { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n) + ' ...' : s; }
  function json(v) { try { return JSON.stringify(v); } catch (e) { return String(v); } }

  function link(url, text) {
    if (S.isGithubUrl(url)) {
      var a = el('a', null, text || url);
      a.href = url; a.target = '_blank'; a.rel = 'noopener noreferrer';
      return a;
    }
    return el('span', null, url == null ? '' : url);
  }

  function section(title, ts, prev) {
    var s = el('div', 'sec');
    var h = el('h3', null, title + (ts ? '  ' + hms(ts) : ''));
    if (ts && prev) h.appendChild(el('span', 'd', delta(prev, ts)));
    s.appendChild(h);
    return s;
  }

  function renderDiff(diff) {
    var box = el('div', 'diff');
    var lines = String(diff).split('\n');
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i], c = '';
      if (l.indexOf('+++') === 0 || l.indexOf('---') === 0 || l.indexOf('diff ') === 0 || l.indexOf('index ') === 0) c = 'meta';
      else if (l.charAt(0) === '+') c = 'add';
      else if (l.charAt(0) === '-') c = 'del';
      else if (l.indexOf('@@') === 0) c = 'hunk';
      box.appendChild(el('div', c, l === '' ? ' ' : l));
    }
    return box;
  }

  function requestText(o) {
    var r = (o.data && o.data.request) || {};
    var q = r.query ? '?' + r.query : '';
    var body = S.decodeB64(r.body_b64);
    var txt = (r.method || '?') + ' ' + (r.path || '?') + q;
    if (body) txt += '\n\n' + clip(body, 1500);
    return txt;
  }

  function buildCard(inc) {
    var status = S.status(inc);
    var card = el('article', 'card');
    card.setAttribute('data-status', status);
    var labels = { open: 'abierta', contained: 'contenida por regla', cured: 'curada por parche' };

    var head = el('div', 'card-head');
    var title = (inc.vuln_class || 'incidente') + '  ' + (inc.route || '') + (inc.param && inc.param.name ? '  [' + inc.param.name + ']' : '');
    add(head, el('div', 'card-title', title), el('span', 'badge', labels[status]));
    card.appendChild(head);
    card.appendChild(el('div', 'kv', inc.id + (inc.hits > 1 ? '   (' + inc.hits + ' disparos del oraculo)' : '')));

    var times = el('div', 'times');
    [['Tiempo a regla', S.timeToRule(inc)], ['Tiempo a parche', S.timeToPatch(inc)]].forEach(function (p) {
      var t = el('div', 't' + (p[1] == null ? ' na' : ''));
      add(t, el('div', 'v', secs(p[1])), el('div', 'k', p[0]));
      times.appendChild(t);
    });
    card.appendChild(times);

    var ms = el('div', 'ms');
    S.milestones(inc).forEach(function (m) {
      var chip = el('span', 'm');
      add(chip, el('b', null, m.label), el('span', 'ts', hms(m.ts)), m.delta ? el('span', 'd', '+' + m.delta.toFixed(1) + ' s') : null);
      ms.appendChild(chip);
    });
    card.appendChild(ms);

    var prev = null;
    var o = inc.oracles[0];
    var base = S.t0(inc);
    if (o) {
      var s1 = section('1. Request del atacante', o.ts, null);
      s1.appendChild(el('div', 'req', requestText(o)));
      card.appendChild(s1);
      var ev0 = (o.data.events && o.data.events[0]) || {};
      var fr = (ev0.stack && ev0.stack[0]) || null;
      var sink = inc.sink || fr;
      var s2 = section('2. Oraculo disparado', o.ts, base);
      var pills = el('div', 'kv');
      add(pills, el('span', 'pill', 'oraculo: ' + (ev0.oracle || '?')), el('span', 'pill', 'modo ' + (o.data.mode || '?')),
        el('span', 'pill', 'HTTP ' + (o.data.status == null ? '?' : o.data.status)));
      s2.appendChild(pills);
      if (sink) s2.appendChild(el('div', 'kv', 'donde: ' + sink.file + ':' + sink.line + (fr && fr.func ? '  ' + fr.func + '()' : '')));
      if (ev0.detail) s2.appendChild(el('div', 'kv', 'detalle: ' + clip(json(ev0.detail), 700)));
      card.appendChild(s2);
      prev = o.ts;
    } else if (inc.opened) {
      var s0 = section('1. Incidente abierto', inc.opened, null);
      s0.appendChild(el('div', 'kv', (inc.route || '') + (inc.sink ? '  ' + inc.sink.file + ':' + inc.sink.line : '')));
      card.appendChild(s0);
      prev = inc.opened;
    }

    if (inc.rule) {
      var sr = section('3. Regla activa', inc.rule.ts, prev);
      var r = inc.rule.rule || {};
      sr.appendChild(el('div', 'kv', (r.method || '') + ' ' + (r.route || '') + '  alcance: ' + (r.scope || '?') + '  ttl: ' + (r.ttl_s || '?') + ' s'));
      if (r.grammar) sr.appendChild(el('div', 'kv', 'gramatica: ' + clip(r.grammar, 200)));
      if (inc.ruleExpired) sr.appendChild(el('div', 'kv', 'expirada ' + hms(inc.ruleExpired.ts) + ' (' + (inc.ruleExpired.reason || '') + ')'));
      card.appendChild(sr);
      prev = inc.rule.ts;
    }

    if (inc.poc) {
      var sp = section('PoC', inc.poc.ts, prev);
      sp.appendChild(el('div', 'kv', (inc.poc.reproducible ? 'reproducible' : 'NO reproducible') + '  corridas: ' + (inc.poc.runs == null ? '?' : json(inc.poc.runs))));
      card.appendChild(sp);
      prev = inc.poc.ts;
    }

    inc.attempts.forEach(function (a) {
      var sa = section('4. Intento de parche #' + a.attempt, a.ts, prev);
      var box = el('div', 'attempt ' + a.status);
      var ah = el('div', 'attempt-head');
      var stl = { pending: 'en curso', rejected: 'rechazado', accepted: 'aceptado' };
      add(ah, el('span', null, 'fuente: ' + (a.source || '?')), el('span', 'st', stl[a.status] || a.status));
      box.appendChild(ah);
      var gates = el('div', 'gates');
      S.GATES.forEach(function (g) {
        var gr = a.gates[g];
        var ge = el('div', 'gate ' + gr.state);
        var mark = gr.state === 'pass' ? ' OK' : gr.state === 'fail' ? ' FALLA' : ' ...';
        add(ge, el('div', 'n', g + mark), gr.detail ? el('div', 'det', clip(gr.detail, 400)) : null);
        gates.appendChild(ge);
      });
      box.appendChild(gates);
      if (a.diff) box.appendChild(renderDiff(a.diff));
      sa.appendChild(box);
      card.appendChild(sa);
      prev = a.diffTs || a.ts;
    });

    if (inc.pr || inc.merged) {
      var spr = section('5. Pull request', (inc.merged || inc.pr).ts, prev);
      if (inc.pr) { var l1 = el('div', 'kv'); add(l1, el('span', 'k', 'abierto: '), link(inc.pr.url), el('span', 'k', '  rama ' + (inc.pr.branch || ''))); spr.appendChild(l1); }
      if (inc.merged) { var l2 = el('div', 'kv'); add(l2, el('span', 'k', 'fusionado: '), link(inc.merged.url), el('span', 'k', '  ' + clip(inc.merged.sha || '', 12))); spr.appendChild(l2); }
      card.appendChild(spr);
      prev = (inc.merged || inc.pr).ts;
    }

    if (inc.deploy) {
      var d = inc.deploy;
      var sd = section('6. Deploy', d.doneTs || d.startTs, prev);
      var txt = 'release ' + (d.release || '?') + (d.doneTs ? (d.ok ? '  OK' : '  FALLO') + (d.rolled_back ? '  (rollback)' : '') : '  en curso...');
      sd.appendChild(el('div', 'kv', txt));
      if (d.detail) sd.appendChild(el('div', 'kv', clip(d.detail, 300)));
      card.appendChild(sd);
      prev = d.doneTs || d.startTs;
    }

    if (inc.verify) {
      var sv = section('7. Verificacion: mismo exploit contra prod', inc.verify.ts, prev);
      sv.appendChild(el('div', 'kv', inc.verify.blocked ? 'BLOQUEADO: el exploit ya no funciona' : 'ATENCION: el exploit todavia funciona en prod'));
      card.appendChild(sv);
    }
    if (inc.closed) card.appendChild(el('div', 'kv', 'cierre: ' + (inc.closed.outcome || '?') + ' a las ' + hms(inc.closed.ts)));
    return card;
  }

  function renderScore() {
    var s = S.scoreboard(st);
    $('sc-open').textContent = s.open; $('sc-contained').textContent = s.contained; $('sc-cured').textContent = s.cured;
    $('sc-seen').textContent = s.seen; $('sc-prod').textContent = s.prod; $('sc-det').textContent = s.detonated;
    $('sc-cap').textContent = s.captive;
    $('sc-clones').textContent = s.free == null ? '-' : s.free + ' / ' + s.busy;
  }

  function renderIncidents() {
    var host = $('incidents');
    var ids = st.order.filter(function (id) { var i = st.incidents[id]; return i.opened || i.oracles.length; }).reverse();
    var empty = $('inc-empty');
    if (empty) empty.style.display = ids.length ? 'none' : '';
    var prevNode = null;
    ids.forEach(function (id) {
      var inc = st.incidents[id], c = cards[id];
      if (!c || c.rev !== inc.rev || c.status !== S.status(inc)) {
        var fresh = buildCard(inc);
        if (c && c.el.parentNode) host.replaceChild(fresh, c.el);
        else host.appendChild(fresh);
        c = cards[id] = { el: fresh, rev: inc.rev, status: S.status(inc) };
      }
      // keep newest first
      var wantAfter = prevNode;
      var cur = wantAfter ? wantAfter.nextSibling : host.firstChild;
      if (cur !== c.el) host.insertBefore(c.el, cur);
      prevNode = c.el;
    });
    Object.keys(cards).forEach(function (id) {
      if (!st.incidents[id] || ids.indexOf(id) < 0) { var n = cards[id].el; if (n.parentNode) n.parentNode.removeChild(n); delete cards[id]; }
    });
  }

  function renderAttacks() {
    var host = $('attacks');
    clear(host);
    if (!st.attackOrder.length) { host.appendChild(el('p', 'empty', 'Sin intentos todavia.')); return; }
    st.attackOrder.forEach(function (v) {
      var list = st.attacks[v].slice(-40);
      var row = el('div', 'grid-row');
      var cells = el('div', 'cells');
      var ok = 0;
      list.forEach(function (x) { cells.appendChild(el('div', 'cell ' + S.attackKind(x))); if (x.ok) ok++; });
      var last = st.attacks[v].slice(-5), lok = 0;
      last.forEach(function (x) { if (x.ok) lok++; });
      var name = el('div', 'name', v); name.title = v;
      add(row, name, cells, el('div', 'rate', lok + '/' + last.length));
      host.appendChild(row);
    });
    host.appendChild(el('div', 'kv', 'columna = intento (viejo a nuevo). Numero: exitos en los ultimos 5.'));
  }

  function renderTicker() {
    var host = $('ticker');
    clear(host);
    if (!st.ticker.length) { host.appendChild(el('p', 'empty', 'Sin trafico todavia.')); return; }
    st.ticker.slice(0, 18).forEach(function (t) {
      var rc = t.route === 'prod' ? 'prod' : t.route === 'deny' ? 'deny' : t.route ? 'shadow' : '';
      var row = el('div', 'row cls-' + (t.cls || 'x'));
      add(row, el('span', null, hms(t.ts)), el('span', 'rt ' + rc, t.route || (t.cls || '...')),
        el('span', 'path', (t.method || '') + ' ' + (t.path || '')), el('span', null, t.status == null ? '' : t.status));
      host.appendChild(row);
    });
  }

  function render() {
    dirty = false; rafId = 0;
    renderScore(); renderIncidents(); renderAttacks(); renderTicker();
  }
  function schedule() {
    if (dirty) return;
    dirty = true;
    rafId = (window.requestAnimationFrame || function (f) { return setTimeout(f, 50); })(render);
  }

  function setConn(on, text) {
    $('conn').setAttribute('data-state', on ? 'on' : 'off');
    $('conn-text').textContent = text;
  }

  function start() {
    var es = new EventSource('/events/stream');
    es.onopen = function () { setConn(true, 'en vivo'); };
    es.onerror = function () { setConn(false, 'reconectando...'); };
    es.onmessage = function (m) {
      var ev;
      try { ev = JSON.parse(m.data); } catch (e) { return; }
      if (!ev || typeof ev !== 'object') return;
      try { S.reduce(st, ev, ev.seq); } catch (e) { /* never let one bad event stop the stream */ }
      schedule();
    };
    es.addEventListener('reset', function () {
      st = S.newState();
      Object.keys(cards).forEach(function (id) { var n = cards[id].el; if (n.parentNode) n.parentNode.removeChild(n); });
      cards = {};
      schedule();
    });
  }

  render();
  start();
})();
