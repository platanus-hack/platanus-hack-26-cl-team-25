/* Pure state reduction: events -> dashboard state. No DOM. Works in browser (window.ImmuneState) and node. */
(function (root) {
  'use strict';

  var GATES = ['policy', 'properties', 'poc', 'tests', 'legit'];
  var TICKER_MAX = 60;
  var PENDING_ORACLE_MAX = 200;
  var ATTACK_MAX = 400;

  function newState() {
    return {
      incidents: {}, order: [], pendingOracles: [], rules: {}, deploys: [],
      attacks: {}, attackOrder: [],
      ticker: [], tickerByRid: {},
      counters: { prod: 0, detonated: 0, deny: 0, total: 0 },
      sessions: {}, pool: null, fuxa: null, lastSeq: 0, lastTs: 0, events: 0
    };
  }

  function ensure(st, id, ts) {
    var inc = st.incidents[id];
    if (!inc) {
      inc = st.incidents[id] = {
        id: id, rev: 0, opened: null, vuln_class: null, route: null, param: null, sink: null,
        oracles: [], hits: 0, rule: null, ruleExpired: null, poc: null,
        attempts: [], pr: null, merged: null, deploy: null, verify: null, closed: null, t: {}
      };
      st.order.push(id);
      inc.t.seen = ts;
    }
    return inc;
  }

  function attemptOf(inc, n, ts) {
    var a = null, i;
    for (i = 0; i < inc.attempts.length; i++) if (inc.attempts[i].attempt === n) a = inc.attempts[i];
    if (!a) {
      a = { attempt: n, source: null, ts: ts, diff: null, diffTs: null, gates: {}, status: 'pending' };
      for (i = 0; i < GATES.length; i++) a.gates[GATES[i]] = { state: 'pending', detail: null, ts: null };
      inc.attempts.push(a);
      inc.attempts.sort(function (x, y) { return x.attempt - y.attempt; });
    }
    return a;
  }

  function attemptStatus(a) {
    var allOk = true;
    for (var i = 0; i < GATES.length; i++) {
      var g = a.gates[GATES[i]];
      if (g.state === 'fail') return 'rejected';
      if (g.state !== 'pass') allOk = false;
    }
    return allOk ? 'accepted' : 'pending';
  }

  function sameFile(a, b) {
    if (!a || !b) return false;
    return a === b || a.endsWith('/' + b) || b.endsWith('/' + a);
  }

  function oracleMatchesSink(data, sink) {
    if (!sink || !data || !Array.isArray(data.events)) return false;
    for (var i = 0; i < data.events.length; i++) {
      var stack = (data.events[i] && data.events[i].stack) || [];
      for (var j = 0; j < stack.length; j++) {
        if (sameFile(stack[j].file, sink.file) && stack[j].line === sink.line) return true;
      }
    }
    return false;
  }

  function attachOracle(inc, o) {
    inc.oracles.push(o);
    inc.hits = inc.oracles.length;
    if (inc.t.oracle == null || o.ts < inc.t.oracle) inc.t.oracle = o.ts;
  }

  function touch(inc) { inc.rev++; }

  function findIncidentForRule(st, rule, evIncident) {
    var id = evIncident || (rule && rule.incident);
    if (id) return ensure(st, id, 0);
    for (var i = 0; i < st.order.length; i++) {
      var c = st.incidents[st.order[i]];
      if (!c.rule && c.route && rule && c.route === rule.route) return c;
    }
    return null;
  }

  function reduce(st, ev, seq) {
    var d = ev.data || {};
    var ts = typeof ev.ts === 'number' ? ev.ts : 0;
    var inc, a, i, id;
    st.events++;
    if (typeof seq === 'number') st.lastSeq = seq;
    if (ts > st.lastTs) st.lastTs = ts;
    id = ev.incident || d.incident || null;

    switch (ev.type) {
      case 'request.classified':
        pushTicker(st, ev.rid, { ts: ts, method: d.method, path: d.path, cls: d.class, route: null, status: null });
        break;
      case 'request.routed':
        st.counters.total++;
        if (d.route === 'prod') st.counters.prod++;
        else if (d.route === 'deny') st.counters.deny++;
        else if (typeof d.route === 'string') st.counters.detonated++;
        var te = ev.rid && st.tickerByRid[ev.rid];
        if (!te) te = pushTicker(st, ev.rid, { ts: ts, method: null, path: null, cls: null });
        te.route = d.route; te.status = d.status; te.ms = d.ms;
        break;
      case 'oracle.fired':
        var o = { ts: ts, rid: ev.rid, data: d };
        if (id) { inc = ensure(st, id, ts); attachOracle(inc, o); touch(inc); break; }
        var matched = false;
        for (i = 0; i < st.order.length; i++) {
          inc = st.incidents[st.order[i]];
          if (oracleMatchesSink(d, inc.sink)) { attachOracle(inc, o); touch(inc); matched = true; break; }
        }
        if (!matched) {
          st.pendingOracles.push(o);
          if (st.pendingOracles.length > PENDING_ORACLE_MAX) st.pendingOracles.shift();
        }
        break;
      case 'session.captured':
        if (d.session) st.sessions[d.session] = d.clone || true;
        break;
      case 'session.released':
        if (d.session) delete st.sessions[d.session];
        break;
      case 'pool.state':
        st.pool = { free: d.l1_free, busy: d.l2_busy, size: d.size };
        break;
      case 'rule.active':
        st.rules[d.id] = d;
        inc = findIncidentForRule(st, d, ev.incident);
        if (inc) {
          inc.rule = { id: d.id, ts: ts, rule: d };
          inc.ruleExpired = null;
          inc.t.rule = ts;
          touch(inc);
        }
        break;
      case 'rule.expired':
        for (i = 0; i < st.order.length; i++) {
          inc = st.incidents[st.order[i]];
          if (inc.rule && inc.rule.id === d.id) { inc.ruleExpired = { ts: ts, reason: d.reason }; touch(inc); }
        }
        delete st.rules[d.id];
        break;
      case 'incident.opened':
        if (!id) break;
        inc = ensure(st, id, ts);
        inc.opened = ts; inc.t.opened = ts;
        inc.vuln_class = d.vuln_class; inc.route = d.route; inc.param = d.param; inc.sink = d.sink || null;
        inc.fuxa = d.fuxa || null;
        var keep = [];
        for (i = 0; i < st.pendingOracles.length; i++) {
          if (oracleMatchesSink(st.pendingOracles[i].data, inc.sink)) attachOracle(inc, st.pendingOracles[i]);
          else keep.push(st.pendingOracles[i]);
        }
        st.pendingOracles = keep;
        touch(inc);
        break;
      case 'poc.ready':
        if (!id) break;
        inc = ensure(st, id, ts); inc.poc = { ts: ts, reproducible: d.reproducible, runs: d.runs, poc: d.poc };
        inc.t.poc = ts; touch(inc);
        break;
      case 'patch.attempt':
        if (!id) break;
        inc = ensure(st, id, ts); a = attemptOf(inc, d.attempt, ts);
        a.source = d.source; a.ts = ts;
        if (inc.t.patchStart == null) inc.t.patchStart = ts;
        touch(inc);
        break;
      case 'patch.diff':
        if (!id) break;
        inc = ensure(st, id, ts); a = attemptOf(inc, d.attempt, ts);
        a.diff = typeof d.diff === 'string' ? d.diff : ''; a.diffTs = ts;
        if (inc.t.patchStart == null) inc.t.patchStart = ts;
        touch(inc);
        break;
      case 'gate.result':
        if (!id) break;
        inc = ensure(st, id, ts); a = attemptOf(inc, d.attempt, ts);
        if (GATES.indexOf(d.gate) >= 0) a.gates[d.gate] = { state: d.ok ? 'pass' : 'fail', detail: d.detail, ts: ts };
        a.status = attemptStatus(a);
        touch(inc);
        break;
      case 'pr.opened':
        if (!id) break;
        inc = ensure(st, id, ts); inc.pr = { ts: ts, url: d.url, branch: d.branch };
        inc.t.pr = ts; touch(inc);
        break;
      case 'pr.merged':
        if (!id) break;
        inc = ensure(st, id, ts); inc.merged = { ts: ts, url: d.url, sha: d.sha };
        inc.t.merged = ts; touch(inc);
        break;
      case 'deploy.started':
      case 'deploy.done':
        var target = id ? ensure(st, id, ts) : findDeployTarget(st, d.release);
        var dep = { ts: ts, release: d.release, started: ev.type === 'deploy.started' };
        if (ev.type === 'deploy.done') { dep.ok = d.ok; dep.rolled_back = d.rolled_back; dep.detail = d.detail; }
        st.deploys.push(dep);
        if (target) {
          if (ev.type === 'deploy.started') { if (!target.deploy) target.deploy = {}; target.deploy.startTs = ts; target.deploy.release = d.release; target.t.deployStart = ts; }
          else {
            target.deploy = target.deploy || {};
            target.deploy.doneTs = ts; target.deploy.release = d.release; target.deploy.ok = d.ok;
            target.deploy.rolled_back = d.rolled_back; target.deploy.detail = d.detail; target.t.deploy = ts;
          }
          touch(target);
        }
        break;
      case 'verify.result':
        if (!id) break;
        inc = ensure(st, id, ts); inc.verify = { ts: ts, blocked: !!d.exploit_blocked_on_prod };
        inc.t.verify = ts; touch(inc);
        break;
      case 'incident.closed':
        if (!id) break;
        inc = ensure(st, id, ts);
        inc.closed = { ts: ts, outcome: d.outcome, seconds_to_rule: d.seconds_to_rule, seconds_to_patch: d.seconds_to_patch };
        inc.t.closed = ts; touch(inc);
        break;
      case 'attack.attempt':
        var v = String(d.vuln);
        if (!st.attacks[v]) { st.attacks[v] = []; st.attackOrder.push(v); }
        st.attacks[v].push({ ts: ts, ok: !!d.ok, saw: !!d.saw_real_data });
        if (st.attacks[v].length > ATTACK_MAX) st.attacks[v].shift();
        break;
      case 'fuxa.status':
        st.fuxa = d;
        break;
      default:
        break;
    }
    return st;
  }

  function findDeployTarget(st, release) {
    var cand = null;
    for (var i = 0; i < st.order.length; i++) {
      var c = st.incidents[st.order[i]];
      if (!c.merged || (c.deploy && c.deploy.doneTs)) continue;
      if (release && c.merged.sha && (String(release).indexOf(c.merged.sha) === 0 || c.merged.sha.indexOf(String(release)) === 0)) return c;
      if (!cand) cand = c;
    }
    return cand;
  }

  function pushTicker(st, rid, entry) {
    entry.rid = rid;
    st.ticker.unshift(entry);
    if (rid) st.tickerByRid[rid] = entry;
    while (st.ticker.length > TICKER_MAX) {
      var old = st.ticker.pop();
      if (old.rid && st.tickerByRid[old.rid] === old) delete st.tickerByRid[old.rid];
    }
    return entry;
  }

  /* open | contained | cured */
  function status(inc) {
    var outcome = inc.closed && inc.closed.outcome;
    if (outcome === 'patched' || (inc.verify && inc.verify.blocked) ||
        (inc.merged && inc.deploy && inc.deploy.doneTs && inc.deploy.ok)) return 'cured';
    if (inc.rule && !inc.ruleExpired) return 'contained';
    return 'open';
  }

  function t0(inc) {
    var c = [inc.t.oracle, inc.t.opened, inc.t.seen].filter(function (x) { return typeof x === 'number' && x > 0; });
    return c.length ? Math.min.apply(null, c) : null;
  }

  function timeToRule(inc) {
    if (inc.closed && typeof inc.closed.seconds_to_rule === 'number') return inc.closed.seconds_to_rule;
    var b = t0(inc);
    return b != null && inc.t.rule ? Math.max(0, inc.t.rule - b) : null;
  }

  function timeToPatch(inc) {
    if (inc.closed && typeof inc.closed.seconds_to_patch === 'number') return inc.closed.seconds_to_patch;
    var end = inc.t.deploy || inc.t.merged;
    var b = t0(inc);
    return b != null && end ? Math.max(0, end - b) : null;
  }

  /* ordered milestones with seconds since the previous one */
  function milestones(inc) {
    var defs = [
      ['oracle', 'Ataque detectado'], ['rule', 'Regla activa'], ['patchStart', 'Parche propuesto'],
      ['pr', 'PR abierto'], ['merged', 'PR fusionado'], ['deploy', 'Deploy'], ['verify', 'Verificado']
    ];
    var out = [], prev = null;
    for (var i = 0; i < defs.length; i++) {
      var ts = defs[i][0] === 'oracle' ? (inc.t.oracle != null ? inc.t.oracle : inc.t.opened) : inc.t[defs[i][0]];
      if (typeof ts !== 'number' || ts <= 0) continue;
      out.push({ key: defs[i][0], label: defs[i][1], ts: ts, delta: prev == null ? 0 : Math.max(0, ts - prev) });
      prev = ts;
    }
    return out;
  }

  function scoreboard(st) {
    var s = { seen: 0, open: 0, contained: 0, cured: 0 };
    for (var i = 0; i < st.order.length; i++) {
      var inc = st.incidents[st.order[i]];
      if (!inc.opened && !inc.oracles.length) continue;
      s.seen++; s[status(inc)]++;
    }
    s.prod = st.counters.prod; s.detonated = st.counters.detonated; s.deny = st.counters.deny; s.total = st.counters.total;
    s.captive = Object.keys(st.sessions).length;
    s.free = st.pool ? st.pool.free : null; s.busy = st.pool ? st.pool.busy : null; s.size = st.pool ? st.pool.size : null;
    return s;
  }

  /* blocked | exec (ok but no real data) | leak (saw real data) */
  function attackKind(x) { return x.saw ? 'leak' : (x.ok ? 'exec' : 'blocked'); }

  function decodeB64(b64) {
    if (!b64) return '';
    try {
      var bin = (typeof atob === 'function') ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch (e) { return '(no decodificable)'; }
  }

  function isGithubUrl(u) { return typeof u === 'string' && u.indexOf('https://github.com/') === 0; }

  var api = {
    GATES: GATES, newState: newState, reduce: reduce, status: status, scoreboard: scoreboard,
    milestones: milestones, timeToRule: timeToRule, timeToPatch: timeToPatch, t0: t0,
    attackKind: attackKind, decodeB64: decodeB64, isGithubUrl: isGithubUrl, attemptStatus: attemptStatus
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ImmuneState = api;
})(typeof window !== 'undefined' ? window : this);
