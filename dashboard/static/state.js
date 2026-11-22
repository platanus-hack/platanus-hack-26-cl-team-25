/* Pure state reduction: events -> dashboard state. No DOM. Works in browser (window.ImmuneState) and node.
   Timings follow immune/metrics.py: everything is measured from incident.opened (start of work); the time
   between "identified" (oracle.fired with rid == evidence_rid, or audit.finding) and incident.opened is queue. */
(function (root) {
  'use strict';

  var GATES = ['policy', 'properties', 'poc', 'tests', 'legit'];
  var TICKER_MAX = 60;
  var PENDING_ORACLE_MAX = 200;
  var ATTACK_MAX = 400;
  var ATTACK_KINDS_MAX = 40;
  var ORACLES_KEPT = 5;        // per incident; `hits` keeps counting
  var SWITCHES_MAX = 12;
  var AUDITS_MAX = 200;
  var INCIDENTS_MAX = 300;     // kept in memory; older closed ones are folded into st.archive (counts and times only)
  var ARCHIVE_TIMES_MAX = 2000;
  var PENDING_SHOWN_S = 900;
  var PENDING_CARDS_MAX = 8;
  var ID_MAX = 120;
  var BODY_B64_MAX = 8000;

  function dict() { return Object.create(null); }   // event ids are data: never index a plain {} with them

  function newState() {
    return {
      incidents: dict(), order: [], pendingOracles: [], rules: dict(),
      audits: dict(), auditOrder: [],
      attacks: dict(), attackOrder: [],
      prodAlerts: [],
      ticker: [], tickerByRid: dict(),
      counters: { prod: 0, detonated: 0, deny: 0, total: 0 },
      sessions: dict(), pool: null, fuxa: null,
      upstream: null, switches: [], deploy: null, lastOpened: null,
      archive: { seen: 0, open: 0, contained: 0, cured: 0, dismissed: 0, audit: 0, prod: [] },
      lastSeq: 0, lastTs: 0, events: 0, ignored: 0
    };
  }

  function isObj(x) { return !!x && typeof x === 'object' && !Array.isArray(x); }
  // deploy.done data.canary -> the few numbers the page shows (a share of real traffic tried the release first)
  function canaryOf(c) {
    if (!c || typeof c !== 'object' || ['ok', 'worse', 'skipped'].indexOf(c.verdict) < 0) return null;
    var can = c.canary && typeof c.canary === 'object' ? c.canary : {};
    var stable = c.stable && typeof c.stable === 'object' ? c.stable : {};
    return { verdict: c.verdict, weight: num(c.weight), seconds: num(c.seconds),
      requests: num(can.requests) || 0, e5: num(can['5xx']) || 0, e4: num(can['4xx']) || 0,
      stableRequests: num(stable.requests) || 0, stableE5: num(stable['5xx']) || 0, stableE4: num(stable['4xx']) || 0 };
  }

  function num(x) { return typeof x === 'number' && isFinite(x) ? x : null; }
  function str(x) { return typeof x === 'string' ? x : (typeof x === 'number' && isFinite(x) ? String(x) : null); }
  /* a usable id (incident, rule, session, rid): short string or number, else null */
  function sid(x) { var s = str(x); return s ? s.slice(0, ID_MAX) : null; }
  function text(x) {
    if (x == null) return null;
    if (typeof x === 'string') return x;
    try { return JSON.stringify(x); } catch (e) { return String(x); }
  }
  function sinkOf(x) { return isObj(x) && typeof x.file === 'string' ? { file: x.file, line: x.line } : null; }
  function paramOf(x) { return isObj(x) && str(x.name) != null ? { 'in': str(x['in']), name: str(x.name) } : null; }

  function ensure(st, id, ts) {
    var inc = st.incidents[id];
    if (!inc) {
      inc = st.incidents[id] = {
        id: id, rev: 0, opened: null, vuln_class: null, method: null, route: null, param: null, sink: null,
        evidence_rid: null, oracles: [], hits: 0, rule: null, ruleExpired: null, poc: null, origin: 'live', parent: null,
        request: null, attempts: [], pr: null, merged: null, deploy: null, prod: null, verify: null, closed: null, t: {}
      };
      st.order.push(id);
      inc.t.seen = ts;
    }
    return inc;
  }

  function attemptOf(inc, n, ts) {
    var a = null, i;
    n = num(n) == null ? 1 : n;
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
    if (typeof a !== 'string' || typeof b !== 'string' || !a || !b) return false;
    return a === b || a.endsWith('/' + b) || b.endsWith('/' + a);
  }

  function oracleMatchesSink(data, sink) {
    if (!sink || !data || !Array.isArray(data.events)) return false;
    for (var i = 0; i < data.events.length; i++) {
      var stack = (data.events[i] && data.events[i].stack) || [];
      if (!Array.isArray(stack)) continue;
      for (var j = 0; j < stack.length; j++) {
        if (stack[j] && sameFile(stack[j].file, sink.file) && stack[j].line === sink.line) return true;
      }
    }
    return false;
  }

  /* '/api/orders/{order_id}' matches '/api/orders/5' */
  function routeMatches(route, path) {
    if (typeof route !== 'string' || typeof path !== 'string') return false;
    var a = route.split('/'), b = path.split('?')[0].split('/');
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] === b[i]) continue;
      if (a[i].charAt(0) === '{' && a[i].charAt(a[i].length - 1) === '}' && b[i] !== '') continue;
      return false;
    }
    return true;
  }

  /* 2: this is the evidence that opened the incident (rid == evidence_rid); 1: another hit on the same
     defect (same route and sink); 0: unrelated. Several incidents share a sink (the db helper), so the
     sink alone only decides when the route is unknown. */
  function oracleScore(inc, o) {
    if (inc.evidence_rid && o.rid && o.rid === inc.evidence_rid) return 2;
    var rq = (o.data && o.data.request) || {};
    if (inc.route && typeof rq.path === 'string') {
      if (!routeMatches(inc.route, rq.path)) return 0;
      if (inc.method && typeof rq.method === 'string' && inc.method !== rq.method) return 0;
    }
    return oracleMatchesSink(o.data, inc.sink) ? 1 : 0;
  }

  /* keep only what the page shows: an evidence object can carry a database snapshot */
  function slimEvidence(d) {
    var rq = isObj(d.request) ? d.request : {};
    var evs = Array.isArray(d.events) ? d.events.slice(0, 3) : [];
    var b64 = typeof rq.body_b64 === 'string' ? rq.body_b64 : '';
    return {
      clone: str(d.clone), mode: str(d.mode), status: d.status == null ? null : str(d.status), verdict: str(d.verdict),
      uid: d.uid == null ? null : str(d.uid), role: str(d.role),
      request: { method: str(rq.method), path: str(rq.path), query: str(rq.query) || '',
                 body_b64: b64.length > BODY_B64_MAX ? b64.slice(0, BODY_B64_MAX) : b64 },
      events: evs.map(function (e) {
        e = isObj(e) ? e : {};
        var stack = Array.isArray(e.stack) ? e.stack.slice(0, 8).filter(isObj) : [];
        return { oracle: str(e.oracle), detail: e.detail == null ? null : e.detail,
                 stack: stack.map(function (f) { return { file: str(f.file), line: f.line, func: str(f.func) }; }) };
      })
    };
  }

  function attachOracle(inc, o, score) {
    inc.hits++;
    if (score === 2) {
      inc.oracles.unshift(o);
      if (inc.t.identified == null || o.ts < inc.t.identified) inc.t.identified = o.ts;
    } else {
      inc.oracles.push(o);
    }
    if (inc.oracles.length > ORACLES_KEPT) inc.oracles.length = ORACLES_KEPT;
    if (inc.t.oracle == null || o.ts < inc.t.oracle) inc.t.oracle = o.ts;
  }

  function touch(inc) { inc.rev++; }

  function findIncidentForRule(st, rule, evIncident, ts) {
    var id = sid(evIncident) || sid(rule.incident);
    if (id) return ensure(st, id, ts);
    for (var i = 0; i < st.order.length; i++) {
      var c = st.incidents[st.order[i]];
      if (!c.rule && c.route && c.route === rule.route) return c;
    }
    return null;
  }

  function shaMatches(sha, release) {
    sha = str(sha); release = str(release);
    return !!sha && !!release && (release.indexOf(sha) === 0 || sha.indexOf(release) === 0);
  }

  /* deploy.* and upstream.switched carry no incident: the merged incident whose sha prefixes the release,
     else the oldest merged one still waiting for `field` (the pipeline handles one incident at a time). */
  function findReleaseTarget(st, release, waiting) {
    var cand = null;
    for (var i = 0; i < st.order.length; i++) {
      var c = st.incidents[st.order[i]];
      if (!c.merged || !waiting(c)) continue;
      if (shaMatches(c.merged.sha, release)) return c;
      if (!cand) cand = c;
    }
    return cand;
  }

  function reduce(st, ev, seq) {
    if (!isObj(ev)) { st.ignored++; return st; }
    var d = isObj(ev.data) ? ev.data : {};
    var ts = num(ev.ts) || 0;
    var rid = sid(ev.rid);
    var inc, a, i, id, au, target, o, sc;
    st.events++;
    if (typeof seq === 'number') st.lastSeq = seq;
    if (ts > st.lastTs) st.lastTs = ts;
    id = sid(ev.incident) || sid(d.incident);

    switch (ev.type) {
      case 'request.classified':
        pushTicker(st, rid, { ts: ts, method: str(d.method), path: str(d.path), cls: str(d['class']),
          reasons: Array.isArray(d.reasons) ? d.reasons.slice(0, 6).map(String) : [], route: null, status: null, verdict: null, ms: null });
        break;
      case 'request.routed':
        st.counters.total++;
        /* metrics.py: detonated = the request ran in a shadow clone (verdict clean | oracle | inconclusive) */
        if (d.verdict === 'clean' || d.verdict === 'oracle' || d.verdict === 'inconclusive' ||
            (typeof d.route === 'string' && d.route.indexOf('shadow') === 0)) st.counters.detonated++;
        if (d.route === 'prod') st.counters.prod++;
        else if (d.route === 'deny') st.counters.deny++;
        var te = rid && st.tickerByRid[rid];
        if (!te) te = pushTicker(st, rid, { ts: ts, method: null, path: null, cls: null, reasons: [] });
        te.route = str(d.route); te.status = d.status == null ? null : str(d.status); te.ms = num(d.ms); te.verdict = str(d.verdict);
        break;
      case 'oracle.fired':
        o = { ts: ts, rid: rid || sid(d.rid), data: slimEvidence(d), req: null };
        o.req = (o.rid && st.tickerByRid[o.rid]) || null;   // classification + routing of the same request
        if (id) { inc = ensure(st, id, ts); attachOracle(inc, o, inc.evidence_rid && o.rid === inc.evidence_rid ? 2 : 1); touch(inc); break; }
        var best = null, bestScore = 0;
        for (i = 0; i < st.order.length; i++) {
          inc = st.incidents[st.order[i]];
          sc = oracleScore(inc, o);
          if (sc > bestScore || (sc === bestScore && sc > 0 && best.closed && !inc.closed)) { best = inc; bestScore = sc; }
        }
        if (best) { attachOracle(best, o, bestScore); touch(best); }
        else {
          st.pendingOracles.push(o);
          if (st.pendingOracles.length > PENDING_ORACLE_MAX) st.pendingOracles.shift();
        }
        break;
      case 'session.captured':
        if (sid(d.session)) st.sessions[sid(d.session)] = true;
        break;
      case 'session.released':
        if (sid(d.session)) delete st.sessions[sid(d.session)];
        break;
      case 'canary.started':
        st.canary = { ts: ts, release: str(d.release), weight: num(d.weight) };
        break;
      case 'canary.done':
        st.canary = null;
        break;
      case 'pool.state':
        st.pool = { free: num(d.l1_free), busy: num(d.l2_busy), size: num(d.size) };
        break;
      case 'upstream.switched':
        st.upstream = { ts: ts, release: str(d.release), addr: str(d.addr) };
        st.switches.push(st.upstream);
        if (st.switches.length > SWITCHES_MAX) st.switches.shift();
        target = id ? ensure(st, id, ts) : findReleaseTarget(st, d.release, function (c) { return !c.prod; });
        /* metrics.py: in_prod = first upstream.switched after pr.merged */
        if (target && target.merged && !target.prod) {
          target.prod = { ts: ts, release: str(d.release), addr: str(d.addr) };
          target.t.inProd = ts; touch(target);
        }
        break;
      case 'rule.active':
        if (sid(d.id)) st.rules[sid(d.id)] = true;
        inc = findIncidentForRule(st, d, ev.incident, ts);
        if (inc) {
          inc.rule = { id: sid(d.id), ts: ts, method: str(d.method), route: str(d.route), scope: str(d.scope),
                       ttl_s: num(d.ttl_s), grammar: str(d.grammar), param: paramOf(d.param) };
          inc.ruleExpired = null;
          if (inc.t.rule == null) inc.t.rule = ts;       // metrics.py keeps the first one
          touch(inc);
        }
        break;
      case 'rule.expired':
        if (!sid(d.id)) break;
        for (i = 0; i < st.order.length; i++) {
          inc = st.incidents[st.order[i]];
          if (inc.rule && inc.rule.id === sid(d.id)) { inc.ruleExpired = { ts: ts, reason: str(d.reason) }; touch(inc); }
        }
        delete st.rules[sid(d.id)];
        break;
      case 'incident.opened':
        if (!id) break;
        inc = ensure(st, id, ts);
        if (inc.opened) {
          /* opened again = a restart or a retry after a transient failure: like metrics.py, the last run is the
             one shown and timed. Detection (oracles, t.identified, t.found) belongs to the incident, not the run. */
          inc.runs = (inc.runs || 1) + 1;
          inc.attempts = []; inc.poc = null; inc.pr = null; inc.merged = null; inc.deploy = null; inc.prod = null;
          inc.verify = null; inc.closed = null; inc.rule = null; inc.ruleExpired = null;
          inc.t = { seen: inc.t.seen, identified: inc.t.identified, oracle: inc.t.oracle, found: inc.t.found };
        }
        inc.opened = ts; inc.t.opened = ts;
        st.lastOpened = id;
        inc.vuln_class = str(d.vuln_class); inc.route = str(d.route); inc.param = paramOf(d.param); inc.sink = sinkOf(d.sink);
        inc.method = str(d.method);
        inc.evidence_rid = sid(d.evidence_rid);
        inc.fuxa = isObj(d.fuxa) ? { synthetic: !!d.fuxa.synthetic, timed: !!d.fuxa.timed } : null;
        if (isObj(d.request)) inc.request = slimEvidence({ request: d.request }).request;
        if (d.origin === 'audit') { inc.origin = 'audit'; inc.parent = sid(d.parent) || inc.parent; }
        var keep = [];
        for (i = 0; i < st.pendingOracles.length; i++) {
          sc = oracleScore(inc, st.pendingOracles[i]);
          if (sc) attachOracle(inc, st.pendingOracles[i], sc);
          else keep.push(st.pendingOracles[i]);
        }
        st.pendingOracles = keep;
        touch(inc);
        break;
      case 'poc.ready':
        if (!id) break;
        inc = ensure(st, id, ts); inc.poc = { ts: ts, reproducible: !!d.reproducible, runs: num(d.runs) };
        inc.t.poc = ts; touch(inc);
        break;
      case 'patch.attempt':
        if (!id) break;
        inc = ensure(st, id, ts); a = attemptOf(inc, d.attempt, ts);
        a.source = str(d.source); a.ts = ts;
        if (inc.t.patchStart == null) inc.t.patchStart = ts;
        touch(inc);
        break;
      case 'patch.diff':
        if (!id) break;
        inc = ensure(st, id, ts); a = attemptOf(inc, d.attempt, ts);
        a.diff = typeof d.diff === 'string' ? d.diff : ''; a.diffTs = ts;
        if (inc.t.patchStart == null) inc.t.patchStart = ts;
        if (inc.t.diff == null) inc.t.diff = ts;
        touch(inc);
        break;
      case 'gate.result':
        if (!id) break;
        inc = ensure(st, id, ts); a = attemptOf(inc, d.attempt, ts);
        if (GATES.indexOf(d.gate) >= 0) a.gates[d.gate] = { state: d.ok ? 'pass' : 'fail', detail: text(d.detail), ts: ts };
        a.status = attemptStatus(a);
        touch(inc);
        break;
      case 'pr.opened':
        if (!id) break;
        inc = ensure(st, id, ts); inc.pr = { ts: ts, url: str(d.url), branch: str(d.branch) };
        inc.t.pr = ts; touch(inc);
        break;
      case 'pr.merged':
        if (!id) break;
        inc = ensure(st, id, ts); inc.merged = { ts: ts, url: str(d.url), sha: str(d.sha) };
        inc.t.merged = ts; touch(inc);
        break;
      case 'deploy.started':
      case 'deploy.done':
        var done = ev.type === 'deploy.done';
        st.deploy = { ts: ts, release: str(d.release), done: done, ok: done ? !!d.ok : null, rolled_back: done ? !!d.rolled_back : false };
        target = id ? ensure(st, id, ts) : findReleaseTarget(st, d.release, function (c) { return !(c.deploy && c.deploy.doneTs); });
        if (target) {
          target.deploy = target.deploy || {};
          target.deploy.release = str(d.release);
          if (!done) { target.deploy.startTs = ts; target.t.deployStart = ts; }
          else {
            target.deploy.doneTs = ts; target.deploy.ok = !!d.ok;
            target.deploy.rolled_back = !!d.rolled_back; target.deploy.detail = text(d.detail); target.t.deploy = ts;
            target.deploy.canary = canaryOf(d.canary);
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
        inc.closed = { ts: ts, outcome: str(d.outcome) };
        inc.t.closed = ts; touch(inc);
        break;
      case 'audit.started':
        if (!id) break;
        au = auditOf(st, id, ts);
        au.vuln_class = str(d.vuln_class) || au.vuln_class; au.candidates = num(d.candidates);
        au.started = ts;
        break;
      case 'audit.finding':
        if (!id) break;
        inc = ensure(st, id, ts);
        inc.origin = 'audit';
        if (sid(d.parent)) inc.parent = sid(d.parent);
        if (!inc.route && str(d.route)) inc.route = str(d.route);
        if (!inc.param && paramOf(d.param)) inc.param = paramOf(d.param);
        if (inc.t.found == null) inc.t.found = ts;
        if (inc.parent) {
          au = auditOf(st, inc.parent, ts);
          if (au.found.indexOf(id) < 0 && au.found.length < 100) au.found.push(id);
        }
        touch(inc);
        break;
      case 'audit.done':
        if (!id) break;
        au = auditOf(st, id, ts);
        au.done = { ts: ts, checked: num(d.checked), findings: num(d.findings), seconds: num(d.seconds) };
        break;
      case 'attack.attempt':
        var v = (str(d.vuln) || '?').slice(0, ID_MAX);
        if (!st.attacks[v]) {
          if (st.attackOrder.length >= ATTACK_KINDS_MAX) break;
          st.attacks[v] = []; st.attackOrder.push(v);
        }
        st.attacks[v].push({ ts: ts, ok: !!d.ok, saw: !!d.saw_real_data });
        if (st.attacks[v].length > ATTACK_MAX) st.attacks[v].shift();
        break;
      case 'prod.alert':   // oracles on production, alert only (sidecar/marker/prodwatch.py); no panel yet
        st.prodAlerts.push({ ts: ts, container: str(d.container), oracle: str(d.oracle), note: str(d.note),
                             candidates: num(d.candidates), confirmed: Array.isArray(d.confirmed) ? d.confirmed.length : 0 });
        if (st.prodAlerts.length > 50) st.prodAlerts.shift();
        break;
      case 'fuxa.status':
        st.fuxa = d;
        break;
      default:
        st.ignored++;
        break;
    }
    if (st.order.length > INCIDENTS_MAX) archiveOne(st);
    return st;
  }

  /* drop one incident from memory: a leftover that was never shown, else the oldest closed one (its outcome
     and its time to production stay in the totals) */
  function archiveOne(st) {
    var i, inc, at = -1;
    for (i = 0; i < st.order.length && at < 0; i++) if (!visible(st.incidents[st.order[i]])) at = i;
    for (i = 0; i < st.order.length && at < 0; i++) if (st.incidents[st.order[i]].closed) at = i;
    if (at < 0) return;
    inc = st.incidents[st.order[at]];
    if (visible(inc)) {
      var a = st.archive;
      a.seen++; a[status(inc)]++;
      if (inc.origin === 'audit') a.audit++;
      if (inc.closed && inc.closed.outcome === 'patched' && timeToProd(inc) != null) {
        a.prod.push(timeToProd(inc));
        if (a.prod.length > ARCHIVE_TIMES_MAX) a.prod.shift();
      }
    }
    delete st.incidents[st.order[at]];
    st.order.splice(at, 1);
  }

  function auditOf(st, id, ts) {
    var au = st.audits[id];
    if (!au) {
      au = st.audits[id] = { incident: id, vuln_class: null, candidates: null, started: ts, done: null, found: [] };
      st.auditOrder.push(id);
      if (st.auditOrder.length > AUDITS_MAX) delete st.audits[st.auditOrder.shift()];
    }
    return au;
  }

  function plural(n, w) { return n + ' ' + w + (n === 1 ? '' : 's'); }

  /* one line about one class self-audit */
  function auditText(au) {
    var head = 'Auditoría de clase ' + (au.vuln_class || '?') + ' tras ' + au.incident + ': ';
    var n = au.candidates == null ? '?' : au.candidates;
    if (!au.done) return head + n + ' candidatos, en curso' + (au.found.length ? ' (' + plural(au.found.length, 'hallazgo') + ')' : '') + '...';
    var f = au.done.findings != null ? au.done.findings : au.found.length;
    return head + (au.done.checked == null ? '?' : au.done.checked) + ' de ' + n + ' candidatos revisados, ' + plural(f, 'hallazgo') +
      (au.done.seconds != null ? ' en ' + au.done.seconds.toFixed(1) + ' s' : '');
  }

  /* the most recent class self-audit, or null */
  function auditLine(st) {
    if (!st.auditOrder.length) return null;
    return auditText(st.audits[st.auditOrder[st.auditOrder.length - 1]]);
  }

  function visible(inc) { return !!(inc.opened || inc.oracles.length || inc.origin === 'audit'); }

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

  /* open | contained | cured | dismissed (closed as not reproducible) */
  function status(inc) {
    var outcome = inc.closed && inc.closed.outcome;
    if (outcome === 'patched' || (inc.verify && inc.verify.blocked) ||
        (!inc.verify && inc.merged && inc.deploy && inc.deploy.doneTs && inc.deploy.ok)) return 'cured';
    if (outcome === 'not_reproducible') return 'dismissed';
    if (inc.rule && !inc.ruleExpired) return 'contained';
    return 'open';
  }

  /* what is happening to this incident right now (null once closed) */
  function phase(inc) {
    if (inc.closed) return null;
    if (!inc.opened) return 'en cola';
    if (inc.verify) return 'cerrando';
    if (inc.prod) return 'verificando en producción';
    if (inc.deploy && inc.deploy.doneTs && !inc.deploy.ok) return inc.deploy.rolled_back ? 'deploy revertido' : 'deploy fallido';
    if (inc.merged) return 'desplegando (blue/green)';
    var a = inc.attempts.length ? inc.attempts[inc.attempts.length - 1] : null;
    /* the pipeline opens the PR after the policy gate and merges it once the other four pass */
    if (inc.pr && (!a || a.status === 'accepted')) return 'fusionando PR';
    if (a) {
      if (a.status === 'accepted') return 'abriendo PR';
      if (a.status === 'rejected') return 'parche #' + a.attempt + ' rechazado, reintentando';
      var n = 0;
      for (var i = 0; i < GATES.length; i++) if (a.gates[GATES[i]].state === 'pass') n++;
      return a.diff == null ? 'generando parche #' + a.attempt : 'validando parche #' + a.attempt + ' (' + n + '/' + GATES.length + ' gates)';
    }
    if (inc.poc && !inc.poc.reproducible) return 'no reproducible';
    if (inc.poc) return inc.rule ? 'generando parche' : 'activando regla';
    return 'reproduciendo (PoC)';
  }

  /* identified: the shadow copy confirmed the defect (metrics.py t0) */
  function t0(inc) {
    var t = inc.t;
    if (inc.origin === 'audit') return pos(t.found) || pos(t.opened) || pos(t.seen);
    if (pos(t.identified)) return t.identified;
    if (pos(t.opened)) return (!inc.evidence_rid && pos(t.oracle) && t.oracle < t.opened) ? t.oracle : t.opened;
    return pos(t.oracle) || pos(t.seen);
  }
  function pos(x) { return typeof x === 'number' && x > 0 ? x : null; }
  function since(inc, ts) { return pos(inc.t.opened) && pos(ts) ? Math.max(0, ts - inc.t.opened) : null; }

  function queueTime(inc) { var b = t0(inc); return pos(inc.t.opened) && b ? Math.max(0, inc.t.opened - b) : null; }
  function timeToRule(inc) { return since(inc, inc.t.rule); }
  function timeToDiff(inc) { return since(inc, inc.t.diff); }
  function timeToMerged(inc) { return since(inc, inc.t.merged); }
  /* THE metric: incident.opened -> production traffic served by the fixed release */
  function timeToProd(inc) {
    if (inc.fuxa) return inc.fuxa.timed && inc.deploy && inc.deploy.ok ? since(inc, inc.deploy.doneTs) : null;
    return since(inc, inc.t.inProd);
  }
  function timeToVerified(inc) { return since(inc, inc.t.verify); }

  /* the whole life of an incident, in pipeline order. state: done | active | pending | fail | skip.
     dt = seconds since incident.opened (null for the detection itself) */
  function stages(inc) {
    var out = [], t = inc.t, a = inc.attempts.length ? inc.attempts[inc.attempts.length - 1] : null, i;
    function push(key, label, ts, state, note) {
      out.push({ key: key, label: label, ts: pos(ts), dt: key === 'detect' ? null : since(inc, ts), state: state || (pos(ts) ? 'done' : 'pending'), note: note || null });
    }
    if (inc.fuxa) {
      var deploy = inc.deploy;
      push('detect', inc.fuxa.synthetic ? 'Evidencia simulada' : 'Violación observada', t0(inc));
      push('patch', 'Parche local', t.diff || t.patchStart);
      if (deploy) push('deploy', deploy.rolled_back ? 'Reversión' : 'Redespliegue', deploy.doneTs || deploy.startTs,
        deploy.doneTs ? (deploy.ok || deploy.rolled_back ? 'done' : 'fail') : 'active');
      if (!inc.fuxa.timed) out.forEach(function (stage) { stage.dt = null; });
      return out;
    }
    var q = queueTime(inc);
    push('detect', inc.origin === 'audit' ? 'Hallado por auditoría' : 'Oráculo disparó', t0(inc), t0(inc) ? 'done' : 'pending');
    push('opened', 'Incidente abierto', t.opened, null, q != null && q >= 1 ? 'cola ' + q.toFixed(1).replace('.', ',') + ' s' : null);
    push('poc', 'PoC', t.poc, inc.poc ? (inc.poc.reproducible ? 'done' : 'fail') : null, inc.poc && !inc.poc.reproducible ? 'no reproducible' : null);
    push('rule', 'Regla activa', t.rule);
    push('patch', 'Parche', t.diff || t.patchStart, a ? (a.diff != null ? 'done' : 'active') : null, a && a.attempt > 1 ? 'intento ' + a.attempt : null);
    for (i = 0; i < GATES.length; i++) {
      var g = a ? a.gates[GATES[i]] : null;
      push('gate:' + GATES[i], GATES[i], g && g.ts, g ? (g.state === 'pass' ? 'done' : g.state === 'fail' ? 'fail' : 'pending') : 'pending');
    }
    push('pr', 'PR', t.pr);
    push('merged', 'Merge', t.merged);
    var dep = inc.deploy;
    var depFail = dep && dep.doneTs && !dep.ok;
    push('prod', 'En producción', t.inProd, depFail ? 'fail' : (inc.prod ? 'done' : (dep ? 'active' : 'pending')),
      depFail ? (dep.rolled_back ? 'rollback' : 'deploy fallido') : (inc.prod && inc.prod.addr ? inc.prod.addr : null));
    push('verify', 'Verificado', t.verify, inc.verify ? (inc.verify.blocked ? 'done' : 'fail') : null, inc.verify && !inc.verify.blocked ? 'exploit sigue activo' : null);
    push('closed', 'Cerrado', t.closed, null, inc.closed && inc.closed.outcome !== 'patched' ? inc.closed.outcome : null);
    if (inc.closed) {
      for (i = 0; i < out.length; i++) if (out[i].state === 'pending' || out[i].state === 'active') out[i].state = 'skip';
    } else if (inc.opened) {
      /* in progress: a gate still missing while the PR is not merged (the pipeline opens the PR after the
         policy gate), else the first step missing after the last one that happened */
      var last = -1, act = -1;
      for (i = 0; i < out.length; i++) {
        if (out[i].state === 'active') { act = i; break; }
        if (out[i].state === 'done' || out[i].state === 'fail') last = i;
      }
      if (act < 0 && a && a.status !== 'rejected' && !inc.merged) {
        for (i = 0; i < out.length; i++) if (out[i].key.indexOf('gate:') === 0 && out[i].state === 'pending') { act = i; break; }
      }
      if (act < 0) for (i = last + 1; i < out.length; i++) if (out[i].state === 'pending') { act = i; break; }
      if (act >= 0) out[act].state = 'active';
    }
    return out;
  }

  function median(v) {
    if (!v.length) return null;
    v = v.slice().sort(function (x, y) { return x - y; });
    var m = v.length >> 1;
    return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
  }

  /* like `python -m immune.metrics`: only incidents closed as patched and serving production count */
  function prodTimes(st) {
    var v = st.archive.prod.slice();
    for (var i = 0; i < st.order.length; i++) {
      var inc = st.incidents[st.order[i]];
      if (inc.closed && inc.closed.outcome === 'patched' && timeToProd(inc) != null) v.push(timeToProd(inc));
    }
    return v;
  }

  /* attacks an oracle already confirmed whose incident is not open yet (the pipeline takes one incident at a
     time, so they can wait a minute or two): one entry per request line, oldest first. Evidence that never
     becomes an incident stops being shown after PENDING_SHOWN_S of event time. */
  function pendingAttacks(st) {
    var seen = dict(), out = [];
    for (var i = 0; i < st.pendingOracles.length; i++) {
      var o = st.pendingOracles[i], rq = o.data.request;
      if (st.lastTs - o.ts > PENDING_SHOWN_S) continue;
      var key = (rq.method || '?') + ' ' + (rq.path || '?');
      if (seen[key]) { seen[key].hits++; continue; }
      seen[key] = { id: 'pending:' + (o.rid || key), key: key, o: o, hits: 1 };
      out.push(seen[key]);
    }
    return out.slice(0, PENDING_CARDS_MAX);
  }

  function scoreboard(st) {
    var ar = st.archive;
    var s = { seen: ar.seen, open: ar.open, contained: ar.contained, cured: ar.cured, dismissed: ar.dismissed, audit: ar.audit };
    s.pending = pendingAttacks(st).length; s.seen += s.pending; s.open += s.pending;
    for (var i = 0; i < st.order.length; i++) {
      var inc = st.incidents[st.order[i]];
      if (!visible(inc)) continue;
      s.seen++; s[status(inc)]++;
      if (inc.origin === 'audit') s.audit++;
    }
    var pt = prodTimes(st);
    s.prodMedian = median(pt); s.prodN = pt.length;
    /* time to the gateway rule, over the incidents in memory that got one */
    var rt = [];
    for (i = 0; i < st.order.length; i++) if (timeToRule(st.incidents[st.order[i]]) != null) rt.push(timeToRule(st.incidents[st.order[i]]));
    s.ruleMedian = median(rt); s.ruleN = rt.length;
    s.prod = st.counters.prod; s.detonated = st.counters.detonated; s.deny = st.counters.deny; s.total = st.counters.total;
    s.captive = Object.keys(st.sessions).length;
    s.free = st.pool ? st.pool.free : null; s.busy = st.pool ? st.pool.busy : null; s.size = st.pool ? st.pool.size : null;
    return s;
  }

  /* display order: in progress, then queued, then closed (most recently closed first) */
  function displayOrder(st) {
    var live = [], queued = [], closed = [];
    for (var i = 0; i < st.order.length; i++) {
      var inc = st.incidents[st.order[i]];
      if (!visible(inc)) continue;
      if (inc.closed) closed.push(inc); else if (inc.opened) live.push(inc); else queued.push(inc);
    }
    live.sort(function (x, y) { return x.opened - y.opened; });
    closed.sort(function (x, y) { return y.closed.ts - x.closed.ts; });
    return live.concat(pendingAttacks(st), queued, closed).map(function (x) { return x.id; });
  }

  /* blocked | exec (ok but no real data) | leak (saw real data) */
  function attackKind(x) { return x.saw ? 'leak' : (x.ok ? 'exec' : 'blocked'); }

  function decodeB64(b64) {
    if (!b64 || typeof b64 !== 'string') return '';
    try {
      var bin = (typeof atob === 'function') ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch (e) { return '(no decodificable)'; }
  }

  /* the only urls the page turns into links: plain github.com paths (no query, no credentials, no odd characters) */
  function isGithubUrl(u) { return typeof u === 'string' && u.length < 300 && /^https:\/\/github\.com\/[A-Za-z0-9_.\/-]+(#[A-Za-z0-9_-]+)?$/.test(u); }

  /* what to print for a PR reference: github links as they are, a local PR file as "PR local #20"
     (the url of a local PR is a path on the host and is not shown) */
  function prLabel(u) {
    if (typeof u !== 'string' || !u) return '';
    if (isGithubUrl(u)) return u;
    var m = /#pr-(\d+)$/.exec(u) || /\/(\d+)\.json$/.exec(u);
    return m ? 'PR local #' + m[1] : 'PR local';
  }

  var api = {
    GATES: GATES, newState: newState, reduce: reduce, status: status, phase: phase, scoreboard: scoreboard,
    stages: stages, t0: t0, queueTime: queueTime, timeToRule: timeToRule, timeToDiff: timeToDiff, timeToMerged: timeToMerged,
    timeToProd: timeToProd, timeToVerified: timeToVerified, displayOrder: displayOrder, routeMatches: routeMatches,
    attackKind: attackKind, decodeB64: decodeB64, isGithubUrl: isGithubUrl, prLabel: prLabel, attemptStatus: attemptStatus,
    auditLine: auditLine, auditText: auditText, visible: visible, pendingAttacks: pendingAttacks
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ImmuneState = api;
})(typeof window !== 'undefined' ? window : this);
