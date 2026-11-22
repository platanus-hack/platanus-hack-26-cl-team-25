// Run: node dashboard/tests/reducer.test.js [events.json]            (events.json: list of bus events with seq)
//      node dashboard/tests/reducer.test.js --timings events.jsonl   (prints per-incident timings as JSON)
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const S = require(path.join(__dirname, '..', 'static', 'state.js'));

if (process.argv[2] === '--timings') {
  const evs = fs.readFileSync(process.argv[3], 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const d = S.newState();
  evs.forEach((e) => S.reduce(d, e, e.seq));
  const out = {};
  d.order.forEach((id) => {
    const i = d.incidents[id];
    out[id] = { status: S.status(i), origin: i.origin, parent: i.parent, hits: i.hits, queue: S.queueTime(i), to_rule: S.timeToRule(i), to_diff: S.timeToDiff(i),
                to_merged: S.timeToMerged(i), to_prod: S.timeToProd(i), to_verified: S.timeToVerified(i),
                evidence: i.oracles.length ? i.oracles[0].data.request.path : null, prod_addr: i.prod && i.prod.addr,
                steps: S.stages(i).map((s) => s.key + ':' + s.state) };
  });
  console.log(JSON.stringify({ incidents: out, score: S.scoreboard(d), upstream: d.upstream, audits: d.auditOrder.map((a) => S.auditText(d.audits[a])), ignored: d.ignored }));
  process.exit(0);
}

let t = 1000;
const mk = (type, data, o = {}) => Object.assign({ type, ts: (t += 1), run: 'r', src: 's', rid: null, incident: null, data }, o);
const b64 = (s) => Buffer.from(s).toString('base64');
const sink = { file: 'app/routes/files.py', line: 27 };
const phpFrame = { file: 'library/sql.inc.php', line: 99 };
const phpEvidence = [{ data: { events: [{ stack: [sink, phpFrame] }] } }];
assert.deepStrictEqual(S.phpLocation({ sink, oracles: phpEvidence }), phpFrame);
assert.deepStrictEqual(S.phpLocation({ sink: phpFrame, oracles: [] }), phpFrame);
assert.strictEqual(S.phpLocation({ sink, oracles: [] }), null);
const oracle = (rid, o = {}) => mk('oracle.fired', Object.assign({
  clone: 'c', rid, mode: 'L2', release: 'r0', verdict: 'oracle', status: 200,
  request: { method: 'GET', path: '/api/download', query: 'file=../x', headers: {}, body_b64: b64('<img src=x onerror=alert(1)>') },
  events: [{ oracle: 'file', detail: { path: '/etc/passwd' }, stack: [{ file: '/srv/app/routes/files.py', line: 27, func: 'download' }] }]
}, o), { rid });

// --- oracle arrives before incident.opened and is matched by route + sink when there is no evidence_rid
let st = S.newState();
S.reduce(st, mk('attack.attempt', { vuln: 'trav', ok: true, saw_real_data: true }));
S.reduce(st, oracle('r1'));
assert.strictEqual(st.pendingOracles.length, 1);
// a confirmed attack is on the page (and counted as open) before the pipeline opens its incident
{
  const p = S.pendingAttacks(st);
  assert.deepStrictEqual(p.map((x) => [x.id, x.key, x.hits]), [['pending:r1', 'GET /api/download', 1]]);
  const b = S.scoreboard(st); assert.deepStrictEqual([b.seen, b.open, b.pending], [1, 1, 1]);
  assert.deepStrictEqual(S.displayOrder(st), ['pending:r1']);
  const q = S.newState();
  S.reduce(q, oracle('q1')); S.reduce(q, oracle('q2')); S.reduce(q, oracle('q3', { request: { method: 'GET', path: '/other' } }));
  assert.deepStrictEqual(S.pendingAttacks(q).map((x) => [x.key, x.hits]), [['GET /api/download', 2], ['GET /other', 1]]);
  S.reduce(q, mk('pool.state', { size: 4 }, { ts: t + 2000 }));          // much later and still no incident: no longer shown
  assert.strictEqual(S.pendingAttacks(q).length, 0); assert.strictEqual(S.scoreboard(q).open, 0);
}
S.reduce(st, mk('incident.opened', { incident: 'i1', vuln_class: 'path_traversal', route: '/api/download', param: { in: 'query', name: 'file' }, sink }, { incident: 'i1' }));
assert.strictEqual(st.pendingOracles.length, 0);
assert.strictEqual(S.pendingAttacks(st).length, 0); assert.deepStrictEqual(S.displayOrder(st), ['i1']);
let i1 = st.incidents.i1;
assert.strictEqual(i1.oracles.length, 1);
assert.strictEqual(S.status(i1), 'open');
assert.strictEqual(S.decodeB64(i1.oracles[0].data.request.body_b64), '<img src=x onerror=alert(1)>');
assert.ok(S.queueTime(i1) > 0);                             // identified before it was opened
{ const b = S.scoreboard(st); assert.deepStrictEqual([b.seen, b.open, b.contained, b.cured], [1, 1, 0, 0]); }
assert.strictEqual(S.phase(i1), 'reproduciendo (PoC)');

// --- rule => contained; time to rule is measured from incident.opened (immune/metrics.py)
S.reduce(st, mk('rule.active', { id: 'ru1', incident: 'i1', method: 'GET', route: '/api/download', scope: 'param', ttl_s: 60 }));
assert.strictEqual(S.status(i1), 'contained');
assert.strictEqual(S.timeToRule(i1), i1.rule.ts - i1.opened);
const firstRule = i1.t.rule;
S.reduce(st, mk('rule.active', { id: 'ru1', incident: 'i1', method: 'GET', route: '/api/download', scope: 'param', ttl_s: 60 }));
assert.strictEqual(i1.t.rule, firstRule);                   // a refreshed rule does not move the metric

// --- failed attempt stays visible next to retry
const A = (n, gate, ok) => mk('gate.result', { incident: 'i1', attempt: n, gate, ok, detail: gate + (ok ? ' ok' : ' bad') }, { incident: 'i1' });
S.reduce(st, mk('patch.attempt', { incident: 'i1', attempt: 1, source: 'llm' }, { incident: 'i1' }));
assert.strictEqual(S.phase(i1), 'generando parche #1');
S.reduce(st, mk('patch.diff', { incident: 'i1', attempt: 1, diff: '--- a\n+++ b\n-x\n+y' }, { incident: 'i1' }));
assert.strictEqual(i1.attempts[0].gates.policy.state, 'pending');
assert.strictEqual(S.phase(i1), 'validando parche #1 (0/5 gates)');
S.reduce(st, A(1, 'policy', true)); S.reduce(st, A(1, 'poc', false));
assert.strictEqual(i1.attempts[0].status, 'rejected');
S.reduce(st, mk('patch.attempt', { incident: 'i1', attempt: 2, source: 'llm' }, { incident: 'i1' }));
S.reduce(st, mk('patch.diff', { incident: 'i1', attempt: 2, diff: '+z' }, { incident: 'i1' }));
S.reduce(st, A(2, 'policy', true));
// the real pipeline opens the PR after the policy gate; the other four gates are still the step in progress
S.reduce(st, mk('pr.opened', { incident: 'i1', url: 'https://github.com/o/r/pull/1', branch: 'b' }, { incident: 'i1' }));
assert.strictEqual(S.phase(i1), 'validando parche #2 (1/5 gates)');
{
  const sg = S.stages(i1);
  assert.deepStrictEqual(sg.filter((s) => s.state === 'active').map((s) => s.key), ['gate:properties']);
  assert.strictEqual(sg.find((s) => s.key === 'pr').state, 'done');
  assert.strictEqual(sg.find((s) => s.key === 'patch').note, 'intento 2');
}
S.GATES.slice(1).forEach((g) => S.reduce(st, A(2, g, true)));
assert.strictEqual(i1.attempts.length, 2);
assert.strictEqual(i1.attempts[0].status, 'rejected');
assert.strictEqual(i1.attempts[0].gates.poc.detail, 'poc bad');
assert.strictEqual(i1.attempts[1].status, 'accepted');
assert.strictEqual(S.phase(i1), 'fusionando PR');

// --- merge / deploy / blue-green switch (no incident on those events) / verify => cured
S.reduce(st, mk('pr.merged', { incident: 'i1', url: 'https://github.com/o/r/pull/1', sha: 'abc123' }, { incident: 'i1' }));
assert.strictEqual(S.timeToProd(i1), null);
S.reduce(st, mk('deploy.started', { release: 'abc123def' }));
assert.strictEqual(S.phase(i1), 'desplegando (blue/green)');
assert.strictEqual(S.stages(i1).find((s) => s.key === 'prod').state, 'active');
S.reduce(st, mk('upstream.switched', { release: 'abc123def', addr: 'prod-green:8000' }));
assert.deepStrictEqual([st.upstream.addr, st.upstream.release], ['prod-green:8000', 'abc123def']);
assert.strictEqual(S.timeToProd(i1), i1.prod.ts - i1.opened);     // THE metric: opened -> fixed release serves production
assert.strictEqual(i1.prod.addr, 'prod-green:8000');
const inProd = i1.t.inProd;
S.reduce(st, mk('upstream.switched', { release: 'zzz', addr: 'prod-blue:8000' }));
assert.strictEqual(i1.t.inProd, inProd);                          // only the first switch after the merge counts
S.reduce(st, mk('deploy.done', { release: 'abc123def', ok: true, rolled_back: false, detail: 'ok' }));
assert.ok(i1.deploy && i1.deploy.ok === true);
assert.strictEqual(S.status(i1), 'cured');
S.reduce(st, mk('verify.result', { incident: 'i1', exploit_blocked_on_prod: true }, { incident: 'i1' }));
// seconds_to_* of incident.closed include the queue and the verification: they are not what the page shows
S.reduce(st, mk('incident.closed', { incident: 'i1', outcome: 'patched', seconds_to_rule: 999, seconds_to_patch: 999 }, { incident: 'i1' }));
assert.strictEqual(S.timeToRule(i1), firstRule - i1.opened);
assert.strictEqual(S.timeToProd(i1), inProd - i1.opened);
assert.strictEqual(S.timeToVerified(i1), i1.verify.ts - i1.opened);
assert.strictEqual(S.phase(i1), null);
{
  const sg = S.stages(i1);
  assert.deepStrictEqual(sg.map((s) => s.key), ['detect', 'opened', 'poc', 'rule', 'patch', 'gate:policy', 'gate:properties', 'gate:poc', 'gate:tests', 'gate:legit', 'pr', 'merged', 'prod', 'verify', 'closed']);
  assert.strictEqual(sg.find((s) => s.key === 'poc').state, 'skip');          // no poc.ready in this run
  sg.filter((s) => s.key !== 'poc').forEach((s) => assert.strictEqual(s.state, 'done', s.key));
  sg.forEach((s) => assert.ok(s.dt == null || s.dt >= 0));
}
S.reduce(st, mk('rule.expired', { id: 'ru1', reason: 'patched' }));
assert.strictEqual(S.status(i1), 'cured');
{ const b = S.scoreboard(st); assert.deepStrictEqual([b.open, b.cured, b.prodN, b.prodMedian], [0, 1, 1, inProd - i1.opened]); }

// --- several incidents share the sink (the db helper): evidence is matched by rid == evidence_rid, never by sink alone
{
  const s = S.newState();
  const dbSink = { file: 'victim/app/db.py', line: 25 };
  const ev = (rid, p, ts) => ({ type: 'oracle.fired', ts, rid, incident: null, data: { rid, mode: 'L1', status: 200, request: { method: 'GET', path: p, query: '' },
    pre_state_b64: 'A'.repeat(50000), events: [{ oracle: 'sql', detail: {}, stack: [{ file: 'victim/app/x.py', line: 3 }, { file: 'victim/app/db.py', line: 25 }] }] } });
  S.reduce(s, { type: 'request.classified', ts: 9.9, rid: 'ra', data: { class: 'suspect', reasons: ['grammar:query.q'], method: 'GET', path: '/api/products' } });
  S.reduce(s, ev('ra', '/api/products', 10)); S.reduce(s, ev('rb', '/api/orders/5', 10.2));
  S.reduce(s, { type: 'request.routed', ts: 10.3, rid: 'ra', data: { route: 'shadow_l1', status: 200, verdict: 'oracle', ms: 124 } });
  S.reduce(s, { type: 'incident.opened', ts: 11, incident: 'a', data: { incident: 'a', vuln_class: 'sqli', method: 'GET', route: '/api/products', sink: dbSink, evidence_rid: 'ra' } });
  assert.strictEqual(s.incidents.a.oracles.length, 1);            // rb has the same sink but is another request
  assert.strictEqual(s.pendingOracles.length, 1);
  assert.strictEqual(s.incidents.a.oracles[0].req.cls, 'suspect');           // classified -> diverted, same rid
  assert.strictEqual(s.incidents.a.oracles[0].req.route, 'shadow_l1');
  assert.strictEqual(JSON.stringify(s.incidents.a).indexOf('AAAA'), -1);     // the db snapshot is not kept
  S.reduce(s, { type: 'incident.opened', ts: 60, incident: 'b', data: { incident: 'b', vuln_class: 'idor', method: 'GET', route: '/api/orders/{order_id}', sink: dbSink, evidence_rid: 'rb' } });
  assert.strictEqual(s.incidents.b.oracles[0].data.request.path, '/api/orders/5');
  assert.ok(Math.abs(S.queueTime(s.incidents.b) - 49.8) < 1e-9);  // t0 = its own oracle.fired, not the incident's opening
  assert.ok(Math.abs(S.queueTime(s.incidents.a) - 1) < 1e-9);
  // later hits: same route + sink goes to that incident, and only a few evidence objects are kept
  for (let k = 0; k < 30; k++) S.reduce(s, ev('rx' + k, '/api/orders/' + k, 70 + k));
  assert.strictEqual(s.incidents.b.hits, 31); assert.ok(s.incidents.b.oracles.length <= 5);
  assert.strictEqual(s.incidents.b.oracles[0].rid, 'rb');         // the opening evidence stays first
  assert.strictEqual(s.incidents.a.hits, 1);
  assert.ok(S.routeMatches('/api/orders/{order_id}', '/api/orders/5') && !S.routeMatches('/api/orders/{order_id}', '/api/orders/5/invoice'));
}

// --- rule expiring without a patch re-opens; closed as not reproducible is neither open nor cured
let s2 = S.newState();
S.reduce(s2, mk('incident.opened', { incident: 'x', vuln_class: 'sqli', route: '/r', sink }, { incident: 'x' }));
S.reduce(s2, mk('rule.active', { id: 'rx', incident: 'x', route: '/r' }));
assert.strictEqual(S.status(s2.incidents.x), 'contained');
S.reduce(s2, mk('rule.expired', { id: 'rx', reason: 'ttl' }));
assert.strictEqual(S.status(s2.incidents.x), 'open');
S.reduce(s2, mk('incident.opened', { incident: 'nr', vuln_class: 'other', route: '/n' }, { incident: 'nr' }));
S.reduce(s2, mk('poc.ready', { incident: 'nr', reproducible: false, runs: 3 }, { incident: 'nr' }));
assert.strictEqual(S.stages(s2.incidents.nr).find((s) => s.key === 'poc').state, 'fail');
S.reduce(s2, mk('incident.closed', { incident: 'nr', outcome: 'not_reproducible' }, { incident: 'nr' }));
assert.strictEqual(S.status(s2.incidents.nr), 'dismissed');
{ const b = S.scoreboard(s2); assert.deepStrictEqual([b.open, b.dismissed, b.cured, b.prodMedian], [1, 1, 0, null]); }
assert.ok(S.stages(s2.incidents.nr).every((s) => s.state !== 'active' && s.state !== 'pending'));
// failed deploy and failed verification are shown as failures
S.reduce(s2, mk('incident.opened', { incident: 'fd', vuln_class: 'sqli', route: '/f' }, { incident: 'fd' }));
S.reduce(s2, mk('pr.merged', { incident: 'fd', sha: 'ffff' }, { incident: 'fd' }));
S.reduce(s2, mk('deploy.done', { release: 'ffff', ok: false, rolled_back: true, detail: 'unhealthy' }));
assert.strictEqual(S.stages(s2.incidents.fd).find((s) => s.key === 'prod').state, 'fail');
assert.strictEqual(S.phase(s2.incidents.fd), 'deploy revertido');
S.reduce(s2, mk('verify.result', { incident: 'fd', exploit_blocked_on_prod: false }, { incident: 'fd' }));
assert.strictEqual(S.stages(s2.incidents.fd).find((s) => s.key === 'verify').state, 'fail');
assert.strictEqual(S.status(s2.incidents.fd), 'open');
// deployed fine but the exploit still works: not cured
S.reduce(s2, mk('incident.opened', { incident: 'fv', vuln_class: 'sqli', route: '/v' }, { incident: 'fv' }));
S.reduce(s2, mk('pr.merged', { incident: 'fv', sha: 'eeee' }, { incident: 'fv' }));
S.reduce(s2, mk('deploy.done', { release: 'eeee', ok: true, rolled_back: false }));
assert.strictEqual(S.status(s2.incidents.fv), 'cured');
S.reduce(s2, mk('verify.result', { incident: 'fv', exploit_blocked_on_prod: false }, { incident: 'fv' }));
assert.strictEqual(S.status(s2.incidents.fv), 'open');
S.reduce(s2, mk('gate.result', { incident: 'fv', attempt: 1, gate: 'tests', ok: false, detail: { failed: 2 } }, { incident: 'fv' }));
assert.strictEqual(s2.incidents.fv.attempts[0].gates.tests.detail, '{"failed":2}');
// display order: in progress, then queued, then closed
S.reduce(s2, mk('audit.finding', { incident: 'q1', parent: 'x', route: '/q' }, { incident: 'q1' }));
assert.deepStrictEqual(S.displayOrder(s2), ['x', 'fd', 'fv', 'q1', 'nr']);

// --- counters, sessions, pool, ticker, attacks
let s3 = S.newState();
S.reduce(s3, mk('request.classified', { class: 'clean', method: 'GET', path: '/a' }, { rid: 'q1' }));
S.reduce(s3, mk('request.routed', { route: 'prod', status: 200 }, { rid: 'q1' }));
S.reduce(s3, mk('request.routed', { route: 'shadow_l2', status: 200 }, { rid: 'q2' }));
S.reduce(s3, mk('request.routed', { route: 'deny', status: 403 }, { rid: 'q3' }));
S.reduce(s3, mk('request.routed', { route: 'prod', status: 404, verdict: 'inconclusive' }, { rid: 'q4' }));   // ran in a clone, then went to prod
S.reduce(s3, mk('session.captured', { session: 'a', clone: 'c1', reason: 'x' }));
S.reduce(s3, mk('session.captured', { session: 'b', clone: null, reason: 'x' }));
S.reduce(s3, mk('session.released', { session: 'a', reason: 'ttl' }));
S.reduce(s3, mk('pool.state', { l1_free: 3, l2_busy: 1, size: 4 }));
const sc = S.scoreboard(s3);
assert.deepStrictEqual([sc.prod, sc.detonated, sc.deny, sc.captive, sc.free, sc.busy], [2, 2, 1, 1, 3, 1]);
assert.strictEqual(s3.ticker.length, 4);
assert.strictEqual(s3.tickerByRid.q1.route, 'prod');
assert.strictEqual(s3.tickerByRid.q1.path, '/a');
for (let i = 0; i < 100; i++) S.reduce(s3, mk('request.routed', { route: 'prod', status: 200 }, { rid: 'z' + i }));
assert.ok(s3.ticker.length <= 60 && Object.keys(s3.tickerByRid).length <= 60);
S.reduce(s3, mk('attack.attempt', { vuln: 'v', ok: true, saw_real_data: true }));
S.reduce(s3, mk('attack.attempt', { vuln: 'v', ok: true, saw_real_data: false }));
S.reduce(s3, mk('attack.attempt', { vuln: 'v', ok: false, saw_real_data: false }));
assert.deepStrictEqual(s3.attacks.v.map(S.attackKind), ['leak', 'exec', 'blocked']);
for (let i = 0; i < 500; i++) S.reduce(s3, mk('attack.attempt', { vuln: 'kind' + i, ok: true }));
assert.ok(s3.attackOrder.length <= 40);

// --- robustness: unknown types, missing or wrongly typed fields, hostile ids
const before = s3.ignored;
S.reduce(s3, { type: 'nope' }); S.reduce(s3, null); S.reduce(s3, 'x'); S.reduce(s3, []);
assert.strictEqual(s3.ignored, before + 4);
S.reduce(s3, { type: 'gate.result', ts: 1 });
S.reduce(s3, { type: 'patch.diff', incident: 'h', data: { attempt: 1, diff: 123 } });
const junk = [null, 0, 1, '', 'x', [], {}, { a: 1 }, true, [1, 2], { file: {}, line: {} }, { name: {} }];
['request.classified', 'request.routed', 'oracle.fired', 'session.captured', 'session.released', 'rule.active', 'rule.expired', 'upstream.switched',
 'pool.state', 'deploy.started', 'deploy.done', 'incident.opened', 'poc.ready', 'patch.attempt', 'patch.diff', 'gate.result', 'pr.opened',
 'pr.merged', 'incident.closed', 'verify.result', 'audit.started', 'audit.finding', 'audit.done', 'attack.attempt'].forEach((type) => {
  junk.forEach((j) => {
    S.reduce(s3, { type, ts: j, rid: j, incident: j, data: j });
    const data = {};
    ['incident', 'id', 'session', 'vuln', 'route', 'param', 'sink', 'request', 'events', 'attempt', 'gate', 'diff', 'detail', 'url', 'sha', 'release', 'addr',
     'outcome', 'parent', 'candidates', 'reasons', 'method', 'path', 'class', 'status', 'ms', 'verdict', 'evidence_rid', 'origin', 'runs'].forEach((k) => { data[k] = j; });
    S.reduce(s3, { type, ts: 5, rid: 'r', incident: 'junk', data });
    S.reduce(s3, { type, ts: 5, data });
  });
});
Object.keys(s3.incidents).forEach((id) => {            // whatever got in must still be drawable
  const i = s3.incidents[id];
  S.status(i); S.phase(i); S.stages(i); S.timeToRule(i); S.timeToProd(i); S.queueTime(i);
  assert.ok(i.param === null || typeof i.param.name === 'string');
  assert.ok(i.sink === null || typeof i.sink.file === 'string');
});
S.scoreboard(s3); S.displayOrder(s3);
// ids are data: '__proto__' and friends must not reach Object.prototype
['__proto__', 'constructor', 'toString', 'hasOwnProperty'].forEach((bad) => {
  S.reduce(s3, { type: 'incident.opened', ts: 7, incident: bad, data: { incident: bad, vuln_class: 'sqli', route: '/p' } });
  S.reduce(s3, { type: 'rule.active', ts: 7, data: { id: bad, incident: bad } });
  S.reduce(s3, { type: 'session.captured', ts: 7, data: { session: bad } });
  S.reduce(s3, { type: 'request.routed', ts: 7, rid: bad, data: { route: 'prod' } });
  S.reduce(s3, { type: 'attack.attempt', ts: 7, data: { vuln: bad, ok: true } });
  S.reduce(s3, { type: 'audit.started', ts: 7, incident: bad, data: { vuln_class: 'sqli' } });
  assert.strictEqual(s3.incidents[bad].id, bad);
});
assert.strictEqual({}.opened, undefined); assert.strictEqual({}.rev, undefined); assert.strictEqual(Object.prototype.id, undefined);
assert.strictEqual(typeof {}.toString, 'function');
assert.strictEqual(S.isGithubUrl('https://github.com/a/b'), true);
assert.strictEqual(S.isGithubUrl('javascript:alert(1)'), false);
assert.strictEqual(S.isGithubUrl('https://github.com.evil.io/x'), false);
assert.strictEqual(S.isGithubUrl('https://github.com/o/r/pull/1"onmouseover="x'), false);
assert.strictEqual(S.isGithubUrl('https://github.com/o/r/pull/1?x=<b>'), false);
assert.strictEqual(S.isGithubUrl('https://github.com/o/r/pull/12'), true);
// a local PR is named, its host path is never printed
assert.strictEqual(S.prLabel('file:///home/someone/repo/.git/immune/prs/20.json#pr-20'), 'PR local #20');
assert.strictEqual(S.prLabel('javascript:alert(1)'), 'PR local');
assert.strictEqual(S.prLabel('https://github.com/o/r/pull/3'), 'https://github.com/o/r/pull/3');

// --- class self-audit: audit.started / audit.finding / audit.done, origin audit linked to its parent
let s4 = S.newState();
S.reduce(s4, mk('incident.opened', { incident: 'p1', vuln_class: 'sqli', method: 'GET', route: '/api/products', param: { in: 'query', name: 'q' }, sink, origin: 'live' }, { incident: 'p1' }));
assert.strictEqual(S.auditLine(s4), null);
S.reduce(s4, mk('incident.closed', { incident: 'p1', outcome: 'patched' }, { incident: 'p1' }));
S.reduce(s4, mk('audit.started', { incident: 'p1', vuln_class: 'sqli', candidates: 8 }, { incident: 'p1' }));
assert.ok(/sqli/.test(S.auditLine(s4)) && /8 candidatos, en curso/.test(S.auditLine(s4)));
S.reduce(s4, mk('audit.finding', { incident: 'a1', parent: 'p1', route: '/api/login', param: { in: 'json', name: '<b>email</b>' } }, { incident: 'a1' }));
let a1 = s4.incidents.a1;
assert.strictEqual(a1.origin, 'audit'); assert.strictEqual(a1.parent, 'p1');
assert.strictEqual(S.visible(a1), true);                      // shown (queued) before incident.opened
assert.strictEqual(S.status(a1), 'open');
assert.strictEqual(S.phase(a1), 'en cola');
assert.strictEqual(S.timeToRule(a1), null);
assert.ok(/1 hallazgo/.test(S.auditLine(s4)));
S.reduce(s4, mk('audit.done', { incident: 'p1', checked: 8, findings: 1, seconds: 5.25 }, { incident: 'p1' }));
assert.strictEqual(S.auditLine(s4), 'Auditoría de clase sqli tras p1: 8 de 8 candidatos revisados, 1 hallazgo en 5.3 s');
S.reduce(s4, mk('incident.opened', { incident: 'a1', vuln_class: 'sqli', method: 'POST', route: '/api/login', param: { in: 'json', name: 'email' }, sink: { file: 'victim/app/db.py', line: 25 }, evidence_rid: 'audit-p1-1', origin: 'audit', parent: 'p1', request: { method: 'POST', path: '/api/login', query: '', body_b64: b64('{"email":"x\' --"}') } }, { incident: 'a1' }));
assert.strictEqual(a1.origin, 'audit'); assert.strictEqual(a1.parent, 'p1'); assert.strictEqual(a1.method, 'POST');
assert.strictEqual(S.stages(a1)[0].label, 'Hallado por auditoría');
assert.strictEqual(S.stages(a1)[0].ts, a1.t.found);        // t0 = the finding, not the queue exit
assert.ok(S.t0(a1) === a1.t.found);
assert.strictEqual(S.queueTime(a1), a1.opened - a1.t.found);
assert.strictEqual(S.decodeB64(a1.request.body_b64), '{"email":"x\' --"}');
S.reduce(s4, mk('rule.active', { id: 'ra', incident: 'a1', route: '/api/login' }));
S.reduce(s4, mk('incident.closed', { incident: 'a1', outcome: 'patched' }, { incident: 'a1' }));
{ const b = S.scoreboard(s4); assert.deepStrictEqual([b.seen, b.cured, b.audit], [2, 2, 1]); }
assert.strictEqual(s4.incidents.p1.origin, 'live');
// a live incident.opened without origin stays live; garbage in audit events does not throw
S.reduce(s4, mk('incident.opened', { incident: 'p2', vuln_class: 'idor', route: '/x' }, { incident: 'p2' }));
assert.strictEqual(s4.incidents.p2.origin, 'live');
S.reduce(s4, { type: 'audit.finding', data: {} }); S.reduce(s4, { type: 'audit.done' });
S.reduce(s4, mk('audit.started', { incident: 'p2', vuln_class: 'idor', candidates: 'many' }, { incident: 'p2' }));
assert.ok(/idor tras p2: \? candidatos/.test(S.auditLine(s4)));

// --- memory stays bounded over a long session and the totals survive
{
  const big = S.newState();
  let ts = 5000;
  for (let k = 0; k < 1000; k++) {
    const id = 'm' + k, e = (type, data) => S.reduce(big, { type, ts: (ts += 1), incident: id, data: Object.assign({ incident: id }, data) });
    S.reduce(big, { type: 'request.routed', ts, rid: 'rq' + k, data: { route: 'prod', status: 200 } });
    e('incident.opened', { vuln_class: 'sqli', route: '/r' + k, origin: k % 4 ? 'live' : 'audit' });
    e('rule.active', { id: 'rule-' + id });
    e('patch.diff', { attempt: 1, diff: '+x'.repeat(200) });
    e('pr.merged', { sha: 's' + k });
    S.reduce(big, { type: 'upstream.switched', ts: (ts += 1), data: { release: 's' + k, addr: 'prod-blue:8000' } });
    e('incident.closed', { outcome: k % 10 ? 'patched' : 'not_reproducible' });
    S.reduce(big, { type: 'rule.expired', ts: (ts += 1), data: { id: 'rule-' + id, reason: 'deleted' } });
  }
  assert.ok(big.order.length <= 300 && Object.keys(big.incidents).length <= 300);
  assert.ok(Object.keys(big.rules).length === 0 && big.ticker.length <= 60 && big.switches.length <= 12);
  const b = S.scoreboard(big);
  assert.deepStrictEqual([b.seen, b.cured, b.dismissed, b.open, b.audit, b.prodN, b.prodMedian], [1000, 900, 100, 0, 250, 900, 4]);
  assert.strictEqual(big.incidents.m999.id, 'm999'); assert.strictEqual(big.incidents.m0, undefined);
  assert.strictEqual(S.displayOrder(big)[0], 'm999');
}

// --- an incident opened again (retry after a transient failure): the last run is the one shown and timed
{
  const d = S.newState();
  const I = { incident: 'inc-r' };
  const run = (ok) => {
    S.reduce(d, mk('incident.opened', { incident: 'inc-r', vuln_class: 'idor', route: '/api/orders/{id}', sink: phpFrame }, I));
    S.reduce(d, mk('rule.active', { id: 'rule-r', incident: 'inc-r', route: '/api/orders/{id}' }, I));
    S.reduce(d, mk('patch.attempt', { incident: 'inc-r', attempt: 1, source: ok ? 'llm' : 'fallback' }, I));
    S.reduce(d, mk('patch.diff', { incident: 'inc-r', attempt: 1, diff: ok ? '+x' : '' }, I));
    S.reduce(d, mk('gate.result', { incident: 'inc-r', attempt: 1, gate: 'policy', ok: ok }, I));
    if (!ok) { t += 30; return S.reduce(d, mk('incident.closed', { incident: 'inc-r', outcome: 'rule_only' }, I)); }
    ['properties', 'poc', 'tests', 'legit'].forEach((g) => S.reduce(d, mk('gate.result', { incident: 'inc-r', attempt: 1, gate: g, ok: true }, I)));
    S.reduce(d, mk('pr.merged', { incident: 'inc-r', sha: 'abc' }, I));
    S.reduce(d, mk('upstream.switched', { release: 'abc', addr: 'prod-b:8000' }));
    S.reduce(d, mk('incident.closed', { incident: 'inc-r', outcome: 'patched' }, I));
  };
  run(false);
  assert.strictEqual(d.incidents['inc-r'].closed.outcome, 'rule_only');
  assert.deepStrictEqual(S.phpLocation(d.incidents['inc-r']), phpFrame);
  run(true);
  const i = d.incidents['inc-r'];
  assert.strictEqual(i.runs, 2);
  assert.strictEqual(i.attempts.length, 1); assert.strictEqual(i.attempts[0].status, 'accepted');
  assert.strictEqual(S.timeToRule(i), 1);                       // measured inside the last run, not from the first rule
  assert.ok(S.stages(i).every((s) => s.state !== 'fail'));              // the failed gate of the first run is gone
  assert.strictEqual(S.status(i), 'cured');
  assert.strictEqual(S.scoreboard(d).ruleMedian, 1);
}

// --- external file: replay the scripted demo and check the end state
if (process.argv[2]) {
  const evs = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const d = S.newState();
  evs.forEach((e) => S.reduce(d, e, e.seq));
  const sb = S.scoreboard(d);
  assert.strictEqual(sb.seen, 2); assert.strictEqual(sb.cured, 2); assert.strictEqual(sb.open, 0);
  assert.strictEqual(d.ignored, 0);                        // every event type of the script is understood
  const trav = d.incidents['inc-trav-1'];
  assert.strictEqual(trav.attempts.length, 2);
  assert.strictEqual(trav.attempts[0].status, 'rejected'); assert.strictEqual(trav.attempts[1].status, 'accepted');
  assert.strictEqual(trav.oracles.length, 1);
  const sq = d.incidents['inc-sqli-1'];
  assert.strictEqual(sq.oracles.length, 1);
  assert.ok(S.decodeB64(sq.oracles[0].data.request.body_b64) === '');
  assert.ok(sq.oracles[0].data.request.query.includes('<img src=x onerror=alert(1)>'));
  assert.ok(sq.deploy && sq.deploy.ok && trav.deploy && trav.deploy.ok);
  assert.ok(S.timeToProd(sq) > 0 && S.timeToRule(sq) > 0);
  assert.ok(d.attackOrder.length === 3 && d.attacks['sqli:/api/search'].length === 6);
  // reload determinism: reducing again gives identical scoreboard
  const d2 = S.newState(); evs.forEach((e) => S.reduce(d2, e, e.seq));
  assert.deepStrictEqual(S.scoreboard(d2), sb);
}
console.log('reducer ok');

// ---- canary summary on deploy.done
(function () {
  var st = S.newState();
  var seq = 9000;
  function ev(type, data) { return { type: type, ts: 100 + seq / 1000, seq: ++seq, run: 'r', src: 't', incident: 'inc-c', data: data }; }
  S.reduce(st, ev('incident.opened', { incident: 'inc-c', vuln_class: 'sqli', method: 'GET', route: '/x' }));
  S.reduce(st, ev('deploy.started', { release: 'abc' }));
  S.reduce(st, ev('deploy.done', { release: 'abc', ok: false, rolled_back: false, detail: 'canary: worse',
    canary: { verdict: 'worse', weight: 0.1, seconds: 3.2, canary: { requests: 30, '5xx': 9, '4xx': 0 }, stable: { requests: 270, '5xx': 1, '4xx': 2 } } }));
  var c = st.incidents['inc-c'].deploy.canary;
  if (!c || c.verdict !== 'worse' || c.requests !== 30 || c.e5 !== 9 || c.stableRequests !== 270 || c.weight !== 0.1) throw new Error('canary summary: ' + JSON.stringify(c));
  S.reduce(st, ev('deploy.done', { release: 'abc', ok: true, rolled_back: false, canary: { verdict: 'nonsense' } }));
  if (st.incidents['inc-c'].deploy.canary !== null) throw new Error('unknown canary verdict must be dropped');
  console.log('canary ok');
})();
