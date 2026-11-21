// Run: node dashboard/tests/reducer.test.js [events.json]   (events.json: list of bus events with seq)
'use strict';
const assert = require('assert');
const path = require('path');
const S = require(path.join(__dirname, '..', 'static', 'state.js'));

let t = 1000;
const mk = (type, data, o = {}) => Object.assign({ type, ts: (t += 1), run: 'r', src: 's', rid: null, incident: null, data }, o);
const b64 = (s) => Buffer.from(s).toString('base64');
const sink = { file: 'app/routes/files.py', line: 27 };
const oracle = (rid) => mk('oracle.fired', {
  clone: 'c', rid, mode: 'L2', release: 'r0', verdict: 'oracle', status: 200,
  request: { method: 'GET', path: '/api/download', query: 'file=../x', headers: {}, body_b64: b64('<img src=x onerror=alert(1)>') },
  events: [{ oracle: 'file', detail: { path: '/etc/passwd' }, stack: [{ file: '/srv/app/routes/files.py', line: 27, func: 'download' }] }]
}, { rid });

// --- oracle arrives before incident.opened and is matched by sink
let st = S.newState();
S.reduce(st, mk('attack.attempt', { vuln: 'trav', ok: true, saw_real_data: true }));
S.reduce(st, oracle('r1'));
assert.strictEqual(st.pendingOracles.length, 1);
S.reduce(st, mk('incident.opened', { incident: 'i1', vuln_class: 'path_traversal', route: '/api/download', param: { in: 'query', name: 'file' }, sink }, { incident: 'i1' }));
assert.strictEqual(st.pendingOracles.length, 0);
let i1 = st.incidents.i1;
assert.strictEqual(i1.oracles.length, 1);
assert.strictEqual(S.status(i1), 'open');
assert.strictEqual(S.decodeB64(i1.oracles[0].data.request.body_b64), '<img src=x onerror=alert(1)>');
{ const b = S.scoreboard(st); assert.deepStrictEqual([b.seen, b.open, b.contained, b.cured], [1, 1, 0, 0]); }

// --- rule => contained; ttr computed from oracle ts
S.reduce(st, mk('rule.active', { id: 'ru1', incident: 'i1', method: 'GET', route: '/api/download', scope: 'param', ttl_s: 60 }));
assert.strictEqual(S.status(i1), 'contained');
assert.ok(S.timeToRule(i1) > 0);

// --- failed attempt stays visible next to retry
const A = (n, gate, ok) => mk('gate.result', { incident: 'i1', attempt: n, gate, ok, detail: gate + (ok ? ' ok' : ' bad') }, { incident: 'i1' });
S.reduce(st, mk('patch.attempt', { incident: 'i1', attempt: 1, source: 'llm' }, { incident: 'i1' }));
S.reduce(st, mk('patch.diff', { incident: 'i1', attempt: 1, diff: '--- a\n+++ b\n-x\n+y' }, { incident: 'i1' }));
assert.strictEqual(i1.attempts[0].gates.policy.state, 'pending');
S.reduce(st, A(1, 'policy', true)); S.reduce(st, A(1, 'poc', false));
assert.strictEqual(i1.attempts[0].status, 'rejected');
S.reduce(st, mk('patch.attempt', { incident: 'i1', attempt: 2, source: 'llm' }, { incident: 'i1' }));
S.GATES.forEach((g) => S.reduce(st, A(2, g, true)));
assert.strictEqual(i1.attempts.length, 2);
assert.strictEqual(i1.attempts[0].status, 'rejected');
assert.strictEqual(i1.attempts[0].gates.poc.detail, 'poc bad');
assert.strictEqual(i1.attempts[1].status, 'accepted');

// --- PR / deploy (no incident on deploy events) / verify => cured
S.reduce(st, mk('pr.opened', { incident: 'i1', url: 'https://github.com/o/r/pull/1', branch: 'b' }, { incident: 'i1' }));
S.reduce(st, mk('pr.merged', { incident: 'i1', url: 'https://github.com/o/r/pull/1', sha: 'abc123' }, { incident: 'i1' }));
S.reduce(st, mk('deploy.started', { release: 'abc123def' }));
S.reduce(st, mk('deploy.done', { release: 'abc123def', ok: true, rolled_back: false, detail: 'ok' }));
assert.ok(i1.deploy && i1.deploy.ok === true);
assert.strictEqual(S.status(i1), 'cured');
S.reduce(st, mk('verify.result', { incident: 'i1', exploit_blocked_on_prod: true }, { incident: 'i1' }));
S.reduce(st, mk('incident.closed', { incident: 'i1', outcome: 'patched', seconds_to_rule: 2.5, seconds_to_patch: 9 }, { incident: 'i1' }));
assert.strictEqual(S.timeToRule(i1), 2.5);
assert.strictEqual(S.timeToPatch(i1), 9);
const ms = S.milestones(i1).map((m) => m.key);
assert.deepStrictEqual(ms, ['oracle', 'rule', 'patchStart', 'pr', 'merged', 'deploy', 'verify']);
S.milestones(i1).forEach((m) => assert.ok(m.delta >= 0));
S.reduce(st, mk('rule.expired', { id: 'ru1', reason: 'patched' }));
assert.strictEqual(S.status(i1), 'cured');
assert.deepStrictEqual([S.scoreboard(st).open, S.scoreboard(st).cured], [0, 1]);

// --- rule expiring without a patch re-opens
let s2 = S.newState();
S.reduce(s2, mk('incident.opened', { incident: 'x', vuln_class: 'sqli', route: '/r', sink }, { incident: 'x' }));
S.reduce(s2, mk('rule.active', { id: 'rx', incident: 'x', route: '/r' }));
assert.strictEqual(S.status(s2.incidents.x), 'contained');
S.reduce(s2, mk('rule.expired', { id: 'rx', reason: 'ttl' }));
assert.strictEqual(S.status(s2.incidents.x), 'open');

// --- counters, sessions, pool, ticker, attacks
let s3 = S.newState();
S.reduce(s3, mk('request.classified', { class: 'clean', method: 'GET', path: '/a' }, { rid: 'q1' }));
S.reduce(s3, mk('request.routed', { route: 'prod', status: 200 }, { rid: 'q1' }));
S.reduce(s3, mk('request.routed', { route: 'shadow_l2', status: 200 }, { rid: 'q2' }));
S.reduce(s3, mk('request.routed', { route: 'deny', status: 403 }, { rid: 'q3' }));
S.reduce(s3, mk('session.captured', { session: 'a', clone: 'c1', reason: 'x' }));
S.reduce(s3, mk('session.captured', { session: 'b', clone: 'c2', reason: 'x' }));
S.reduce(s3, mk('session.released', { session: 'a', reason: 'ttl' }));
S.reduce(s3, mk('pool.state', { l1_free: 3, l2_busy: 1, size: 4 }));
const sc = S.scoreboard(s3);
assert.deepStrictEqual([sc.prod, sc.detonated, sc.deny, sc.captive, sc.free, sc.busy], [1, 1, 1, 1, 3, 1]);
assert.strictEqual(s3.ticker.length, 3);
assert.strictEqual(s3.tickerByRid.q1.route, 'prod');
assert.strictEqual(s3.tickerByRid.q1.path, '/a');
for (let i = 0; i < 100; i++) S.reduce(s3, mk('request.routed', { route: 'prod', status: 200 }, { rid: 'z' + i }));
assert.ok(s3.ticker.length <= 60 && Object.keys(s3.tickerByRid).length <= 60);
S.reduce(s3, mk('attack.attempt', { vuln: 'v', ok: true, saw_real_data: true }));
S.reduce(s3, mk('attack.attempt', { vuln: 'v', ok: true, saw_real_data: false }));
S.reduce(s3, mk('attack.attempt', { vuln: 'v', ok: false, saw_real_data: false }));
assert.deepStrictEqual(s3.attacks.v.map(S.attackKind), ['leak', 'exec', 'blocked']);

// --- robustness: unknown types, missing data, hostile strings
S.reduce(s3, { type: 'nope' });
S.reduce(s3, { type: 'gate.result', ts: 1 });
S.reduce(s3, { type: 'patch.diff', incident: 'h', data: { attempt: 1, diff: 123 } });
assert.strictEqual(S.isGithubUrl('https://github.com/a/b'), true);
assert.strictEqual(S.isGithubUrl('javascript:alert(1)'), false);
assert.strictEqual(S.isGithubUrl('https://github.com.evil.io/x'), false);

// --- external file: replay the scripted demo and check the end state
if (process.argv[2]) {
  const evs = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));
  const d = S.newState();
  evs.forEach((e) => S.reduce(d, e, e.seq));
  const sb = S.scoreboard(d);
  assert.strictEqual(sb.seen, 2); assert.strictEqual(sb.cured, 2); assert.strictEqual(sb.open, 0);
  const trav = d.incidents['inc-trav-1'];
  assert.strictEqual(trav.attempts.length, 2);
  assert.strictEqual(trav.attempts[0].status, 'rejected'); assert.strictEqual(trav.attempts[1].status, 'accepted');
  assert.strictEqual(trav.oracles.length, 1);
  const sq = d.incidents['inc-sqli-1'];
  assert.strictEqual(sq.oracles.length, 1);
  assert.ok(S.decodeB64(sq.oracles[0].data.request.body_b64) === '');
  assert.ok(sq.oracles[0].data.request.query.includes('<img src=x onerror=alert(1)>'));
  assert.ok(sq.deploy && sq.deploy.ok && trav.deploy && trav.deploy.ok);
  assert.ok(d.attackOrder.length === 3 && d.attacks['sqli:/api/search'].length === 6);
  // reload determinism: reducing again gives identical scoreboard
  const d2 = S.newState(); evs.forEach((e) => S.reduce(d2, e, e.seq));
  assert.deepStrictEqual(S.scoreboard(d2), sb);
}
console.log('reducer ok');
