'use strict';

const assert = require('node:assert/strict');
const { randomBytes, randomUUID } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const { protectScheduler, protectSocket } = require('./policy.cjs');
const { createContainment } = require('./containment.cjs');
const { createEvaluator } = require('./policy-evaluator.cjs');

const jwt = createRequire('/app/server/package.json')('jsonwebtoken');
const auth = { secretCode: randomBytes(32).toString('hex'), adminGroups: [255] };
const accounts = new Map([['administrator', { groups: [255] }], ['operator', { groups: [1] }]]);
const runtime = {
    users: { getUserCache: id => accounts.get(id) },
};
const sign = (id, expiresIn = 60) => jwt.sign({ id }, auth.secretCode, { expiresIn });
const identities = {
    anonymous: undefined,
    invalid: 'invalid',
    guest: sign('guest'),
    operator: sign('operator'),
    expired: sign('administrator', -1),
    unknown_account: sign('former-user'),
    administrator: sign('administrator'),
};

async function checkHttp(token, effect, opId = randomUUID()) {
    const req = { headers: { 'x-access-token': token, 'x-immune-op-id': opId } };
    let status;
    await protectScheduler(req, { sendStatus: code => { status = code; } }, () => {
        effect();
        status = 204;
    }, runtime, auth);
    return status;
}

function syntheticSocket(token, id = 'session-' + randomUUID()) {
    let middleware;
    protectSocket({ id, handshake: { query: { token } }, use: callback => { middleware = callback; } },
        runtime.users, auth);
    return async (packet, effect) => {
        let allowed = false;
        await middleware(packet, error => {
            if (error) return;
            effect();
            allowed = true;
        });
        return allowed;
    };
}

const server = readFileSync('/app/server/runtime/index.js', 'utf8');
assert.match(server, /io\.on\('connection', async \(socket\) => \{\s*immunePolicy\.protectSocket\(socket, users, api\.authJwt\);/);
for (const event of ['DAQ_RESULT', 'DAQ_ERROR']) {
    assert.ok(server.includes('socket.emit(Events.IoEventTypes.' + event + ','));
    assert.ok(!server.includes('io.emit(Events.IoEventTypes.' + event + ','));
}
const scheduler = readFileSync('/app/server/api/scheduler/index.js', 'utf8');
for (const method of ['post', 'delete']) {
    assert.ok(scheduler.includes('schedulerApp.' + method + '("/api/scheduler", ' +
        '(req, res, next) => immunePolicy.protectScheduler(req, res, next, runtime, authJwt), secureFnc,'));
}

async function main() {
    // Factory controls listed in IMMUNE_FUXA_PROTECTED_OBSERVE run in observation:
    // an unprivileged identity reaches the effect and the decision is recorded.
    const observe = new Set((process.env.IMMUNE_FUXA_PROTECTED_OBSERVE || '')
        .split(',').map(item => item.trim()).filter(Boolean));
    let checks = 0;
    for (const [identity, token] of Object.entries(identities)) {
        const allowed = identity === 'administrator';
        const session = syntheticSocket(token);
        const state = { tagValue: 1, deviceEnabled: true, schedule: 'original', disclosures: 0 };
        const reaches = operation => allowed || observe.has(operation);
        assert.equal(await session(['device-values', { cmd: 'set' }], () => { state.tagValue = 2; }), reaches('tag_write'));
        assert.equal(state.tagValue, reaches('tag_write') ? 2 : 1);
        assert.equal(await session(['device-enable', {}], () => { state.deviceEnabled = false; }), reaches('device_control'));
        assert.equal(state.deviceEnabled, !reaches('device_control'));
        assert.equal(await session(['daq-query', {}], () => { state.disclosures++; }), reaches('historian_query'));
        assert.equal(state.disclosures, reaches('historian_query') ? 1 : 0);
        assert.equal(await checkHttp(token, () => { state.schedule = 'updated'; }), reaches('scheduler_authorization') ? 204 : 403);
        assert.equal(state.schedule, reaches('scheduler_authorization') ? 'updated' : 'original');
        assert.equal(await checkHttp(token, () => { delete state.schedule; }), reaches('scheduler_authorization') ? 204 : 403);
        assert.equal(state.schedule, reaches('scheduler_authorization') ? undefined : 'original');
        checks += 5;
    }

    const revoked = syntheticSocket(identities.administrator);
    accounts.delete('administrator');
    // A revoked account loses its role; in observation mode the effect still
    // happens (that exposure is exactly what the incident records).
    assert.equal(await revoked(['device-values', { cmd: 'set' }], () => {}), observe.has('tag_write'));
    assert.equal(await syntheticSocket(undefined)(['device-values', { cmd: 'get' }], () => {}), true);
    checks += 2;

    const evaluator = createEvaluator();
    assert.equal(await evaluator('unregistered', 'administrator'), 'deny');
    const offline = createEvaluator({ entry: '/immune/nonexistent-checker.cjs', timeout: 100 });
    assert.equal(await offline('tag_write', 'administrator'), 'unavailable');
    checks += 2;

    // Session containment: repeated denied operations restrict the session, the
    // denied operations stay blocked and ordinary reads remain available.
    {
        let moment = 0;
        const events = [];
        const containment = createContainment({
            threshold: 3, window: 120_000, ttl: 900_000, now: () => moment,
            emit: (type, payload) => events.push({ type, ...payload }),
        });
        const session = 'sid:synthetic';
        assert.equal(containment.check(session, 'tag_write'), false);
        for (let attempt = 0; attempt < 3; attempt++) {
            moment += 1000;
            assert.equal(containment.observe(session, 'tag_write'), attempt === 2);
        }
        const restricted = events.find(item => item.type === 'session_restricted');
        assert.equal(restricted.session, session);
        assert.deepEqual(restricted.operations, ['tag_write']);
        assert.equal(restricted.reason, 'repeated-denied-operations');
        assert.equal(restricted.expires, Math.round((3 * 1000 + 900_000) / 1000));
        assert.equal(containment.check(session, 'tag_write'), true);
        assert.equal(containment.check(session, 'device_control'), false);
        containment.observe(session, 'device_control');
        assert.equal(containment.check(session, 'device_control'), true);
        assert.equal(containment.active().length, 1);
        moment += 900_001;
        assert.equal(containment.check(session, 'tag_write'), false);
        assert.deepEqual(events.filter(item => item.type === 'session_released'),
            [{ type: 'session_released', session, reason: 'ttl' }]);
        checks += 10;
    }

    // The server keeps the denied effect away even while the policy evaluator is
    // offline, and containment keys never carry credentials, only opaque ids.
    {
        let moment = 0;
        const containment = createContainment({ threshold: 2, window: 60_000, ttl: 5000, now: () => moment });
        containment.observe('sid:a', 'tag_write');
        moment += 1000;
        assert.equal(containment.observe('sid:a', 'tag_write'), true);
        assert.equal(containment.check('sid:a', 'tag_write'), true);
        assert.equal(containment.active()[0].session, 'sid:a');
        moment += 5001;
        assert.equal(containment.check('sid:a', 'tag_write'), false);
        checks += 4;
    }

    console.log(JSON.stringify({
        checks, identities: Object.keys(identities).length, evaluator: 'metadata',
        operations: ['tag_write', 'device_control', 'historian_query', 'scheduler_authorization'],
        containment: 'session', observe: [...observe],
    }));
}

main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
