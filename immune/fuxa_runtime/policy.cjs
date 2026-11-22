'use strict';

const { randomUUID } = require('node:crypto');
const { appendFileSync, readFileSync, statSync } = require('node:fs');
const { createRequire } = require('node:module');
const { createEvaluator } = require('./policy-evaluator.cjs');
const { createContainment, tokenKey } = require('./containment.cjs');
const evaluate = createEvaluator();

// Incident containment rules: while a candidate patch validates, Fleet keeps a
// TTL rule in /telemetry/rules.json that denies the affected operation for
// every session. The file is re-read when its mtime changes.
let rulesCache = { mtime: -1, rules: [] };

function activeRule(operation) {
    let stat;
    try {
        stat = statSync('/telemetry/rules.json');
    } catch {
        return null;
    }
    if (stat.mtimeMs !== rulesCache.mtime) {
        try {
            const parsed = JSON.parse(readFileSync('/telemetry/rules.json', 'utf8'));
            rulesCache = {
                mtime: stat.mtimeMs,
                rules: Array.isArray(parsed) ? parsed.filter(item => item && typeof item.until === 'number') : [],
            };
        } catch {
            return null;
        }
    }
    const now = Date.now() / 1000;
    const rule = rulesCache.rules.find(item => item.until > now
        && Array.isArray(item.operations) && item.operations.includes(operation));
    return rule || null;
}

function socketOperation([name, argument]) {
    if (name === 'device-values' && argument?.cmd === 'set') return 'tag_write';
    if (name === 'device-enable') return 'device_control';
    if (name === 'daq-query') return 'historian_query';
    return null;
}

function verifiedAdmin(token, verify, users, adminGroups) {
    if (typeof token !== 'string' || !token || token.length > 8192) return false;
    try {
        const claims = verify(token);
        if (typeof claims?.id !== 'string' || claims.id === 'guest' || !Number.isFinite(claims.exp)) return false;
        const account = users.getUserCache(claims.id);
        if (!account) return false;
        const groups = Array.isArray(account.groups) ? account.groups : [account.groups];
        return groups.some(group => adminGroups.includes(group));
    } catch {
        return false;
    }
}

function roleOf(token, users, auth) {
    const jwt = createRequire('/app/server/package.json')('jsonwebtoken');
    return verifiedAdmin(token, value => jwt.verify(value, auth.secretCode, { algorithms: ['HS256'] }),
        users, auth.adminGroups) ? 'administrator' : 'unprivileged';
}

const OP_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

// Factory controls listed here run in observation: the effect happens and is
// recorded, and only an incident turns them into enforcement.
const OBSERVE = new Set((process.env.IMMUNE_FUXA_PROTECTED_OBSERVE || '')
    .split(',').map(item => item.trim()).filter(Boolean));

function opIdOf(value) {
    return typeof value === 'string' && OP_ID.test(value) ? value : randomUUID();
}

function append(entry) {
    try {
        appendFileSync('/telemetry/events.jsonl', JSON.stringify(entry) + '\n', { mode: 0o600 });
    } catch {
        console.error('Inmune: structured policy telemetry unavailable');
    }
}

function recordDecision(reason, decision, context = {}) {
    append({
        id: opIdOf(context.id), type: 'policy_decision',
        revision: process.env.IMMUNE_FUXA_REVISION, reason, decision,
        ...(context.role ? { role: context.role } : {}),
        ...(context.session ? { session: context.session } : {}),
    });
}

// Session containment runs inside the server, with the session already
// authenticated. It restricts the denied operations for the session and never
// the ordinary HMI reads.
const containment = createContainment({
    emit: (type, payload) => append({
        id: randomUUID(), type, revision: process.env.IMMUNE_FUXA_REVISION, ...payload,
    }),
});

function sessionOfSocket(socket) {
    const sid = typeof socket?.id === 'string' && socket.id.length <= 64 ? socket.id : '';
    return 'sid:' + (sid || 'anonymous');
}

async function authorize(operation, token, users, auth, context = {}) {
    // Incident containment rule: 'role' scope denies every non-admin session,
    // 'session' scope denies only the offending session. Administrators keep
    // working either way, so containment never takes the plant down.
    const rule = activeRule(operation);
    if (rule) {
        let applies = true;
        if (rule.scope === 'session') {
            applies = typeof context.session === 'string' && context.session === rule.session;
        } else if (rule.require_role) {
            let role = 'unprivileged';
            try {
                role = roleOf(token, users, auth);
            } catch {
                role = 'unprivileged';
            }
            applies = role !== rule.require_role;
        }
        if (applies) {
            recordDecision(operation, 'contained', context);
            return 'contained';
        }
    }
    let decision = 'unavailable';
    let role;
    try {
        role = roleOf(token, users, auth);
        decision = await evaluate(operation, role);
        if (decision === 'allow' && roleOf(token, users, auth) !== 'administrator') decision = 'deny';
    } catch {
        decision = 'unavailable';
    }
    let recorded = decision;
    if (OBSERVE.has(operation) && decision === 'deny') {
        // Observation before the effect: the operation goes through and the
        // reached effect is the evidence Inmune turns into an incident.
        recorded = 'observed';
        decision = 'observed';
    }
    recordDecision(operation, recorded, { ...context, role });
    return decision;
}

function protectSocket(socket, users, auth) {
    socket.use(async (packet, next) => {
        const operation = socketOperation(packet);
        if (!operation) return next();
        const session = sessionOfSocket(socket);
        if (containment.check(session, operation)) {
            recordDecision(operation, 'contained', { session });
            return next(new Error('Unauthorized operation'));
        }
        const decision = await authorize(operation, socket.handshake.query.token, users, auth, { session });
        if (decision === 'deny') {
            containment.observe(session, operation);
            return next(new Error('Unauthorized operation'));
        }
        if (decision === 'observed') return next();
        if (decision === 'contained') return next(new Error('Unauthorized operation'));
        if (decision !== 'allow') return next(new Error('Authorization unavailable'));
        next();
    });
}

async function protectScheduler(req, res, next, runtime, auth) {
    const token = req.headers['x-access-token'];
    const session = tokenKey(token);
    const context = { id: req.headers['x-immune-op-id'], session };
    if (containment.check(session, 'scheduler_authorization')) {
        recordDecision('scheduler_authorization', 'contained', context);
        return res.sendStatus(403);
    }
    const decision = await authorize('scheduler_authorization', token, runtime.users, auth, context);
    if (decision === 'deny') {
        containment.observe(session, 'scheduler_authorization');
        return res.sendStatus(403);
    }
    if (decision === 'observed') return next();
    if (decision === 'contained') return res.sendStatus(403);
    if (decision !== 'allow') return res.sendStatus(503);
    next();
}

module.exports = {
    protectScheduler, protectSocket, socketOperation, verifiedAdmin, containment, tokenKey,
};
