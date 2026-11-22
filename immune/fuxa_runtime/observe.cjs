'use strict';

const { randomUUID } = require('node:crypto');
const { appendFileSync } = require('node:fs');
const requests = new WeakMap();
const revision = process.env.IMMUNE_FUXA_REVISION;
const effects = {
    'settings.write': 'write-settings',
    'system-function.run': 'dispatch-system-function',
};

function emit(type, context, evidence) {
    const entry = JSON.stringify({ type, revision, ...context, ...evidence });
    if (!revision) {
        console.log('IMMUNE_FUXA ' + entry);
        return;
    }
    try {
        appendFileSync('/telemetry/events.jsonl', entry + '\n', { mode: 0o600 });
    } catch {
        console.error('Immune: structured telemetry unavailable');
    }
}

const OP_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

// The gateway forwards x-immune-op-id so this request and its verdict share one id.
function opIdOf(req) {
    const header = req && req.headers ? req.headers['x-immune-op-id'] : null;
    return typeof header === 'string' && OP_ID.test(header) ? header : randomUUID();
}

function http(operation) {
    return function observeRequest(req, res, next) {
        const context = { id: opIdOf(req), operation };
        requests.set(req, context);
        res.once('finish', () => {
            if (res.statusCode === 401 || res.statusCode === 403) {
                emit('http', context, { status: res.statusCode });
            }
        });
        next();
    };
}

function roleOf(req, runtime) {
    if (runtime.settings.secureEnabled !== true) return 'unknown';
    if (req.apiKey) return 'admin'; // Set by FUXA only after verifying a stored API key.
    if (!req.userId || req.userId === 'guest' || req.tokenExpired) return 'anonymous';
    const account = runtime.users.getUserCache(req.userId);
    if (!account) return 'unknown';
    const groups = Array.isArray(account.groups) ? account.groups : [account.groups];
    const administrator = require(process.env.IMMUNE_FUXA_AUTH_HELPER || '/app/server/api/jwt-helper.js');
    return groups.some(group => administrator.adminGroups.includes(group)) ? 'admin' : 'member';
}

function authorize(operation, mode, req, runtime) {
    const context = requests.get(req) || { id: opIdOf(req), operation };
    let role = 'unknown';
    try {
        role = roleOf(req, runtime);
    } catch {
        // The observer cannot make an authorization decision when identity lookup fails.
    }
    const allowed = mode === 'observe' || role === 'admin';
    emit('effect', context, {
        boundary: effects[operation] || 'write-route',
        role,
        decision: mode === 'observe' ? 'observed' : allowed ? 'allowed' : 'blocked',
    });
    return allowed;
}

// Generic pre-effect guard for declared HTTP write routes. The candidate revision
// is the only place where the mode switches from observe to enforce.
function routeGuard(operation, mode, req, res, next, runtime) {
    const context = { id: opIdOf(req), operation };
    let role = 'unknown';
    try {
        role = roleOf(req, runtime);
    } catch {
        // Without a verifiable identity the guard stops the effect.
    }
    const allowed = mode === 'observe' || role === 'admin';
    emit('effect', context, { boundary: 'write-route', role,
        decision: mode === 'observe' ? 'observed' : allowed ? 'allowed' : 'blocked' });
    if (allowed) return next();
    res.status(403).end();
}

module.exports = { http, authorize, routeGuard, opIdOf };
