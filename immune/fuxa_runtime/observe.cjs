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
        console.error('Inmune: structured telemetry unavailable');
    }
}

function http(operation) {
    return function observeRequest(req, res, next) {
        const context = { id: randomUUID(), operation };
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
    const context = requests.get(req) || { id: randomUUID(), operation };
    let role = 'unknown';
    try {
        role = roleOf(req, runtime);
    } catch {
        // The observer cannot make an authorization decision when identity lookup fails.
    }
    const allowed = mode === 'observe' || role === 'admin';
    emit('effect', context, {
        boundary: effects[operation],
        role,
        decision: mode === 'observe' ? 'observed' : allowed ? 'allowed' : 'blocked',
    });
    return allowed;
}

module.exports = { http, authorize };
