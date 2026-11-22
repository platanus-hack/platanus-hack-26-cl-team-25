'use strict';

/*
 * Session containment for FUXA. When the policy denies a protected operation for
 * one session repeatedly inside the window, the session receives a temporary
 * restriction over the affected operations. Ordinary reads stay available: the
 * restriction only covers the denied operations. Restrictions expire on their
 * own and every transition is emitted as structured telemetry:
 *   {type: 'session_restricted', session, operations, reason, expires}
 *   {type: 'session_released', session, reason: 'ttl'}
 * Keys are opaque (Socket.IO sid or a token digest); no credentials or contents
 * are ever stored.
 */

const DEFAULTS = { threshold: 3, window: 120_000, ttl: 900_000 };

function tokenKey(token) {
    return createDigest('token', token);
}

function createDigest(prefix, value) {
    const { createHash } = require('node:crypto');
    return prefix + ':' + createHash('sha256').update(String(value)).digest('hex').slice(0, 16);
}

function createContainment({
    threshold = DEFAULTS.threshold, window = DEFAULTS.window, ttl = DEFAULTS.ttl,
    now = () => Date.now(), emit = () => {},
} = {}) {
    const denied = new Map();      // key -> [timestamps ms]
    const restricted = new Map();  // key -> {operations:Set, reason, expires, ts}

    function expired(record) {
        return now() >= record.expires;
    }

    function releaseExpired() {
        for (const [key, record] of restricted) {
            if (expired(record)) {
                restricted.delete(key);
                emit('session_released', { session: key, reason: 'ttl' });
            }
        }
    }

    function isRestricted(key, operation) {
        const record = restricted.get(key);
        if (!record) return false;
        if (expired(record)) {
            restricted.delete(key);
            emit('session_released', { session: key, reason: 'ttl' });
            return false;
        }
        return !operation || record.operations.has(operation);
    }

    function observe(key, operation) {
        const existing = restricted.get(key);
        if (existing && !expired(existing)) {
            if (!existing.operations.has(operation)) {
                existing.operations.add(operation);
                emit('session_restricted', {
                    session: key,
                    operations: [...existing.operations],
                    reason: existing.reason,
                    expires: Math.round(existing.expires / 1000),
                });
            }
            return true;
        }
        if (existing) {
            restricted.delete(key);
            emit('session_released', { session: key, reason: 'ttl' });
        }
        const stamps = (denied.get(key) || []).filter(stamp => now() - stamp <= window);
        stamps.push(now());
        denied.set(key, stamps);
        if (stamps.length < threshold) return false;
        denied.delete(key);
        const record = {
            operations: new Set([operation]),
            reason: 'repeated-denied-operations',
            expires: now() + ttl,
            ts: now(),
        };
        restricted.set(key, record);
        emit('session_restricted', {
            session: key,
            operations: [...record.operations],
            reason: record.reason,
            expires: Math.round(record.expires / 1000),
        });
        return true;
    }

    function check(key, operation) {
        releaseExpired();
        return isRestricted(key, operation);
    }

    function release(session) {
        if (restricted.delete(session)) {
            emit('session_released', { session, reason: 'ttl' });
            return true;
        }
        return false;
    }

    function active() {
        releaseExpired();
        return [...restricted.entries()].map(([session, record]) => ({
            session, operations: [...record.operations], reason: record.reason,
            expires: Math.round(record.expires / 1000),
        }));
    }

    return { check, observe, release, active };
}

module.exports = { createContainment, tokenKey, DEFAULTS };
