'use strict';

const MAX_POLL_BYTES = 64 * 1024;
const { socketOperation } = require('./policy.cjs');

function* pollingPackets(body, version) {
    if (version === '4') {
        yield* body.split('\x1e');
        return;
    }
    for (let offset = 0; offset < body.length;) {
        const header = /^([0-9]{1,6}):/.exec(body.slice(offset, offset + 7));
        if (!header) return;
        const start = offset + header[0].length;
        offset = start + Number(header[1]);
        if (offset > body.length || offset === start) return;
        yield body.slice(start, offset);
    }
}

function pollingSignal(body, version) {
    for (const packet of pollingPackets(body, version)) {
        const match = /^42(?:\/[^,]+,)?\d*(\[.*\])$/s.exec(packet);
        if (!match) continue;
        let args;
        try {
            args = JSON.parse(match[1]);
        } catch {
            continue;
        }
        const operation = socketOperation(args);
        if (operation) return operation;
    }
    return null;
}

// A scheduler change without a token is suspicious, not blocked here: the
// server policy decides, and an observed violation becomes an incident.
function schedulerWithoutToken(request, path) {
    return path === '/api/scheduler' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)
        && !request.headers['x-access-token']?.trim();
}

function watchRequest(request, path, transport) {
    if (schedulerWithoutToken(request, path)) {
        return () => 'scheduler_without_token';
    }
    if (path !== '/socket.io') return () => null;
    if (transport === 'websocket') return () => 'not_inspected';
    if (request.method !== 'POST') return () => null;

    const query = new URLSearchParams(request.url.split('?')[1]);
    const version = query.get('EIO');
    const encoding = request.headers['content-encoding'];
    const contentType = request.headers['content-type'];
    if (query.get('transport') !== 'polling' || !['3', '4'].includes(version)
        || (encoding && encoding !== 'identity')
        || (contentType && !/^text\/plain(?:\s*;|$)/i.test(contentType))) {
        return () => 'not_inspected';
    }
    const chunks = [];
    let size = 0;
    let signal = 'not_inspected';
    request.on('data', chunk => {
        size += chunk.length;
        if (size <= MAX_POLL_BYTES) chunks.push(chunk);
        else chunks.length = 0;
    });
    request.once('end', () => {
        if (size <= MAX_POLL_BYTES) signal = pollingSignal(Buffer.concat(chunks, size).toString('utf8'), version);
    });
    return () => signal;
}

module.exports = { schedulerWithoutToken, watchRequest };
