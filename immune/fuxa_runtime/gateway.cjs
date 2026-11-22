'use strict';

const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const { randomUUID } = require('node:crypto');
const { pipeline } = require('node:stream');
const { watchRequest } = require('./gateway-signals.cjs');

const knownRoutes = new Map(JSON.parse(process.env.IMMUNE_FUXA_ROUTES || '[]')
    .concat(['/', '/home', '/editor', '/device', '/rodevice', '/users', '/view', '/favicon.ico'])
    .map(route => [route.toLowerCase(), route]));

function routeLabel(url) {
    const pathname = url.split(/[?#]/, 1)[0].replace(/\/$/, '').toLowerCase() || '/';
    if (knownRoutes.has(pathname)) return knownRoutes.get(pathname);
    if (pathname === '/socket.io' || pathname.startsWith('/socket.io/')) return '/socket.io';
    if (pathname.startsWith('/api/')) return '/api/*';
    if (pathname.startsWith('/home/')) return '/home/:vista';
    if (pathname.startsWith('/assets/') || /\.(?:js|css|woff2?|ttf|svg|png|ico)$/.test(pathname)) return '/assets/*';
    return '/otras-rutas';
}

function requestLog(request, transport) {
    const started = performance.now();
    const path = routeLabel(request.url);
    const signal = watchRequest(request, path, transport);
    // The gateway mints the operation identifier and forwards it upstream, so the
    // server-side verdict (observe/policy) and this request share one id.
    const id = randomUUID();
    const sessionId = sessionIdOf(request, path);
    let recorded = false;
    const record = (status, blocked = false) => {
        if (recorded) return;
        recorded = true;
        const reason = signal();
        console.log(JSON.stringify({
            type: 'fuxa.request', id, ts: Date.now() / 1000, method: request.method,
            path, status, transport, ms: Math.round(performance.now() - started),
            ...(sessionId ? { sid: sessionId } : {}),
            ...(reason ? { reason } : {}),
            ...(blocked ? { blocked: true } : {}),
        }));
    };
    record.id = id;
    return record;
}

function sessionIdOf(request, path) {
    if (path !== '/socket.io') return null;
    const sid = new URLSearchParams(request.url.split('?')[1]).get('sid');
    return typeof sid === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(sid) ? sid : null;
}

function active() {
    const target = fs.readFileSync('/run/immune/active', 'utf8').trim();
    if (!/^immune-fuxa-[a-f0-9]{12}-r-[a-f0-9]{12}$/.test(target)) {
        throw new Error('Invalid upstream name');
    }
    return target;
}

const gateway = http.createServer((request, response) => {
    // The gateway only marks suspicious requests. Blocking belongs to the server
    // policy: an observed violation opens an incident, a containment rule holds
    // it while the patch validates, and the patched revision enforces it.
    const record = requestLog(request, 'http');
    response.once('finish', () => record(response.statusCode));
    response.once('close', () => record(null));
    const unavailable = () => {
        if (response.headersSent) response.destroy();
        else response.writeHead(503).end();
    };
    try {
        const hostname = active();
        const upstream = http.request({
            hostname, port: 1881, method: request.method, path: request.url,
            headers: { ...request.headers, 'x-immune-op-id': record.id },
        }, incoming => {
            response.writeHead(incoming.statusCode, {
                ...incoming.headers, 'x-immune-fuxa-revision': hostname.split('-r-')[1],
            });
            pipeline(incoming, response, () => {});
        });
        upstream.on('error', unavailable);
        upstream.setTimeout(30_000, () => upstream.destroy());
        request.on('aborted', () => upstream.destroy());
        request.pipe(upstream);
    } catch {
        unavailable();
    }
});

gateway.on('upgrade', (request, client, head) => {
    const record = requestLog(request, 'websocket');
    client.once('close', () => record(null));
    let upstream;
    try {
        upstream = net.connect(1881, active());
    } catch {
        client.destroy();
        return;
    }
    upstream.on('error', () => client.destroy());
    client.on('error', () => upstream.destroy());
    client.on('close', () => upstream.destroy());
    upstream.on('close', () => client.destroy());
    upstream.once('connect', () => {
        let prefix = '';
        function statusLine(chunk) {
            prefix += chunk.subarray(0, 13 - prefix.length).toString('ascii');
            if (prefix.length < 13) return;
            upstream.removeListener('data', statusLine);
            const status = /^HTTP\/\d\.\d (\d{3})/.exec(prefix);
            record(status ? Number(status[1]) : null);
        }
        upstream.on('data', statusLine);
        const headers = [];
        for (let index = 0; index < request.rawHeaders.length; index += 2) {
            headers.push(request.rawHeaders[index] + ': ' + request.rawHeaders[index + 1]);
        }
        upstream.write([request.method + ' ' + request.url + ' HTTP/' + request.httpVersion, ...headers, '', ''].join('\r\n'));
        if (head.length) upstream.write(head);
        client.pipe(upstream).pipe(client);
    });
});

gateway.listen(1881, '0.0.0.0');
