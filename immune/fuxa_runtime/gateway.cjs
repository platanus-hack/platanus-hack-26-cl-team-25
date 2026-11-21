'use strict';

const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const { pipeline } = require('node:stream');

function active() {
    const target = fs.readFileSync('/run/immune/active', 'utf8').trim();
    if (!/^immune-fuxa-[a-f0-9]{12}-r-[a-f0-9]{12}$/.test(target)) {
        throw new Error('Invalid upstream name');
    }
    return target;
}

const gateway = http.createServer((request, response) => {
    const unavailable = () => {
        if (response.headersSent) response.destroy();
        else response.writeHead(503).end();
    };
    try {
        const hostname = active();
        const upstream = http.request({
            hostname, port: 1881, method: request.method, path: request.url, headers: request.headers,
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
