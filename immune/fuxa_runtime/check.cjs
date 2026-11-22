'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const vm = require('node:vm');
const monitor = require('./observe.cjs');

const enforced = (process.argv[2] || '').split(',');
const server = process.env.IMMUNE_FUXA_CHECK_ROOT || '/app/server';
const files = [
    ['api/index.js', 'settings.write', 'write-settings'],
    ['api/scripts/index.js', 'system-function.run', 'dispatch-system-function'],
];
const events = [];
const print = console.log;
console.log = line => events.push(JSON.parse(line.slice('IMMUNE_FUXA '.length)));
try {
    for (const [file, operation, boundary] of files) {
        const source = fs.readFileSync(server + '/' + file, 'utf8');
        const guard = /^ *if \(!immuneMonitor\.authorize\((.+), req, runtime\)\) return res\.status\(403\)\.end\(\);$/m.exec(source);
        assert.ok(guard, operation + ' is wired to the effect');
        const actual = JSON.parse('[' + guard[1] + ']');
        const mode = enforced.includes(operation) ? 'enforce' : 'observe';
        assert.deepEqual(actual, [operation, mode]);
        const evaluate = vm.runInNewContext(
            '(immuneMonitor, req, runtime, res) => {\n' + guard[0] + '\nreturn "continued";\n}',
        );
        const runtime = {
            settings: { secureEnabled: true },
            users: { getUserCache: id => ({ groups: id === 'administrator' ? 255 : 2 }) },
        };
        for (const [userId, role] of [['administrator', 'admin'], ['viewer', 'member'], [null, 'anonymous']]) {
            const req = { userId };
            const res = Object.assign(new EventEmitter(), {
                statusCode: 200,
                status(code) { this.statusCode = code; return this; },
                end() { this.emit('finish'); },
            });
            monitor.http(operation)(req, res, () => {});
            const start = events.length;
            const allowed = role === 'admin' || mode === 'observe';
            assert.equal(evaluate(monitor, req, runtime, res), allowed ? 'continued' : undefined);
            const evidence = events[start];
            assert.equal(evidence.role, role);
            assert.equal(evidence.boundary, boundary);
            assert.equal(evidence.decision, mode === 'observe' ? 'observed' : allowed ? 'allowed' : 'blocked');
            assert.equal(res.statusCode, allowed ? 200 : 403);
        }
    }
} finally {
    console.log = print;
}
