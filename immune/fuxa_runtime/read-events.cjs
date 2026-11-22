'use strict';

const fs = require('node:fs');
const cursor = Number(process.argv[2]);
if (!Number.isSafeInteger(cursor) || cursor < 0) throw new Error('Invalid telemetry cursor');
const file = '/telemetry/events.jsonl';
if (!fs.existsSync(file)) {
    process.stdout.write(JSON.stringify({ offset: 0, entries: [] }));
} else {
    const handle = fs.openSync(file, 'r');
    try {
        const start = cursor <= fs.fstatSync(handle).size ? cursor : 0;
        const batch = Buffer.alloc(64 * 1024);
        const length = fs.readSync(handle, batch, 0, batch.length, start);
        const end = batch.subarray(0, length).lastIndexOf(10) + 1;
        const entries = end ? batch.subarray(0, end - 1).toString('utf8').split('\n') : [];
        process.stdout.write(JSON.stringify({ offset: start + end, entries }));
    } finally {
        fs.closeSync(handle);
    }
}
