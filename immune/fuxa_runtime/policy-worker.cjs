'use strict';

const { parentPort } = require('node:worker_threads');
const operations = new Set(['tag_write', 'device_control', 'historian_query', 'scheduler_authorization']);

parentPort.on('message', ({ id, operation, role }) => {
    const decision = operations.has(operation) && role === 'administrator' ? 'allow' : 'deny';
    parentPort.postMessage({ id, decision });
});
