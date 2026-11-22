'use strict';

const path = require('node:path');
const { Worker } = require('node:worker_threads');

const MAX_PENDING = 128;

function createEvaluator({ entry = path.join(__dirname, 'policy-worker.cjs'), timeout = 750 } = {}) {
    let worker;
    let nextId = 0;
    const pending = new Map();

    function settle(id, decision) {
        const request = pending.get(id);
        if (!request) return;
        pending.delete(id);
        clearTimeout(request.timer);
        request.resolve(decision);
        if (pending.size === 0) worker?.unref();
    }

    function start() {
        const instance = new Worker(entry, { resourceLimits: { maxOldGenerationSizeMb: 16 } });
        worker = instance;
        const failed = () => {
            if (worker !== instance) return;
            worker = undefined;
            for (const id of pending.keys()) settle(id, 'unavailable');
        };
        instance.on('message', ({ id, decision }) => {
            if (worker !== instance) return;
            settle(id, decision === 'allow' || decision === 'deny' ? decision : 'unavailable');
        });
        instance.on('error', failed);
        instance.on('exit', failed);
        instance.unref();
    }

    return (operation, role) => {
        if (pending.size >= MAX_PENDING) return Promise.resolve('unavailable');
        try {
            if (!worker) start();
        } catch {
            return Promise.resolve('unavailable');
        }
        const id = ++nextId;
        worker.ref();
        return new Promise(resolve => {
            const timer = setTimeout(() => settle(id, 'unavailable'), timeout);
            pending.set(id, { resolve, timer });
            try {
                worker.postMessage({ id, operation, role });
            } catch {
                settle(id, 'unavailable');
            }
        });
    };
}

module.exports = { createEvaluator };
