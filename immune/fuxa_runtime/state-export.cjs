'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { DatabaseSync, backup } = require('node:sqlite');

async function exportState(source, target) {
    for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
        if (entry.name === '_logs' || /\.db-(?:wal|shm|journal)$/.test(entry.name)) continue;
        const from = path.join(source, entry.name);
        const to = path.join(target, entry.name);
        if (entry.isDirectory()) {
            fs.mkdirSync(to, { mode: 0o700 });
            await exportState(from, to);
        } else if (entry.isFile() && entry.name.endsWith('.db')) {
            const db = new DatabaseSync(from, { readOnly: true });
            try {
                await backup(db, to);
            } finally {
                db.close();
            }
        } else if (entry.isFile()) {
            fs.copyFileSync(from, to);
            fs.chmodSync(to, fs.statSync(from).mode & 0o777);
        } else {
            throw new Error('Unexpected file type in demo state');
        }
    }
}

async function main() {
    const snapshot = fs.mkdtempSync('/tmp/immune-state-');
    try {
        await exportState('/lab', snapshot);
        const appData = path.join(snapshot, '_appdata');
        for (const file of ['settings.js', 'project.fuxap.db']) {
            if (!fs.statSync(path.join(appData, file)).isFile()) throw new Error('Incomplete app state');
        }
        fs.writeFileSync(path.join(appData, '.initialized'), '', { mode: 0o600 });
        const archived = spawnSync('tar', ['-C', snapshot, '-cf', '-', '.'], { stdio: ['ignore', 'inherit', 'inherit'] });
        if (archived.status !== 0) throw new Error('State archive failed');
    } finally {
        fs.rmSync(snapshot, { recursive: true, force: true });
    }
}

main().catch(() => {
    console.error('Inmune: error al capturar el estado de FUXA');
    process.exitCode = 1;
});
