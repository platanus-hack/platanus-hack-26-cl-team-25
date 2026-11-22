'use strict';

const fs = require('node:fs');
const { randomBytes } = require('node:crypto');
const { seedPlant, runPlant } = require('./plant.cjs');

fs.mkdirSync('/lab/_appdata', { recursive: true });
const settings = {
    secureEnabled: true,
    secureOnlyEditor: false,
    nodeRedEnabled: false,
    swaggerEnabled: false,
    secretCode: randomBytes(48).toString('hex'),
};
const settingsFile = '/lab/_appdata/settings.js';
const ready = '/lab/_appdata/.initialized';
if (!fs.existsSync(settingsFile)) {
    fs.writeFileSync(
        settingsFile,
        'module.exports = { ...require("/app/server/settings.default.js"), ...' +
            JSON.stringify(settings) + ' };\n',
        { mode: 0o600, flag: 'wx' },
    );
}

async function start() {
    if (!fs.existsSync(ready)) {
        await seedPlant('/lab/_appdata');
        fs.writeFileSync(ready, '', { mode: 0o600, flag: 'wx' });
    }
    process.env.userDir = '/lab';
    process.argv = [process.execPath, '/app/server/main.js', '--port', '1881'];
    require('/app/server/main.js');
    runPlant(require('/app/server/runtime').devices);
}

start().catch(error => {
    console.error('Estación Delta: ' + (error?.message || 'no se pudo cargar el proyecto'));
    process.exitCode = 1;
});
