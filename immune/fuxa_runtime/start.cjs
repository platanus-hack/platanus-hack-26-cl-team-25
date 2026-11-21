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
fs.writeFileSync(
    '/lab/_appdata/settings.js',
    'module.exports = { ...require("/app/server/settings.default.js"), ...' +
        JSON.stringify(settings) + ' };\n',
    { mode: 0o600, flag: 'wx' },
);
seedPlant('/lab/_appdata').then(() => {
    process.env.userDir = '/lab';
    process.argv = [process.execPath, '/app/server/main.js', '--port', '1881'];
    require('/app/server/main.js');
    runPlant(require('/app/server/runtime').devices);
}).catch(error => {
    console.error('Estación Delta: ' + (error?.message || 'no se pudo cargar el proyecto'));
    process.exitCode = 1;
});
