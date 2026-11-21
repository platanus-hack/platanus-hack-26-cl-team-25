'use strict';

const fs = require('node:fs');
const path = require('node:path');

const storage = require('/app/server/runtime/project/prjstorage');
const viewId = 'v_estacion_delta';
const measures = {
    level: { id: 'TK101_LEVEL', label: 'Nivel', init: 72, value: '72 %', x: 739, y: 244, unit: ' %' },
    temperature: { id: 'TK101_TEMP', label: 'Temperatura', init: 24.8, value: '24.8 °C', x: 739, y: 312, unit: ' °C' },
    flow: { id: 'FT101_FLOW', label: 'Caudal', init: 37, value: '37 m³/h', x: 739, y: 380, unit: ' m³/h' },
    pump: { id: 'P101_STATE', label: 'Bomba', init: 'En marcha', x: 739, y: 449 },
    alarm: { id: 'TK101_ALARM', label: 'Nivel alto', init: 'Normal', x: 979, y: 565, align: 'end' },
};

async function seedPlant(workDir) {
    const { GENERAL, DEVICES, VIEWS, ALARMS } = storage.TableType;
    const tags = {};
    const items = {};
    let svg = fs.readFileSync(path.join(__dirname, 'plant.svg'), 'utf8');
    for (const [key, measure] of Object.entries(measures)) {
        const { id, label, init, value, x, y, align = 'start', unit } = measure;
        tags[id] = { id, name: label, type: typeof init, init };
        const itemId = 'VAL_' + id;
        const property = { events: [], variable: label, variableId: id, variableSrc: 'FUXA',
            ranges: unit ? [{ type: 'unit', text: unit }] : [] };
        items[itemId] = { id: itemId, name: label, type: 'svg-ext-value', label: 'Value', property };
        svg = svg.replace('{{' + key + '}}',
            '<g id="' + itemId + '" type="svg-ext-value"><text id="' + itemId + '_text" x="' + x +
            '" y="' + y + '" text-anchor="' + align + '" font-size="22" font-weight="650" fill="#132c35">' +
            (value || init) + '</text></g>');
    }
    await storage.init({ workDir }, console);
    try {
        await storage.setSections([
            { table: GENERAL, name: 'version', value: '1.02' },
            { table: GENERAL, name: 'name', value: 'Estación Delta' },
            { table: GENERAL, name: 'layout', value: { start: viewId, header: {},
                navigation: { mode: 'fix', type: 'inline', items: [{ icon: 'home', view: viewId, link: '', text: 'Operación' }] } } },
            { table: DEVICES, name: '0', value: { id: '0', name: 'FUXA', type: 'FuxaServer', enabled: true,
                property: {}, tags } },
            { table: VIEWS, name: viewId, value: { id: viewId, name: 'Operación',
                profile: { width: 1040, height: 625, bkcolor: '#eef2f2ff' }, items, variables: {}, svgcontent: svg } },
            { table: ALARMS, name: 'TK-101 Nivel alto', value: { name: 'TK-101 Nivel alto',
                property: { variableId: measures.level.id }, high: { enabled: true, min: 85, max: 100,
                    checkdelay: 1, timedelay: 0, text: 'Nivel alto en TK-101', group: 'Trasiego',
                    ackmode: 'alarm.ack-active', color: '#ffffff', bkcolor: '#9b3425' } } },
        ]);
    } finally {
        storage.close();
    }
}

function runPlant(devices) {
    let tick = 0;
    async function sample() {
        try {
            if (!devices.getDeviceValue('0', measures.level.id)) return;
            tick += 1;
            const phase = tick % 40;
            const level = 70 + (phase <= 20 ? phase : 40 - phase);
            const values = {
                level, temperature: Number((24.8 + 1.2 * Math.sin(phase / 6)).toFixed(1)),
                flow: phase < 26 ? 36 + Math.round(3 * Math.sin(phase / 3)) : 0,
                pump: phase < 26 ? 'En marcha' : 'En espera',
                alarm: level >= 85 ? 'Nivel alto' : 'Normal',
            };
            for (const [key, value] of Object.entries(values)) {
                await devices.setDeviceValue('0', measures[key].id, value);
            }
        } catch (error) {
            console.error('Estación Delta: ' + error.message);
        } finally {
            setTimeout(sample, 2000).unref();
        }
    }
    setTimeout(sample, 2000).unref();
}

module.exports = { seedPlant, runPlant };
