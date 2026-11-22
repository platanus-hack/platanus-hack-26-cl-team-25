// Records the demo as one 1920x1080 video: the live dashboard on the left, the attacker's terminal on the right.
//
//   NODE_PATH=<dir with playwright-core> node deploy/record_demo.js --log ATTACKER_LOG --out DIR
//        [--dashboard http://127.0.0.1:8090] [--max-seconds 600] [--chromium PATH]
//
// It stops when ATTACKER_LOG.done exists (deploy/record_demo.sh creates it when the attacker exits) or after
// --max-seconds, then writes DIR/demo.webm and screenshots of the final dashboard at 1920x1080, 1280x720 and
// 1024x768 (projector sizes). Driven by deploy/record_demo.sh.
'use strict';
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright-core');

function arg(name, dflt) {
  const i = process.argv.indexOf('--' + name);
  return i > 0 ? process.argv[i + 1] : dflt;
}

const LOG = arg('log');
const OUT = arg('out');
const DASH = arg('dashboard', 'http://127.0.0.1:8090');
const MAX = parseFloat(arg('max-seconds', '600'));
const CHROMIUM = arg('chromium', undefined);
const PANE = 660;

// The dashboard's CSP (style-src 'self') blocks <style> elements and style attributes, so the pane is built with
// DOM nodes and styled through the CSSOM (element.style), which the CSP allows.
const COLORS = { '32': ['#4ade80', ''], '33': ['#facc15', ''], '31;1': ['#f87171', '700'], '2': ['#7b8594', ''],
  '1': ['', '700'] };
function segments(line) {
  const out = [];
  let cur = null;
  for (const part of line.split(/(\x1b\[[0-9;]*m)/)) {
    const m = /^\x1b\[([0-9;]*)m$/.exec(part);
    if (m) { cur = m[1] === '0' ? null : (COLORS[m[1]] || null); continue; }
    if (part) out.push([part, cur ? cur[0] : '', cur ? cur[1] : '']);
  }
  return out;
}

async function pane(page) {
  await page.evaluate((w) => {
    if (document.getElementById('rec-term')) return;
    document.documentElement.style.marginRight = w + 'px';
    const d = document.createElement('div');
    d.id = 'rec-term';
    Object.assign(d.style, { position: 'fixed', top: '0', right: '0', width: w + 'px', height: '100vh',
      background: '#0b0d10', borderLeft: '1px solid #2a2f36', color: '#d6dae0', zIndex: '99999',
      display: 'flex', flexDirection: 'column', font: '13px/1.45 ui-monospace,Menlo,Consolas,monospace' });
    const h = document.createElement('div');
    h.textContent = 'Atacante · python -m sim.attacker';
    Object.assign(h.style, { padding: '12px 16px', font: '600 15px system-ui,sans-serif', color: '#9aa4b2',
      borderBottom: '1px solid #2a2f36' });
    const b = document.createElement('div');
    b.id = 'rec-body';
    Object.assign(b.style, { padding: '10px 14px', overflow: 'hidden', whiteSpace: 'pre', flex: '1',
      display: 'flex', flexDirection: 'column', justifyContent: 'flex-end' });
    d.appendChild(h); d.appendChild(b);
    document.body.appendChild(d);
  }, PANE);
}

async function fill(page, lines) {
  await page.evaluate((rows) => {
    const b = document.getElementById('rec-body');
    if (!b) return;
    b.textContent = '';
    for (const segs of rows) {
      const row = document.createElement('div');
      for (const [t, color, weight] of segs) {
        const s = document.createElement('span');
        s.textContent = t;
        if (color) s.style.color = color;
        if (weight) s.style.fontWeight = weight;
        row.appendChild(s);
      }
      if (!segs.length) row.textContent = ' ';
      b.appendChild(row);
    }
  }, lines);
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch({ executablePath: CHROMIUM, args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 },
    recordVideo: { dir: OUT, size: { width: 1920, height: 1080 } } });
  const page = await ctx.newPage();
  await page.goto(DASH, { waitUntil: 'domcontentloaded' });
  const t0 = Date.now();
  while ((Date.now() - t0) / 1000 < MAX) {
    await pane(page).catch(() => {});
    let text = '';
    try { text = fs.readFileSync(LOG, 'utf8'); } catch (e) { /* not started yet */ }
    await fill(page, text.split('\n').slice(-44).map(segments)).catch(() => {});
    if (fs.existsSync(LOG + '.done')) { await page.waitForTimeout(8000); break; }
    await page.waitForTimeout(400);
  }
  await page.screenshot({ path: path.join(OUT, 'final-split-1920x1080.png') });
  const video = page.video();
  await ctx.close();
  if (video) fs.renameSync(await video.path(), path.join(OUT, 'demo.webm'));
  for (const [w, h] of [[1920, 1080], [1280, 720], [1024, 768]]) {
    const c = await browser.newContext({ viewport: { width: w, height: h } });
    const p = await c.newPage();
    await p.goto(DASH, { waitUntil: 'domcontentloaded' });
    await p.waitForTimeout(4000);
    await p.screenshot({ path: path.join(OUT, 'dashboard-' + w + 'x' + h + '.png') });
    await c.close();
  }
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
