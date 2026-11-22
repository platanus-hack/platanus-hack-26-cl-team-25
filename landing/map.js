// The instruments share the same chassis, light direction and connector height.
const chassis = (y, deep = 9) => `
  <g transform="translate(0 ${y})">
    <path class="face" d="m-41 -4 25 12 57 -12v${deep}L-16 ${8 + deep}l-25 -12Z"/>
    <path class="side" d="m-41 -4 25 12v${deep}l-25 -12Z"/>
    <path class="lid" d="m-41 -4 57 -12 25 12-57 12Z"/>
    <path class="seam" d="m-11 11 27 -6"/>
    <path class="light" d="m25 3 6 -1m3 -1 3 -.6"/>
  </g>`;

const instruments = {
  request: `
    ${chassis(7, 3)}
    <path class="side" d="m-7 4 1 -8 8 -2 2 7 8 4-15 3-10 -4Z"/>
    <g transform="matrix(1,-.19,0,1,0,-10)">
      <rect class="side" x="-36" y="-34" width="72" height="44" rx="4"/>
      <rect class="glass" x="-32" y="-30" width="64" height="36" rx="1.5"/>
      <path class="seam" d="M-32 -22h64"/><path class="light" d="M-28 -26h2m3 0h2m3 0h2"/>
      <g class="web-content"><path class="screen-ink" d="M-25 -15h20v15h-20z"/><path class="display" d="m-23 -3 5 -7 4 4 3 -3 4 6M2 -13h22M2 -7h16M2 -1h10"/></g>
      <g class="web-input"><path class="light" d="m-23 -14 5 4-5 4m9 1h8"/><path class="display" d="M3 -13h20M3 -7h15M3 -1h18"/></g>
    </g>`,
  proxy: `
    ${chassis(4)}${chassis(-9)}${chassis(-22)}
    <g transform="matrix(1,-.21,.85,.42,0,-27)">
      <path class="light" d="M-8 -7h-5V7h5M8 -7h5V7H8"/><circle r="3" class="lamp"/>
    </g>`,
  prod: `
    ${chassis(5)}${chassis(-9)}${chassis(-23)}
    <path d="m-29 -27 41 -9 12 6-41 9Z" fill="url(#vents)"/>
    <path class="light" d="m-35 -8 5 2m-5 12 5 2m-5 -30 5 2"/>`,
  clone: `
    ${chassis(6,5)}
    <path class="guide" d="M-28 2v-19M26 0v-20M-7 6v-18"/>
    <g class="float-cap">${chassis(-18,7)}
      <path class="light" d="m-13 -24 16 -4 10 5-16 4Zm0 0v4l10 5 16 -4v-4"/>
    </g>`,
  rule: `
    ${chassis(7,5)}
    <g transform="matrix(1,-.21,0,1,0,-8)">
      <path class="side" d="m-30 -31 4 -2 57 0v38l-5 2-56 -2Z"/>
      <rect class="face" x="-30" y="-31" width="57" height="37" rx="2"/>
      <path class="mortar" d="M-29 -19h55m-55 12h55m-40 -23v11m19 -11v11m-30 0v12m20 -12v12m-10 0V5m19 -12V5"/>
      <path class="light" d="M-24 -26h7M10 0h10"/><path class="gate-bolt" d="M-29 -13h55"/>
    </g>`,
  patch: `
    ${chassis(7,4)}
    <g transform="matrix(1,-.21,0,1,0,-8)">
      <rect class="side" x="-31" y="-28" width="64" height="36" rx="4"/>
      <rect class="glass" x="-27" y="-24" width="56" height="28" rx="2"/>
      <path class="seam" d="M-23 -8h48"/>
      <path class="light" d="M-23 -9h8l4 -6 5 13 7 -18 5 12h10l4 -4h5"/>
    </g>`,
  review: `
    ${chassis(7,4)}
    <g transform="matrix(1,-.21,0,1,0,-8)">
      <path class="side" d="M-20 -32h33l10 10v29h-43Z"/>
      <path class="lid" d="M-25 -36H9l10 10V4h-44Z"/><path class="seam" d="M9 -36v10h10M-18 -26h14M-18 -20h17M-18 -14h10"/>
      <circle cx="14" cy="-2" r="12" class="glass"/><path class="light checkmark" pathLength="1" d="m8 -2 4 4 8 -9"/>
    </g>`
};

const mapLayouts = {
  wide: {
    box: '0 0 520 365',
    nodes: { request:[78,58], proxy:[260,58], prod:[442,58], clone:[260,180], rule:[78,180], patch:[78,301], review:[260,301] },
    wires: {
      'to-proxy':'M123 62H211', direct:'M306 62H393',
      'to-clone':'M300 70 320 77Q328 80 328 90V155Q328 164 320 168L302 177',
      cleared:'M304 188H428Q442 188 442 174V112',
      'to-rule':'M213 184H125',
      'to-patch':'M40 191 27 199Q18 203 18 213V279Q18 289 27 293L37 298',
      'to-review':'M125 305H211'
    },
    labels: [[347,52,'directa'],[353,129,'aislar'],[400,178,'liberar']]
  },
  compact: {
    box: '0 0 350 472',
    nodes: { request:[82,54], proxy:[266,54], prod:[82,183], clone:[266,183], rule:[266,314], patch:[82,314], review:[184,414] },
    wires: {
      'to-proxy':'M128 57H217',
      direct:'M221 69 169 89Q159 91 159 104V174Q159 186 147 186H130',
      'to-clone':'M305 62 318 67Q326 70 326 80V167Q326 177 316 181L310 183',
      cleared:'M218 186H131',
      'to-rule':'M305 195 318 200Q326 203 326 213V298Q326 308 316 312L310 314',
      'to-patch':'M220 318H130',
      'to-review':'M43 326 33 330Q25 334 25 344V406Q25 418 37 418H136'
    },
    labels: [[131,130,'directa'],[301,131,'aislar']]
  }
};

const stationNames = { request:'Portal web', proxy:'Proxy Immune', prod:'Producción', clone:'App clon', rule:'Contención', patch:'Validaciones', review:'Verificación' };
const mapSvg = document.getElementById('diagram');
mapSvg.querySelector('#stations').innerHTML = Object.entries(instruments).map(([id, art]) => `
  <g class="station" id="${id}" role="button" tabindex="0" aria-label="${stationNames[id]}">
    <rect class="hit-area" x="-61" y="-48" width="122" height="98" rx="9"/>
    <ellipse class="shadow" cy="12" rx="46" ry="10"/>
    <ellipse class="field-ring" cy="9" rx="53" ry="14"/>
    <g class="instrument">${art}</g>
    <text class="station-name" y="43">${stationNames[id]}</text>
    ${id === 'prod' ? '<g id="delivery-stamp" visibility="hidden" aria-hidden="true"><rect x="-51" y="51" width="102" height="22" rx="4"/><text y="66"></text></g>' : ''}
  </g>`).join('');
const compactMap = matchMedia('(max-width: 680px)');
function layoutMap() {
  const layout = compactMap.matches ? mapLayouts.compact : mapLayouts.wide;
  mapSvg.setAttribute('viewBox', layout.box);
  for (const [id, [x,y]] of Object.entries(layout.nodes)) {
    document.getElementById(id).setAttribute('transform', `translate(${x} ${y})`);
  }
  for (const [id, d] of Object.entries(layout.wires)) {
    let path = document.getElementById(id);
    if (!path) {
      path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.id = id;
      mapSvg.querySelector('.wires').append(path);
    }
    path.setAttribute('d', d);
  }
  mapSvg.querySelector('.wire-label').innerHTML = layout.labels.map(([x,y,name]) =>
    `<text x="${x}" y="${y}">${name}</text>`).join('');
}
layoutMap();
