// Each scenario describes a local illustration. Selecting one only changes this diagram.
const lookup = id => document.getElementById(id);
const tone = { neutral: 'var(--text)', good: 'var(--acc)', suspect: 'var(--hold)', attack: 'var(--atk)' };

function stage(node, wire, color, title, note) {
  return { node, wire, color, title, note };
}

const incidents = {
  sqli: ['Inyección SQL', 'La entrada cambió la estructura de una consulta SQL.'],
  traversal: ['Acceso a archivos', 'La aplicación intentó leer fuera del directorio permitido.'],
  idor: ['Acceso entre usuarios', 'El observador detectó datos de un propietario distinto.']
};

function scenarioFor(record) {
  const incident = record.incident;
  const stages = [
    stage('request', null, 'neutral', 'Request recibida', 'El portal envía la petición al gateway de Tienda.')
  ];
  if (record.classification === 'suspect') {
    stages.push(stage('proxy', 'to-proxy', 'suspect', 'El proxy deriva la request', 'La entrada sale del perfil esperado. El proxy la envía a la app clon.'));
    if (incident) {
      stages.push(
        stage('clone', 'to-clone', 'attack', incidents[incident.kind][0], incidents[incident.kind][1]),
        stage('rule', 'to-rule', 'suspect', 'Regla de contención activa', 'El pipeline reproduce el efecto y acota la regla a la operación afectada.'),
        stage('patch', 'to-patch', 'suspect', 'Un cambio bajo prueba', 'El pipeline evalúa el diff y compara el comportamiento antes y después.'),
        stage('review', 'to-review', 'good', 'Corrección verificada', 'En esta corrida de laboratorio se integró el parche y se verificó la corrección.')
      );
    } else {
      stages.push(stage('clone', 'to-clone', 'suspect', 'La app clon devuelve su veredicto',
        record.verdict === 'clean' ? 'Los observadores permiten reenviar la petición.' : 'El resultado es inconcluso. En esta corrida el gateway reenvió la petición.'));
    }
  } else {
    stages.push(stage('proxy', 'to-proxy', 'good', 'El proxy permite el paso', 'La petición coincide con el perfil de la operación.'));
  }
  if (record.route === 'prod') {
    const success = record.status < 400;
    const via = record.classification === 'clean' ? 'direct' : 'cleared';
    stages.push(stage('prod', via, success ? 'good' : 'suspect', '¡Llegaste a producción!',
      success ? 'La aplicación atendió la petición.' : 'La entrega se completó. La aplicación respondió que el recurso no existe.'));
  }
  return {record, stages, request: record.method + ' ' + record.path};
}

const inbox = lookup('requests');
for (const record of recordedRequests) {
  const label = document.createElement('label');
  const input = document.createElement('input');
  input.type = 'radio';
  input.name = 'scenario';
  input.value = record.id;
  const entry = document.createElement('span');
  entry.className = 'request-entry';
  const method = document.createElement('b');
  method.textContent = record.method;
  const path = document.createElement('code');
  path.textContent = record.path;
  const preview = document.createElement('small');
  const payload = record.input;
  if (payload.body) {
    preview.textContent = Object.keys(payload.body).join(' · ');
  } else {
    preview.textContent = Object.entries(payload.query || payload.pathParams || {})
      .map(([key, value]) => key + '=' + value).join(' · ') || 'Sin parámetros';
  }
  entry.append(method, path, preview);
  label.append(input, entry);
  inbox.append(label);
}

function showInput(record) {
  const {query, pathParams, body, example, note} = record.input;
  lookup('entry-id').textContent = '#' + record.id;
  lookup('entry-method').textContent = record.method;
  lookup('entry-route').textContent = record.path;
  const content = lookup('entry-content');
  const label = document.createElement('h4');
  if (body) {
    label.textContent = 'Body JSON';
    const json = document.createElement('pre');
    json.textContent = JSON.stringify(body, null, 2);
    content.replaceChildren(label, json);
  } else if (query || pathParams) {
    label.textContent = query ? 'Query' : 'Parámetros de ruta';
    const fields = document.createElement('dl');
    for (const [key, value] of Object.entries(query || pathParams)) {
      const name = document.createElement('dt');
      const data = document.createElement('dd');
      name.textContent = key;
      data.textContent = value;
      fields.append(name, data);
    }
    content.replaceChildren(label, fields);
  } else {
    content.replaceChildren();
  }
  lookup('entry-note').textContent = example
    ? 'Valores de ejemplo. La grabación conserva solo el método y la ruta.'
    : note || 'Valor registrado en la ruta.';
}

const choices = inbox.querySelectorAll('input');
const resume = lookup('resume');
const slider = lookup('stage');
const diagram = lookup('diagram');
const trace = document.querySelector('.trace');
const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
let scenario = scenarioFor(recordedRequests[0]);
let index = 0;
const stageDuration = 2400;
const intro = lookup('intro');
function paintIntro() {
  intro.hidden = reduced.matches || !scenario.record.incident || scenario.stages[index].node !== 'clone'
    || elapsed < travelDuration || frame === null;
  if (intro.hidden) return;
  const progress = Math.min(1, (elapsed - travelDuration) / (stageDuration - travelDuration));
  const opacity = Math.max(0, Math.min(1, (1 - progress) / 0.16));
  const value = 'oracle.fired  [' + scenario.record.incident.oracle + ']';
  const length = Math.min(value.length, Math.floor(progress * 2 * value.length));
  lookup('intro-value').textContent = value.slice(0, length);
  intro.style.setProperty('--alpha', opacity);
  intro.style.setProperty('--rise', ((1 - opacity) * -7) + 'px');
  intro.style.setProperty('--progress', progress);
}
const trail = lookup('travel-line');
const packet = lookup('packet');
let frame = null;
let previousTime = 0;
let elapsed = 0;
let wire = null;
let distance = 0;
let travelDuration = 0;

function paintTravel() {
  const moving = elapsed < travelDuration;
  diagram.classList.toggle('in-transit', moving);
  packet.setAttribute('visibility', moving ? 'visible' : 'hidden');
  if (!moving) return;

  // The light and the advancing stroke share the distance along the wire.
  const time = elapsed / travelDuration;
  const fraction = time * time * (3 - 2 * time);
  const position = wire.getPointAtLength(distance * fraction);
  trail.style.strokeDashoffset = String(1 - fraction);
  packet.setAttribute('transform', 'translate(' + position.x + ' ' + position.y + ')');
}

function showStage(animate) {
  const stages = scenario.stages;
  const current = stages[index];
  diagram.querySelectorAll('.passed, .current').forEach(el => {
    el.classList.remove('passed', 'current');
    el.style.removeProperty('--signal');
  });
  stages.slice(0, index + 1).forEach((step, i) => {
    for (const id of [step.node, step.wire].filter(Boolean)) {
      const el = lookup(id);
      el.classList.add(i === index ? 'current' : 'passed');
      el.style.setProperty('--signal', tone[step.color]);
    }
  });
  diagram.style.setProperty('--signal', tone[current.color]);
  trace.style.setProperty('--signal', tone[current.color]);
  wire = current.wire && lookup(current.wire);
  distance = wire ? wire.getTotalLength() : 0;
  travelDuration = wire && !reduced.matches ? Math.min(1100, 340 + distance * 4) : 0;
  if (wire) trail.setAttribute('d', wire.getAttribute('d'));
  elapsed = animate ? 0 : travelDuration;
  paintTravel();
  diagram.classList.toggle('injection', Boolean(scenario.record.incident) && index >= 2);
  if (scenario.record.incident && current.node === 'clone') {
    lookup('intro-name').textContent = incidents[scenario.record.incident.kind][0];
    lookup('intro-field').textContent = 'shadow_l1 / observador';
  }
  paintIntro();

  diagram.querySelector('[aria-current="step"]')?.removeAttribute('aria-current');
  lookup(current.node).setAttribute('aria-current', 'step');
  resume.hidden = frame !== null || index === stages.length - 1;
  renderEvidence(animate && travelDuration > 0 ? stages[index - 1] : current);
  lookup('counter').textContent = (index + 1) + ' / ' + stages.length;
  slider.max = stages.length;
  slider.value = index + 1;
  slider.setAttribute('aria-valuetext', `Etapa ${index + 1} de ${stages.length}. ${current.title}`);
  slider.style.setProperty('--progress', (100 * index / (stages.length - 1)) + '%');
}

const gateNames = {
  policy: 'Política del diff', properties: 'Propiedades de seguridad',
  poc: 'Prueba de concepto', tests: 'Tests de la app', legit: 'Tráfico legítimo'
};

function renderEvidence(current) {
  const {record} = scenario;
  const incident = record.incident;
  const node = current.node;
  const fields = {request: [['request.id', record.id], ['method', record.method]],
    proxy: [['request.classified', record.classification], ['destino', record.classification === 'suspect' ? 'app clon' : 'producción']],
    prod: [['request.routed', record.route], ['HTTP', record.status], ['latencia', record.ms + ' ms']],
    clone: [['veredicto', record.verdict], ...(incident ? [['oracle.fired', incident.oracle], ['incidente', incident.id]] : [])]
  };
  if (incident) {
    fields.rule = [['poc.ready', incident.reproducible ? 'reproducible' : 'inconclusa'], ['repeticiones', incident.runs], ['rule.scope', incident.scope], ['TTL', incident.ttl + ' s']];
    fields.patch = [['incidente', incident.id]];
    fields.review = [['pr.merged', incident.sha], ['verify.result', incident.verified ? 'ataque bloqueado' : 'pendiente'], ['incident.closed', incident.outcome]];
  }
  const stamp = lookup('delivery-stamp');
  stamp.setAttribute('visibility', node === 'prod' ? 'visible' : 'hidden');
  stamp.querySelector('text').textContent = '✓ HTTP ' + record.status;
  const event = {
    request: 'Entrada HTTP', proxy: 'request.classified', prod: 'request.routed',
    clone: incident ? 'oracle.fired' : 'request.routed', rule: 'rule.active',
    patch: 'patch.diff', review: 'verify.result'
  }[node];
  lookup('req-line').textContent = event;
  lookup('map-status').textContent = stationNames[node] + ' · ' + event;
  lookup('step-title').textContent = current.title;
  lookup('step-title').classList.toggle('arrived', node === 'prod' && record.status < 400);
  lookup('step-note').textContent = current.note;
  const list = lookup('trace-fields');
  list.replaceChildren();
  for (const [key, value] of fields[node]) {
    const term = document.createElement('dt');
    const detail = document.createElement('dd');
    term.textContent = key;
    detail.textContent = value;
    list.append(term, detail);
  }
  const hasPatch = node === 'patch' || node === 'review';
  const diff = lookup('patch-inspector');
  diff.hidden = lookup('checks').hidden = !hasPatch;
  if (!hasPatch) return;
  diff.open = node === 'patch';
  lookup('patch-file').textContent = incident.file;
  const changes = incident.diff.filter(line => line.startsWith('+') || line.startsWith('-'));
  const additions = changes.filter(line => line.startsWith('+')).length;
  lookup('diff-count').textContent = '+' + additions + ' / −' + (changes.length - additions);
  renderDiff(lookup('patch-code'), changes, true);
  const results = Object.values(incident.gates);
  lookup('gate-count').textContent = results.filter(Boolean).length + '/' + results.length;
  const checks = Object.entries(incident.gates).map(([gate, ok]) => {
    const row = document.createElement('li');
    row.textContent = (ok ? '✓ ' : '× ') + gateNames[gate];
    return row;
  });
  lookup('gate-list').replaceChildren(...checks);
}

function renderDiff(container, lines, compact) {
  container.replaceChildren(...lines.map(line => {
    const span = document.createElement('span');
    if (line.startsWith('+')) span.className = 'added';
    if (line.startsWith('-')) span.className = 'removed';
    if (line.startsWith('@@')) span.className = 'hunk';
    span.textContent = compact ? line[0] + ' ' + line.slice(1).trimStart() : line;
    return span;
  }));
}

lookup('expand-patch').addEventListener('click', () => {
  const incident = scenario.record.incident;
  pause();
  hideTip();
  lookup('reader-file').textContent = incident.file;
  renderDiff(lookup('reader-code'), incident.diff, false);
  lookup('patch-reader').showModal();
});

lookup('close-patch').addEventListener('click', () => lookup('patch-reader').close());

function finished() {
  return index === scenario.stages.length - 1 && elapsed >= travelDuration;
}

function pause() {
  cancelAnimationFrame(frame);
  frame = null;
  resume.hidden = index === scenario.stages.length - 1;
}

function tick(now) {
  const inTransit = elapsed < travelDuration;
  elapsed += Math.max(0, now - previousTime);
  previousTime = now;
  if (inTransit) {
    paintTravel();
    if (elapsed >= travelDuration) renderEvidence(scenario.stages[index]);
  }
  if (scenario.stages[index].node === 'clone') paintIntro();
  if (finished()) {
    pause();
    return;
  }
  if (elapsed >= stageDuration) {
    index++;
    showStage(true);
  }
  frame = requestAnimationFrame(tick);
}

function play() {
  if (frame !== null) return;
  previousTime = performance.now();
  frame = requestAnimationFrame(tick);
  resume.hidden = true;
}

const stations = [...diagram.querySelectorAll('.station')];
const tip = lookup('station-tip');
const field = document.querySelector('.map-field');
let inspected = null;

const descriptions = {
  request: 'El portal web es el punto de entrada de la petición.',
  proxy: 'Compara la petición con el formato que espera la aplicación.',
  prod: 'La aplicación atiende el tráfico que pasa los controles.',
  clone: 'Una copia aislada permite observar qué efecto tiene una entrada sospechosa.',
  rule: 'Una regla temporal contiene las peticiones que coinciden con la falla.',
  patch: 'Se comprueba la corrección y el comportamiento esperado.',
  review: 'El pipeline registra el resultado de verificar la versión corregida.'
};

function stageOf(node) {
  return scenario.stages.findIndex(step => step.node === node.id);
}

function positionTip() {
  if (!inspected) return;
  const box = inspected.getBoundingClientRect();
  const area = field.getBoundingClientRect();
  const left = box.left - area.left + (box.width - tip.offsetWidth) / 2;
  const above = box.top - area.top - tip.offsetHeight;
  tip.style.left = Math.max(8, Math.min(left, area.width - tip.offsetWidth - 8)) + 'px';
  tip.style.top = (above >= 4 ? above : box.bottom - area.top) + 'px';
}

function hideTip() {
  inspected?.classList.remove('is-inspected');
  inspected?.removeAttribute('aria-describedby');
  inspected = null;
  tip.hidden = true;
}

function inspectStation(node) {
  hideTip();
  inspected = node;
  const n = stageOf(node);
  tip.querySelector('strong').textContent = n < 0 ? 'Fuera de este recorrido' : 'Etapa ' + (n + 1) + ' de ' + scenario.stages.length;
  tip.querySelector('span').textContent = descriptions[node.id];
  node.classList.add('is-inspected');
  node.setAttribute('aria-describedby', tip.id);
  tip.hidden = false;
  positionTip();
}

function seek(next) {
  firstView.disconnect();
  pause();
  index = next;
  showStage(false);
}

function selectStation(node) {
  const next = stageOf(node);
  if (next >= 0) seek(next);
  inspectStation(node);
}

for (const node of stations) {
  node.addEventListener('pointerenter', event => {
    if (event.pointerType !== 'touch') inspectStation(node);
  });
  node.addEventListener('pointerleave', event => {
    if (event.pointerType !== 'touch' && !tip.contains(event.relatedTarget)) hideTip();
  });
  node.addEventListener('focus', () => inspectStation(node));
  node.addEventListener('blur', hideTip);
  node.addEventListener('click', () => selectStation(node));
  node.addEventListener('keydown', event => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      selectStation(node);
    }
  });
}
tip.addEventListener('pointerleave', event => {
  if (!inspected?.contains(event.relatedTarget)) hideTip();
});
document.addEventListener('pointerdown', event => {
  if (!event.target.closest('.station, .station-tip')) hideTip();
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') hideTip();
});
new ResizeObserver(positionTip).observe(field);

const firstView = new IntersectionObserver(entries => {
  if (entries.some(entry => entry.isIntersecting)) {
    firstView.disconnect();
    play();
  }
}, {threshold: 0.1});

for (const choice of choices) {
  choice.addEventListener('click', () => {
    firstView.disconnect();
    hideTip();
    pause();
    scenario = scenarioFor(recordedRequests.find(record => record.id === choice.value));
    index = 0;
    showInput(scenario.record);
    play();
    showStage(false);
  });
}

resume.addEventListener('click', () => {
  firstView.disconnect();
  hideTip();
  play();
  paintIntro();
});
slider.addEventListener('pointerdown', () => {
  firstView.disconnect();
  pause();
});
slider.addEventListener('input', () => seek(slider.valueAsNumber - 1));
reduced.addEventListener('change', () => {
  if (reduced.matches) showStage(false);
});
compactMap.addEventListener('change', () => {
  layoutMap();
  const fraction = travelDuration ? Math.min(1, elapsed / travelDuration) : 1;
  if (wire) {
    distance = wire.getTotalLength();
    trail.setAttribute('d', wire.getAttribute('d'));
    if (fraction < 1) paintTravel();
  }
});
let resumeOnReturn = false;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    resumeOnReturn = frame !== null;
    pause();
  } else if (resumeOnReturn && !reduced.matches) {
    resumeOnReturn = false;
    play();
  }
});
choices[0].checked = true;
showInput(scenario.record);
showStage(false);
resume.hidden = true;
firstView.observe(field);
