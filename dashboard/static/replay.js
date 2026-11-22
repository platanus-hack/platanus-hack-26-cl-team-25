/* Read-only replay. Chat input is local text; the only fetch loads a fixed recording. */
(function () {
  'use strict';

  const duration = 120000;
  const leadIn = 3600;
  const firstBurstGap = 820;
  const minimumGap = 350;
  const openingWords = 'Voy a probar tres accesos con la cuenta de prueba y revisar qué devuelve cada uno.'.split(' ');
  const get = (id) => document.getElementById('demo-' + id);
  const demo = document.getElementById('demo');
  const live = document.getElementById('live-dashboard');
  const header = document.querySelector('.bar');
  const form = get('form');
  const prompt = get('prompt');
  const logs = get('logs');
  const transcript = get('chat-transcript');
  const thread = get('chat-thread');
  const requests = get('requests');
  const issues = get('incidents');
  const map = get('map');
  const issueNames = {
    sqli: 'Inyección SQL',
    traversal: 'Lectura fuera del directorio permitido',
    idor: 'Acceso a un recurso ajeno'
  };
  const issueSteps = ['Regla', 'Parche', 'Validación', 'Producción'];
  const chatActions = {
    sqli: {
      action: 'Empiezo por la búsqueda de productos. Voy a ver si devuelve información restringida.',
      success: 'La búsqueda me respondió como si la consulta fuera válida.'
    },
    traversal: {
      action: 'Ahora paso a los archivos. Voy a pedir uno que debería quedar fuera de mi alcance.',
      success: 'También recibí una respuesta exitosa. Desde acá no puedo saber de qué entorno vino.'
    },
    idor: {
      action: 'Me queda probar si puedo consultar un pedido de otra cuenta.',
      success: 'El servicio aceptó la consulta del pedido. Con eso terminé las tres pruebas.'
    }
  };
  const descriptions = {
    'request.classified': ['El gateway clasifica una solicitud', (event) => event.class === 'suspect'
      ? 'La marca como sospechosa y evalúa si debe enviarla a la copia aislada.'
      : 'La clasifica como tráfico legítimo.'],
    'request.routed': ['El gateway registra el destino', (event) =>
      (event.route === 'shadow_l1' ? 'La solicitud se atendió en la copia aislada.' : 'La solicitud se atendió en producción.') +
      ' El registro indica HTTP ' + event.status + '.'],
    'oracle.fired': ['Ataque detectado en la copia aislada', () =>
      'Una comprobación de seguridad confirmó un efecto indebido al ejecutar la solicitud en la copia.'],
    'incident.opened': ['Immune abre un incidente', (event) => event.incident + ' se vincula a la solicitud que aportó la evidencia.'],
    'rule.active': ['El gateway activa una regla temporal', (event) => 'La regla protege el punto confirmado mientras se prepara la corrección de ' + event.incident + '.'],
    'patch.attempt': ['Immune empieza a reparar el incidente', (event) => 'La corrida registra el intento ' + event.attempt + ' de reparación para ' + event.incident + '.'],
    'gate.result': ['El candidato pasa por las validaciones', (event) =>
      'Control «' + event.gate + '» para ' + event.incident + ': ' + (event.ok ? 'aprobado.' : 'rechazado.')],
    'deploy.started': ['Comienza el despliegue', () => 'Immune prepara la versión que incorpora el parche validado.'],
    'upstream.switched': ['El gateway cambia de versión', () => 'Producción empieza a recibir tráfico en la versión nueva.'],
    'deploy.done': ['Termina el despliegue', (event) => event.ok ? 'La corrida registra un despliegue exitoso.' : 'El despliegue quedó marcado como fallido.'],
    'verify.result': ['Immune comprueba la corrección en producción', (event) => 'Para ' + event.incident +
      (event.exploit_blocked_on_prod ? ', la comprobación registra que el acceso indebido quedó bloqueado.' : ', la comprobación no registró el bloqueo.')],
    'incident.closed': ['Immune cierra el incidente', (event) => event.incident +
      (event.outcome === 'patched' ? ' queda cerrado con el parche aplicado.' : ' queda cerrado con resultado ' + event.outcome + '.')]
  };

  const byRequest = new Map();
  const byIncident = new Map();
  const issuesById = new Map();
  const narratedRequests = new Map();
  let scheduled = [];
  let cursor = 0;
  let elapsed = 0;
  let started = 0;
  let timer = null;
  let status = 'idle';
  let recordingId = '';
  let latest = null;
  let pinnedId = null;
  let deployed = false;
  let repaired = 0;
  let opening = null;
  let visibleWords = 0;

  function clock(ms) {
    const seconds = Math.floor(ms / 1000);
    return String(Math.floor(seconds / 60)).padStart(2, '0') + ':' + String(seconds % 60).padStart(2, '0');
  }

  function setPhase(title, detail) {
    get('phase-title').textContent = title;
    get('phase-detail').textContent = detail;
  }

  function setClock() {
    const label = clock(elapsed) + ' / 02:00';
    if (get('time').textContent !== label) get('time').textContent = label;
    get('progress').value = elapsed;
  }

  function controls() {
    thread.toggleAttribute('data-running', status === 'playing');
    get('send').disabled = status !== 'idle';
    get('pause').disabled = status !== 'playing' && status !== 'paused';
    get('pause').textContent = status === 'paused' ? 'Continuar' : 'Pausar';
    get('reset').disabled = status === 'idle' || status === 'loading';
  }

  function drawMap(request) {
    const event = request && request.event;
    const route = request && request.route;
    const inShadow = !!request && (route === 'shadow_l1' || request.evidence);
    const response = request && request.response;
    const deploying = event && ['deploy.started', 'upstream.switched', 'deploy.done'].includes(event.type);
    const verifying = event && ['verify.result', 'incident.closed'].includes(event.type);
    map.dataset.route = !request ? 'idle' : route === 'prod' ? 'production' : inShadow ? 'shadow' : 'request';
    map.classList.toggle('has-repair', !!(deploying || (verifying && request.verified)));
    map.classList.toggle('has-evidence', !!request?.evidence);
    get('detection').hidden = !request?.evidence;
    get('trace').textContent = request ? 'Solicitud #' + request.id : '';
    get('agent-state').textContent = request ? request.method + ' · ' + (response ? 'HTTP ' + response : 'Enviada') : 'En espera';
    get('gateway-state').textContent = request
      ? request.rule ? 'Regla registrada' : request.class === 'suspect' ? 'Sospechosa' : 'Legítima'
      : 'En espera';
    get('shadow-state').textContent = !request ? 'En espera' :
      request.evidence ? 'Evidencia confirmada' : inShadow ? 'Ejecución aislada' : 'Sin ejecución registrada';
    get('prod-state').textContent = !request ? 'En espera' :
      verifying && request.verified ? 'Parche verificado' :
      deploying ? 'Despliegue del parche' :
      route === 'prod' ? 'Atendió la solicitud' :
      deployed ? 'Versión actualizada' : 'Operativa';
  }

  function selectRequest(id) {
    pinnedId = id;
    get('follow').hidden = id === null;
    for (const request of byRequest.values()) {
      request.button.setAttribute('aria-pressed', String(request.id === id));
    }
    drawMap(id ? byRequest.get(id) : latest);
  }

  function addRequest(event) {
    const row = document.createElement('li');
    const button = document.createElement('button');
    const id = document.createElement('span');
    const classification = document.createElement('b');
    const result = document.createElement('span');
    button.type = 'button';
    button.setAttribute('aria-pressed', 'false');
    id.className = 'demo-meta';
    id.textContent = event.method + ' #' + event.rid;
    classification.textContent = event.class === 'suspect' ? 'Sospechosa' : 'Legítima';
    result.textContent = 'Clasificada';
    button.append(id, classification, result);
    row.append(button);
    requests.prepend(row);
    const request = { id: event.rid, method: event.method, class: event.class, result, button };
    byRequest.set(event.rid, request);
    button.addEventListener('click', () => selectRequest(pinnedId === event.rid ? null : event.rid));
    return request;
  }

  function showCurl(event, request) {
    if (event.type === 'request.classified') {
      const narration = narratedRequests.get(event.rid);
      const parent = narration ? appendChat(narration.action) : document.createElement('li');
      const tool = document.createElement('div');
      const command = document.createElement('code');
      const output = document.createElement('p');
      const label = narration ? 'Prueba' : 'Tráfico';
      tool.className = 'demo-tool';
      command.textContent = '$ curl · ' + event.method + ' · ' + label + ' #' + event.rid;
      output.textContent = 'Enviando…';
      tool.setAttribute('data-pending', '');
      tool.append(command, output);
      parent.append(tool);
      if (!narration) transcript.append(parent);
      request.terminalOutput = output;
      request.terminalItem = tool;
      if (narration) request.chatMessage = parent;
    } else if (event.type === 'request.routed') {
      request.terminalOutput.textContent = 'HTTP ' + event.status + ' · ' + event.ms + ' ms';
      request.terminalItem.removeAttribute('data-pending');
      if (request.chatMessage) {
        const reply = document.createElement('p');
        reply.textContent = event.status >= 200 && event.status < 300
          ? narratedRequests.get(event.rid).success
          : 'El servicio respondió con un rechazo.';
        request.chatMessage.append(reply);
      }
    } else {
      return;
    }
    thread.scrollTop = thread.scrollHeight;
  }

  function openIssue(event) {
    const item = document.createElement('li');
    const heading = document.createElement('div');
    const title = document.createElement('b');
    const phase = document.createElement('span');
    const progress = document.createElement('div');
    heading.className = 'demo-issue-heading';
    progress.className = 'demo-issue-progress';
    title.textContent = event.incident + ' · ' + (issueNames[event.vuln_class] || 'Incidente confirmado');
    heading.append(title, phase);
    const markers = issueSteps.map((label) => {
      const marker = document.createElement('span');
      marker.textContent = label;
      progress.append(marker);
      return marker;
    });
    item.append(heading, progress);
    issues.append(item);
    issuesById.set(event.incident, { phase, markers, gates: new Map() });
    get('incidents-empty').hidden = true;
    get('incidents-count').hidden = false;
  }

  function updateIssue(event) {
    if (event.type === 'incident.opened') openIssue(event);
    const issue = issuesById.get(event.incident);
    if (!issue) return;

    let step = -1;
    let label;
    switch (event.type) {
      case 'incident.opened': label = 'Evidencia confirmada'; break;
      case 'rule.active': step = 0; label = 'Regla temporal activa'; break;
      case 'patch.attempt':
        issue.gates.clear();
        step = 1;
        label = 'Preparando el parche';
        break;
      case 'gate.result': {
        issue.gates.set(event.gate, event.ok);
        const failed = [...issue.gates.values()].filter((ok) => !ok).length;
        step = 2;
        label = failed ? 'Validando · ' + failed + ' controles rechazados' : 'Validando · ' + issue.gates.size + ' controles aprobados';
        break;
      }
      case 'deploy.started': step = 3; label = 'Desplegando el parche'; break;
      case 'upstream.switched': step = 3; label = 'Nueva versión activa'; break;
      case 'deploy.done': step = 3; label = event.ok ? 'Despliegue completado' : 'Falló el despliegue'; break;
      case 'verify.result': step = 3; label = event.exploit_blocked_on_prod ? 'Bloqueo verificado' : 'Bloqueo sin confirmar'; break;
      case 'incident.closed':
        step = event.outcome === 'patched' ? issueSteps.length : -1;
        label = event.outcome === 'patched' ? 'Resuelto · parche en producción' : 'Cerrado · ' + event.outcome;
        break;
      default: return;
    }
    issue.phase.textContent = label;
    issue.markers.forEach((marker, index) => {
      marker.dataset.state = index < step ? 'complete' : index === step ? 'current' : 'pending';
      if (index === step) marker.setAttribute('aria-current', 'step');
      else marker.removeAttribute('aria-current');
    });
    get('incidents-count').textContent = repaired + ' / ' + issuesById.size + ' resueltos';
  }

  function appendLog(event, list) {
    const item = document.createElement('li');
    const time = document.createElement('span');
    const code = document.createElement('code');
    time.className = 'demo-meta';
    time.textContent = clock(event.at * 1000);
    code.textContent = '#' + event.seq + ' ' + event.type +
      (event.rid ? ' · ' + event.rid : event.incident ? ' · ' + event.incident : '') +
      (event.status ? ' · ' + event.status : '') + (event.gate ? ' · ' + event.gate : '');
    item.append(time, code);
    const following = list.scrollHeight - list.clientHeight - list.scrollTop < 12;
    list.append(item);
    if (following) list.scrollTop = list.scrollHeight;
  }

  function appendChat(message) {
    const item = document.createElement('li');
    const speaker = document.createElement('b');
    const text = document.createElement('p');
    speaker.className = 'demo-speaker';
    speaker.textContent = 'LLM';
    text.textContent = message;
    item.append(speaker, text);
    transcript.append(item);
    thread.scrollTop = thread.scrollHeight;
    return item;
  }

  function apply(event) {
    let request = byRequest.get(event.rid) || byIncident.get(event.incident);
    if (event.type === 'request.classified') request = addRequest(event);
    if (event.type === 'incident.opened' && request) byIncident.set(event.incident, request);
    if (event.type === 'upstream.switched') deployed = true;
    if (event.type === 'incident.closed' && event.outcome === 'patched') repaired += 1;
    if (request) {
      request.event = event;
      showCurl(event, request);
      if (event.type === 'oracle.fired') {
        request.evidence = true;
        request.result.textContent = 'Evidencia confirmada';
      }
      if (event.type === 'request.routed') {
        request.route = event.route;
        request.response = event.status;
        request.result.textContent = (event.route === 'shadow_l1' ? 'Copia aislada' : 'Producción') + ' · ' + event.status;
      }
      if (event.type === 'rule.active') request.rule = true;
      if (event.type === 'verify.result') request.verified = event.exploit_blocked_on_prod;
      latest = request;
    }
    updateIssue(event);
    appendLog(event, logs);
    const [title, explain] = descriptions[event.type];
    setPhase(title, explain(event));
    drawMap(pinnedId ? byRequest.get(pinnedId) : latest);
  }

  function pause() {
    window.clearInterval(timer);
    timer = null;
    status = 'paused';
    controls();
  }

  function advance() {
    elapsed = Math.min(duration, performance.now() - started);
    if (opening) {
      const words = Math.min(openingWords.length, Math.floor(elapsed / 125));
      if (words > visibleWords) {
        opening.textContent = openingWords.slice(0, words).join(' ');
        visibleWords = words;
      }
      if (visibleWords === openingWords.length) opening = null;
    }
    while (cursor < scheduled.length && scheduled[cursor].due <= elapsed) apply(scheduled[cursor++].event);
    setClock();
    if (elapsed < duration) return;
    window.clearInterval(timer);
    timer = null;
    status = 'finished';
    appendChat('Terminé mi parte de la prueba. Del lado de Immune se ve cómo cerró cada incidente.');
    setPhase('Corrida completa', byRequest.size + ' solicitudes registradas y ' + repaired +
      ' incidentes cerrados con parche en la corrida ' + recordingId + '.');
    controls();
  }

  function resume() {
    started = performance.now() - elapsed;
    status = 'playing';
    timer = window.setInterval(advance, 80);
    controls();
  }

  function reset() {
    window.clearInterval(timer);
    timer = null;
    scheduled = [];
    cursor = 0;
    elapsed = 0;
    deployed = false;
    repaired = 0;
    status = 'idle';
    latest = null;
    byRequest.clear();
    byIncident.clear();
    issuesById.clear();
    narratedRequests.clear();
    opening = null;
    visibleWords = 0;
    logs.replaceChildren();
    transcript.replaceChildren();
    thread.hidden = true;
    requests.replaceChildren();
    issues.replaceChildren();
    get('incidents-empty').hidden = false;
    get('incidents-count').hidden = true;
    get('message').hidden = true;
    form.hidden = false;
    selectRequest(null);
    setPhase('Esperando el mensaje', 'Cuando inicies la grabación, cada solicitud aparecerá con su clasificación y destino.');
    setClock();
    controls();
    prompt.focus();
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const message = prompt.value.trim();
    if (status !== 'idle' || !message) return;
    status = 'loading';
    controls();
    get('user-text').textContent = message;
    get('message').hidden = false;
    thread.hidden = false;
    form.hidden = true;
    setPhase('Cargando la corrida grabada', 'Los eventos se van a mostrar en orden de registro.');
    try {
      const response = await fetch('/static/replay.json');
      if (!response.ok) throw new Error('Recording unavailable');
      const recording = await response.json();
      const events = recording.events;
      const last = events[events.length - 1].at;
      let pacing = 0;
      const offsets = events.map((entry, index) => {
        if (index > 0) pacing += entry.at < 1 ? firstBurstGap : minimumGap;
        return pacing;
      });
      const scaled = duration - leadIn - 4000 - pacing;
      scheduled = events.map((entry, index) => ({
        event: entry,
        due: leadIn + offsets[index] + (entry.at / last) * scaled
      }));
      recordingId = recording.run;
      events.forEach((entry) => {
        if (entry.type === 'incident.opened' && chatActions[entry.vuln_class]) {
          narratedRequests.set(entry.rid, chatActions[entry.vuln_class]);
        }
      });
      const reply = appendChat('Preparando las pruebas…').lastElementChild;
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) reply.textContent = openingWords.join(' ');
      else opening = reply;
      setPhase('Reproduciendo la corrida ' + recordingId, 'El registro muestra el tiempo original. El reloj de la demo termina en dos minutos.');
      if (demo.hidden) pause();
      else {
        resume();
        thread.focus({ preventScroll: true });
      }
    } catch {
      status = 'idle';
      controls();
      thread.hidden = true;
      form.hidden = false;
      setPhase('No se pudo cargar la corrida', 'Volvé a enviar el mensaje para reintentar.');
      if (!demo.hidden) prompt.focus();
    }
  });

  prompt.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
    event.preventDefault();
    form.requestSubmit();
  });

  get('pause').addEventListener('click', () => {
    if (status === 'playing') pause();
    else if (status === 'paused') resume();
  });
  get('reset').addEventListener('click', reset);
  get('follow').addEventListener('click', () => {
    selectRequest(null);
    get('requests-title').focus();
  });

  function showDemo(open, moveFocus) {
    demo.hidden = !open;
    live.hidden = open;
    header.classList.toggle('is-demo', open);
    get('mode').textContent = open ? 'Volver al panel en vivo' : 'Abrir demo interactiva';
    if (!open && status === 'playing') pause();
    if (moveFocus) (open ? get('title') : get('mode')).focus();
  }

  const demoRequested = () => new URLSearchParams(window.location.search).has('demo');
  get('mode').addEventListener('click', () => {
    const open = demo.hidden;
    const url = new URL(window.location.href);
    if (open) url.searchParams.set('demo', '');
    else url.searchParams.delete('demo');
    window.history.pushState(null, '', url);
    showDemo(open, true);
    window.scrollTo(0, 0);
  });
  window.addEventListener('popstate', () => showDemo(demoRequested(), true));
  showDemo(demoRequested(), false);
})();
