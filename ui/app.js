(() => {
  'use strict';
  const MAX_BYTES = 2 * 1024 * 1024;

  const $ = id => document.getElementById(id);

  const ACCESS_HEADER = 'X-Preview-Access-Code';
  const state = {events: [], rows: [], decisions: new Map(), drafts: new Map(), analysisId: null, resumeOffered: false, resumeCount: 0, busy: false, generation: 0, controller: null,
    accessCode: null, providers: {jev_configured:false, openrouter_configured:false, narrative_model:'deepseek/deepseek-v4.1-flash', access_required:false},
    keys: {jev:'', openrouter:''}, resumeCache: new Map(), lastRun: null};
  // Static website (site/index.html): keys stay in this tab and requests go straight from the browser
  // to TypeSafe and OpenRouter through ui/engine.js. Without this flag the page talks to web_app.py.
  const BROWSER = document.body?.dataset?.mode === 'browser';
  const KEY_STORE = 'casebench.keys';
  const NO_DECISIONS = `No ${BROWSER ? 'Jev' : 'server-issued'} decisions. Local preview does not assign relatedness.`;
  const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
  const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
  const text = x => x === undefined || x === null || x === '' ? '—' : typeof x === 'string' ? x : String(x);
  const field = (obj, key) => object(obj) ? obj[key] : undefined;
  function source(raw) {
    if (object(raw._source)) return raw._source;
    if (!object(raw.fields)) return raw;
    const fields = raw.fields;
    const one = key => Array.isArray(fields[key]) ? fields[key][0] : fields[key];
    const proc = {};
    for (const key of ['name', 'executable', 'command_line', 'pid', 'entity_id', 'sha256']) {
      if (one(`process.${key}`) !== undefined) proc[key] = one(`process.${key}`);
    }
    const parent = {};
    for (const key of ['name', 'pid', 'entity_id', 'command_line']) {
      if (one(`process.parent.${key}`) !== undefined) parent[key] = one(`process.parent.${key}`);
    }
    if (Object.keys(parent).length) proc.parent = parent;
    return {'@timestamp':one('@timestamp'), event:{category:fields['event.category'] || [], type:fields['event.type'] || [], action:one('event.action'), id:one('event.id')},
      host:{name:one('host.name')}, user:{name:one('user.name')}, process:proc,
      file:{path:one('file.path'), name:one('file.name')}, destination:{ip:one('destination.ip'), domain:one('destination.domain'), port:one('destination.port')},
      dns:{question:{name:one('dns.question.name')}}, registry:{path:one('registry.path'), value:one('registry.value')},
      winlog:{event_data:{TargetImage:one('winlog.event_data.TargetImage'), TargetProcessGUID:one('winlog.event_data.TargetProcessGUID')}}};
  }
  const idOf = raw => {
    const src = source(raw), ev = field(src, 'event');
    return text(raw.id || raw._id || src.id || field(ev, 'id'));
  };
  const timeOf = src => src['@timestamp'] || src.timestamp || src.time;
  function isExecution(src) {
    const proc = src.process, ev = field(src, 'event');
    if (!object(proc) || !Object.keys(proc).length) return false;
    const kind = String(src.kind || field(ev, 'category') || field(ev, 'dataset') || '').toLowerCase();
    const action = String(field(ev, 'action') || src.action || src.kind || '').toLowerCase();
    const types = field(ev, 'type');
    return kind === 'execution' || (kind.includes('process') && ((Array.isArray(types) ? types.includes('start') : types === 'start') || /^(start|exec|fork|create|process_started|created-process|process creation)$/.test(action))) || (kind.includes('sysmon') && /^(1|process create)$/.test(action));
  }
  function parseEvents(input) {
    const events = Array.isArray(input) ? input : object(input) ? input.events : null;
    if (!Array.isArray(events) || !events.length || events.length > 500) throw Error('Expected 1–500 event objects in a JSON array or an object containing an events array.');
    const ids = new Set();
    return events.map((raw, index) => {
      if (!object(raw)) throw Error(`Event ${index + 1} is not an object.`);
      const id = idOf(raw);
      if (id === '—') throw Error(`Event ${index + 1} has no id, _id, or event.id.`);
      if (ids.has(id)) throw Error(`Duplicate event ID: ${id}`);
      ids.add(id);
      const src = source(raw), time = timeOf(src), proc = field(src, 'process');
      const category = field(field(src, 'event'), 'category');
      return {id, raw, src, time, process:object(proc) ? proc : {}, execution:isExecution(src), kind:src.kind || (Array.isArray(category) ? category.join(', ') : category) || 'event', index};
    }).sort((a,b) => {
      const x = Date.parse(a.time), y = Date.parse(b.time);
      return (Number.isFinite(x) ? x : Infinity) - (Number.isFinite(y) ? y : Infinity) || a.index - b.index;
    });
  }
  function element(tag, cls, value) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (value !== undefined) node.textContent = text(value);
    return node;
  }
  function appendField(dl, label, value) {
    if (value === undefined || value === null || value === '') return;
    const div = element('div');
    div.append(element('dt', '', label), element('dd', '', Array.isArray(value) ? value.join(', ') : value));
    dl.append(div);
  }
  function setStatus(message, error = false) {
    $('status').textContent = message;
    $('status').classList.toggle('error', error);
  }
  function page(name) {
    for (const id of ['setup', 'events', 'table']) {
      $(`page-${id}`).hidden = id !== name;
      $(`nav-${id}`).setAttribute('aria-selected', String(id === name));
    }
    location.hash = name;
  }

  // Replit preview requires the per-start access code; it is kept in memory for this tab only.
  const providersUnlocked = () => state.providers.access_required !== true || !!state.accessCode;
  async function unlock() {
    const code = $('access-code').value.trim();
    if (!code) { setStatus('Enter the preview access code from the workflow console.', true); return; }
    try {
      const response = await fetch(`${location.origin}/api/access`, {method:'POST', headers:{'Content-Type':'application/json', [ACCESS_HEADER]:code},
        body:'{}', credentials:'omit', cache:'no-store', redirect:'error'});
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw Error(typeof result.error === 'string' ? result.error.slice(0, 160) : `Access check returned HTTP ${response.status}.`);
      state.accessCode = code;
      $('access-code').value = '';
      setStatus('Provider calls unlocked for this tab.');
    } catch (error) {
      state.accessCode = null;
      setStatus(`Unlock failed: ${error.message}`, true);
    }
    renderAccess();
  }

  function renderAccess() {
    $('access-box').hidden = state.providers.access_required !== true;
    $('access-state').textContent = state.providers.access_required !== true ? '' : state.accessCode ? 'Provider calls unlocked for this tab.' : 'Provider calls locked.';
  }
  // Browser mode: keys typed into this page, optionally remembered in this browser's local storage only.
  function renderKeys() {
    state.providers = {jev_configured:!!state.keys.jev, openrouter_configured:!!state.keys.openrouter,
      narrative_model:'deepseek/deepseek-v4.1-flash', access_required:false, example_available:true};
    $('key-status').textContent = `${state.keys.jev ? 'TypeSafe key entered' : 'TypeSafe key needed for Analyze'} · ${state.keys.openrouter ? 'OpenRouter key entered' : 'OpenRouter key optional'}`;
    $('narrate').disabled = state.busy || !state.analysisId || !state.providers.openrouter_configured;
  }
  function saveKeys() {
    try {
      if ($('remember-keys').checked && (state.keys.jev || state.keys.openrouter)) localStorage.setItem(KEY_STORE, JSON.stringify(state.keys));
      else localStorage.removeItem(KEY_STORE);
    } catch { /* Storage unavailable: the keys stay in this tab's memory only. */ }
  }
  function setupKeys() {
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(KEY_STORE) || 'null'); } catch { saved = null; }
    if (object(saved)) {
      state.keys = {jev:typeof saved.jev === 'string' ? saved.jev : '', openrouter:typeof saved.openrouter === 'string' ? saved.openrouter : ''};
      $('remember-keys').checked = true;
    }
    $('jev-key').value = state.keys.jev;
    $('openrouter-key').value = state.keys.openrouter;
    for (const [id, name] of [['jev-key', 'jev'], ['openrouter-key', 'openrouter']]) {
      $(id).addEventListener('input', () => { state.keys[name] = $(id).value.trim(); saveKeys(); renderKeys(); });
    }
    $('remember-keys').addEventListener('change', saveKeys);
    $('forget-keys').addEventListener('click', () => {
      state.keys = {jev:'', openrouter:''};
      $('jev-key').value = ''; $('openrouter-key').value = ''; $('remember-keys').checked = false;
      saveKeys(); renderKeys();
      setStatus('Keys removed from this page and this browser.');
    });
    renderKeys();
  }
  // The privacy notice can be dismissed; the choice is remembered in this browser and Privacy brings it back.
  const NOTE_STORE = 'casebench.privacyDismissed';
  function setupPrivacyNote() {
    const show = visible => {
      $('privacy-note').hidden = !visible;
      $('privacy-show').hidden = visible;
      try { visible ? localStorage.removeItem(NOTE_STORE) : localStorage.setItem(NOTE_STORE, '1'); } catch { /* Not remembered. */ }
    };
    let dismissed = false;
    try { dismissed = localStorage.getItem(NOTE_STORE) === '1'; } catch { dismissed = false; }
    show(!dismissed);
    $('privacy-dismiss').addEventListener('click', () => show(false));
    $('privacy-show').addEventListener('click', () => { show(true); page('setup'); });
  }
  async function refreshProviders() {
    if (BROWSER) return renderKeys();
    try {
      const response = await fetch(`${location.origin}/api/status`, {credentials:'omit', cache:'no-store'});
      if (!response.ok) throw Error('status unavailable');
      const result = await response.json();
      if (result.narrative_model !== 'deepseek/deepseek-v4.1-flash') throw Error('unexpected model');
      state.providers = result;
      $('model-name').textContent = result.narrative_model;
      $('provider-status').textContent = `${result.jev_configured ? 'Jev ready' : 'Jev key missing'} · ${result.openrouter_configured ? 'OpenRouter ready' : 'OpenRouter key missing'}`;
      $('provider-help').textContent = typeof result.key_problem === 'string' ? result.key_problem.slice(0, 200)
        : !result.jev_configured ? 'Add TYPESAFE_API_KEY to .env on the server (python3 web_app.py --setup-keys), then Refresh.' : '';
      $('preview').hidden = result.example_available !== true;
      renderAccess();
    } catch {
      $('model-name').textContent = 'deepseek/deepseek-v4.1-flash';
      $('provider-status').textContent = 'Local server status unavailable; provider buttons need the running app.';
      $('provider-help').textContent = '';
      $('preview').hidden = true;
    }
    $('narrate').disabled = !state.analysisId || !state.providers.openrouter_configured;
  }
  function resetAnalysis() {
    state.generation++;
    if (state.controller) state.controller.abort();
    state.controller = null;
    state.analysisId = null;
    state.decisions.clear();
    state.drafts.clear();
    state.busy = false;
    state.resumeOffered = false;
    state.lastRun = null;
    $('resume').hidden = true;
    $('narrate').disabled = true;
    if (BROWSER) $('download').hidden = true;
    $('findings').textContent = NO_DECISIONS;
    $('narrative').textContent = 'Narrative is optional and must be requested separately.';
    renderTable();
  }
  function linkedProcessContext() {
    const links = new Map();
    if (!state.analysisId) return links;
    const seedId = $('seed').value;
    for (const row of state.rows) {
      if (row.id !== seedId && !state.decisions.get(row.id)?.related) continue;
      const host = field(row.src.host, 'name') || row.src.host;
      const entity = row.process.entity_id;
      if (typeof host !== 'string' || !host || typeof entity !== 'string' || !entity) continue;
      const key = JSON.stringify([host, entity]);
      if (!links.has(key) || row.id === seedId) links.set(key, {id:row.id, seed:row.id === seedId});
    }
    return links;
  }
  function contextFor(row, links) {
    if (row.execution) return null;
    const host = field(row.src.host, 'name') || row.src.host;
    const entity = row.process.entity_id;
    if (typeof host !== 'string' || typeof entity !== 'string' || !host || !entity) return null;
    return links.get(JSON.stringify([host, entity])) || null;
  }
  function linkedRows(links) {
    if (!state.analysisId) return [];
    return state.rows.filter(row => row.id === $('seed').value || state.decisions.get(row.id)?.related || contextFor(row, links));
  }
  function indicatorFor(row) {
    const src = row.src, dns = field(src, 'dns'), winlog = field(src, 'winlog');
    const candidates = [
      [field(src.registry, 'path'), 'registry-value', 'Host Artifacts'],
      [field(src.file, 'path'), 'file-path', 'Host Artifacts'],
      [field(field(winlog, 'event_data'), 'TargetImage'), 'file-path', 'Host Artifacts'],
      [field(field(dns, 'question'), 'name'), 'domain', 'Domain Names'],
      [field(src.destination, 'ip'), 'ipv4-address', 'IP Addresses'],
      [row.process.executable, 'file-path', 'Host Artifacts']];
    return candidates.find(([value]) => typeof value === 'string' && value) || ['', '', ''];
  }
  // A decision whose Jev answer was reused from an earlier (interrupted) run of the same inputs.
  function reusedLabel(decision) {
    if (!object(decision?.reused)) return '';
    const when = decision.reused.answered_utc;
    return typeof when === 'string' && when ? `Reused from earlier run · answered ${when}` : 'Reused from earlier run';
  }
  function renderTable() {
    const target = $('table-body'); target.replaceChildren();
    const links = linkedProcessContext();
    const visible = linkedRows(links);
    $('table-count').textContent = `${visible.length} linked row${visible.length === 1 ? '' : 's'}`;
    const contextCount = state.rows.filter(row => contextFor(row, links)).length;
    const related = [...state.decisions.values()].filter(d => d.id !== $('seed').value && d.related).length;
    const evaluated = [...state.decisions.values()].filter(d => d.id !== $('seed').value).length;
    const summary = $('table-summary'); summary.replaceChildren();
    for (const label of [`${state.rows.length} source events`, `${state.rows.filter(r => r.execution).length} process starts`,
      `${evaluated} Jev decisions`, `${related} related`, `${contextCount} entity-linked context`, `${visible.length} incident rows`]) summary.append(element('span', 'metric', label));
    $('table-guidance').textContent = !state.rows.length ? 'Load an export to begin.' : state.analysisId
      ? `Jev assessment complete for ${evaluated} execution candidate${evaluated === 1 ? '' : 's'}. ${contextCount} other events share a host and process entity ID with the seed or a related execution; these are linked context, not Jev-scored verdicts. ${state.drafts.size ? 'DeepSeek draft received; verify cited claims.' : 'Request a separate DeepSeek draft on Source & analysis if needed.'}`
      : 'Local preview only. OpenRouter being ready does not assess events. Go to Source & analysis, enter analyst context, then click Analyze with Jev.';
    for (const row of visible) {
      const decision = state.decisions.get(row.id), draft = state.drafts.get(row.id);
      const context = contextFor(row, links);
      const seed = row.id === $('seed').value;
      const action = field(field(row.src, 'event'), 'action') || row.src.action || row.kind;
      const [indicator, type, pyramid] = indicatorFor(row);
      const title = draft ? draft.title : `${text(row.process.name || row.kind)} · ${text(action)}`;
      const description = draft ? `${draft.summary} [DeepSeek draft; verify cited evidence]` :
        `${text(row.process.name || row.kind)}: ${text(action)}${indicator ? ` · ${indicator}` : ''}. ${seed ? 'Analyst-confirmed starting process' : context ? `Same process entity as ${context.id}` : `Jev selected basis: ${text(decision?.reason)}`}. Evidence ID: ${row.id}.`;
      const score = seed ? '100% · analyst confirmed' : context
        ? `100% · entity match${!context.seed && state.decisions.get(context.id)?.probability !== undefined ? ` · Jev-linked execution ${(state.decisions.get(context.id).probability * 100).toFixed(0)}%` : ''}`
        : typeof decision?.probability === 'number' ? `${(decision.probability * 100).toFixed(0)}% · Jev relatedness` : 'Jev score unavailable';
      const tr = element('tr');
      tr.sourceEventId = row.id;
      const titleCell = element('td');
      titleCell.append(element('span', 'row-title', title), element('span', 'row-origin', score),
        element('span', 'row-origin', seed ? 'Confirmed seed' : context ? (context.seed ? 'Context · confirmed seed' : 'Context · related execution') : 'Related · review'));
      const reused = !seed && !context ? reusedLabel(decision) : '';
      if (reused) titleCell.append(element('span', 'row-origin reused', reused));
      const category = String(row.kind).toLowerCase(), actionText = String(action).toLowerCase();
      const phase = row.execution ? 'Execution' : actionText.includes('remotethread') ? 'Process Interaction'
        : category.includes('network') ? 'Network Activity' : category.includes('registry') || category.includes('configuration') ? 'Registry Activity'
          : category.includes('file') ? 'File Activity' : '';
      tr.append(element('td', 'mono', row.time || ''), element('td', '', field(row.src.host, 'name') || row.src.host || ''),
        element('td', '', phase), titleCell, element('td', '', description), element('td', '', row.process.name || ''),
        element('td', '', ''), element('td', 'mono', row.process.command_line || ''), element('td', 'mono', indicator),
        element('td', '', type), element('td', '', pyramid));
      target.append(tr);
    }
  }
  function renderTimeline() {
    const target = $('timeline');
    target.replaceChildren();
    const links = linkedProcessContext();
    const visible = linkedRows(links);
    $('count').textContent = `${visible.length} linked event${visible.length === 1 ? '' : 's'}`;
    if (!visible.length) target.append(element('div', 'empty', state.rows.length
      ? 'No linked events yet. Confirm the starting execution and analyst context on Source & analysis, then click Analyze with Jev.'
      : 'No linked events yet. Import source events, confirm a starting execution and analyze with Jev to build this sequence.'));
    for (const row of visible) {
      const position = state.rows.findIndex(e => e.id === row.id);
      const article = element('article', 'event');
      article.id = `event-${position}`;
      const head = element('div', 'event-header');
      head.append(element('span', 'tag', row.execution ? 'Process start' : text(row.kind)));
      const decision = state.decisions.get(row.id);
      const context = contextFor(row, links);
      if (row.id === $('seed').value) head.append(element('span', 'tag seed', 'Analyst-confirmed malicious seed · 100%'));
      else if (decision) head.append(element('span', 'tag related', `Jev-linked incident execution · ${typeof decision.probability === 'number' ? `${(decision.probability * 100).toFixed(0)}%` : 'score unavailable'}`));
      else if (context) head.append(element('span', 'tag context', 'Incident process activity · exact entity match'));
      const reused = row.id !== $('seed').value && decision ? reusedLabel(decision) : '';
      if (reused) head.append(element('span', 'tag reused', reused));
      const proc = row.process, host = field(row.src, 'host'), user = field(row.src, 'user');
      const label = proc.name || field(row.src, 'name') || field(row.src, 'file')?.path || text(row.kind);
      const body = element('div', 'event-body');
      body.append(head, element('h3', '', label));
      if (proc.command_line) body.append(element('p', 'command', proc.command_line));
      if (row.id === $('seed').value) body.append(element('p', '', 'Analyst-confirmed malicious starting execution. The 100% display reflects analyst confirmation, not a Jev prediction.'));
      else if (decision) body.append(element('p', '', `Jev relatedness: ${typeof decision.probability === 'number' ? `${(decision.probability * 100).toFixed(0)}%` : 'not supplied'} · ${text(decision.reason)}. Not a maliciousness verdict.`));
      else if (context) body.append(element('p', '', `Same host and process entity ID as ${context.id}; activity by an incident-linked process, not independently Jev-scored. Individual artifacts are not thereby independently malicious.`));
      const dl = element('dl');
      appendField(dl, 'Event ID', row.id);
      appendField(dl, 'Entity ID', proc.entity_id);
      appendField(dl, 'Parent entity ID', field(proc.parent, 'entity_id'));
      appendField(dl, 'Host', object(host) ? host.name : host);
      appendField(dl, 'User', object(user) ? user.name : user);
      appendField(dl, 'Action', field(field(row.src, 'event'), 'action') || row.src.action);
      body.append(dl);
      article.append(element('time', 'event-time', row.time || 'Time unavailable'), body);
      target.append(article);
    }
  }
  function load(input, label) {
    const rows = parseEvents(input);
    resetAnalysis();
    state.resumeCache = new Map();
    state.events = Array.isArray(input) ? input : input.events;
    state.rows = rows;
    const seed = $('seed');
    seed.replaceChildren();
    const starts = rows.filter(r => r.execution);
    for (const row of starts) {
      const option = element('option', '', `${row.id} · ${text(row.process.name)} · ${text(row.time)} · ${row.process.entity_id ? 'entity ID available' : 'no entity ID'}`);
      option.value = row.id;
      seed.append(option);
    }
    if (!seed.options.length) {
      const option = element('option', '', 'No process starts found'); option.value = ''; seed.append(option);
    }
    // Prefer a better-identified record of the same earliest process start,
    // never a different execution merely because it has more fields.
    if (starts.length) {
      const first = starts[0];
      const sameStart = starts.filter(r => r.time === first.time && r.process.name === first.process.name &&
        r.process.pid === first.process.pid && (field(r.src.host, 'name') || r.src.host) === (field(first.src.host, 'name') || first.src.host));
      seed.value = (sameStart.find(r => r.process.entity_id) || first).id;
    }
    seed.disabled = !rows.some(r => r.execution);
    $('analyze').disabled = seed.disabled;
    $('source').textContent = `${label} · ${rows.length} events`;
    renderTimeline(); renderTable();
    setStatus(seed.disabled ? 'Preview loaded; no eligible starting execution.' : 'Local preview loaded; nothing sent. Confirm the starting execution and add analyst context.');
  }
  function backendOrigin() {
    const url = new URL($('backend').value.trim());
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
      throw Error('Backend origin must be an HTTP(S) origin without a path or credentials.');
    }
    if (url.origin !== location.origin) throw Error('Backend must be the same origin as this page; never send telemetry to another service.');
    return url.origin;
  }
  async function post(path, body, generation) {
    const origin = backendOrigin();
    const controller = new AbortController();
    state.controller = controller;
    const response = await fetch(`${origin}${path}`, {
      method:'POST', headers:{'Content-Type':'application/json', ...(state.accessCode ? {[ACCESS_HEADER]:state.accessCode} : {})}, body:JSON.stringify(body),
      credentials:'omit', cache:'no-store', redirect:'error', signal:controller.signal
    });
    if (generation !== state.generation) throw Error('Source changed; response discarded.');
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) { state.accessCode = null; renderAccess(); }
      const failure = await response.json().catch(() => null);
      const error = Error(object(failure) && typeof failure.error === 'string' ? failure.error.slice(0, 240) : `${path} returned HTTP ${response.status}.`);
      error.status = response.status;
      // The server offers a resume after a failed or interrupted Jev run; it reuses only answered calls.
      if (object(failure) && failure.resume_available === true) {
        error.resumeAvailable = true;
        error.reusable = Number.isInteger(failure.reusable_answers) && failure.reusable_answers >= 0 ? failure.reusable_answers : 0;
      }
      throw error;
    }
    const result = await response.json();
    if (!object(result)) throw Error(`${path} returned an invalid JSON object.`);
    return result;
  }
  function validateDecisions(result) {
    if (typeof result.analysis_id !== 'string' || !result.analysis_id.trim() || !Array.isArray(result.decisions)) throw Error('Analysis response is missing analysis_id or decisions.');
    const known = new Set(state.rows.map(r => r.id));
    const decisions = new Map();
    for (const d of result.decisions) {
      if (!object(d) || typeof d.id !== 'string' || !known.has(d.id) || typeof d.related !== 'boolean' || decisions.has(d.id) || (d.probability !== undefined && (typeof d.probability !== 'number' || !Number.isFinite(d.probability) || d.probability < 0 || d.probability > 1)) ||
          (d.reused !== undefined && (!object(d.reused) || (d.reused.answered_utc !== null && typeof d.reused.answered_utc !== 'string')))) {
        throw Error('Analysis contains an invalid, duplicate, or unknown event decision.');
      }
      decisions.set(d.id, d);
    }
    return decisions;
  }
  function runSummaryText(summary) {
    if (!object(summary)) return 'Analysis complete.';
    const details = [];
    if (typeof summary.model === 'string' && summary.model) details.push(`Model ${summary.model}`);
    if (Number.isFinite(summary.threshold)) details.push(`Threshold ${summary.threshold.toFixed(2)}`);
    if (Number.isInteger(summary.api_calls)) details.push(`${summary.api_calls} API call${summary.api_calls === 1 ? '' : 's'}`);
    if (Number.isInteger(summary.evaluated_candidates)) details.push(`${summary.evaluated_candidates} candidate${summary.evaluated_candidates === 1 ? '' : 's'} evaluated`);
    if (Number.isInteger(summary.related_candidates)) details.push(`${summary.related_candidates} related`);
    if (Number.isInteger(summary.reused_answers)) details.push(`${summary.reused_answers} answer${summary.reused_answers === 1 ? '' : 's'} reused`);
    if (Number.isInteger(summary.retried_requests)) details.push(`${summary.retried_requests} retr${summary.retried_requests === 1 ? 'y' : 'ies'}`);
    if (Number.isFinite(summary.elapsed_seconds)) details.push(`${summary.elapsed_seconds.toFixed(2)}s total`);
    if (Number.isFinite(summary.api_elapsed_seconds)) details.push(`${summary.api_elapsed_seconds.toFixed(2)}s in API calls`);
    if (Number.isInteger(summary.input_tokens) || Number.isInteger(summary.output_tokens)) {
      details.push(`${Number.isInteger(summary.input_tokens) ? summary.input_tokens : 0} input / ${Number.isInteger(summary.output_tokens) ? summary.output_tokens : 0} output tokens`);
    }
    if (typeof summary.resumed === 'boolean') details.push(summary.resumed ? 'Resumed run' : 'Fresh run');
    return details.length ? details.join(' · ') : 'Analysis complete.';
  }
  function renderFindings(result) {
    const target = $('findings'); target.replaceChildren();
    target.append(element('p', 'note', `Analysis ID: ${state.analysisId} · Seed confirmed malicious by analyst; Jev scores measure candidate relatedness, not independent maliciousness.`));
    if (result.summary !== undefined) target.append(element('p', 'summary', runSummaryText(result.summary)));
    target.append(element('p', 'note', `${state.decisions.size} ${BROWSER ? 'Jev' : 'server-issued'} decision(s) matched to source event IDs. Exact process-entity context is joined without a separate Jev score; other source events stay outside the incident timeline.`));
  }
  function validateNarrative(result) {
    if (!Array.isArray(result.timeline)) throw Error('Narrative response is missing a timeline array.');
    const known = new Set(state.rows.map(r => r.id));
    for (const entry of result.timeline) {
      if (!object(entry) || typeof entry.event_id !== 'string' || !known.has(entry.event_id) || typeof entry.title !== 'string' || typeof entry.summary !== 'string' || !Array.isArray(entry.evidence_ids) || !entry.evidence_ids.every(id => typeof id === 'string' && known.has(id))) {
        throw Error('Narrative contains missing fields or evidence IDs absent from this source.');
      }
    }
  }
  function renderNarrative(result) {
    const target = $('narrative'); target.replaceChildren();
    target.append(element('p', 'note', `Optional narrative · ${text(result.model)} · analyst review required. Generated text is not an evidence source.`));
    for (const item of result.timeline) {
      const article = element('article', 'event');
      article.append(element('div', 'time', state.rows.find(row => row.id === item.event_id).time || 'Time unavailable'), element('h3', '', item.title), element('p', '', item.summary));
      const refs = element('p', 'note');
      refs.append(element('span', '', 'Source event: '));
      const link = id => {
        const anchor = element('a', '', id);
        anchor.href = `#event-${state.rows.findIndex(row => row.id === id)}`;
        anchor.addEventListener('click', () => page('events'));
        return anchor;
      };
      refs.append(link(item.event_id), element('span', '', ' · Evidence IDs: '));
      item.evidence_ids.forEach((id, index) => {
        if (index) refs.append(element('span', '', ', '));
        refs.append(link(id));
      });
      if (!item.evidence_ids.length) refs.append(element('span', '', 'none'));
      article.append(refs);
      target.append(article);
    }
    if (!result.timeline.length) target.append(element('p', 'note', 'No narrative entries returned.'));
    state.drafts = new Map(result.timeline.map(item => [item.event_id, item]));
    renderTable();
  }
  function offerResume(count) {
    state.resumeOffered = true; state.resumeCount = count;
    $('resume').textContent = `Resume (${count} answered call${count === 1 ? '' : 's'} reused)`;
    $('resume').hidden = false;
  }
  async function runAction(kind) {
    if (state.busy) return;
    const narrate = kind === 'narrate';
    const resuming = kind === 'resume', resumeCount = state.resumeCount;
    // Analyze while a Resume is offered is a deliberate fresh start, so the server does not offer it again.
    const fresh = kind === 'analyze' && state.resumeOffered;
    if (resuming && !state.resumeOffered) { setStatus('No failed analysis to resume; run Analyze.', true); return; }
    const seedId = $('seed').value;
    const description = $('description').value.trim();
    if (!narrate && (!seedId || !description)) { setStatus('Choose a starting execution and enter analyst context.', true); return; }
    if (narrate && !state.analysisId) { setStatus('Analyze first; no server analysis ID exists.', true); return; }
    if (!providersUnlocked()) { setStatus('Unlock provider calls with the preview access code first; nothing was sent.', true); return; }
    if (BROWSER && !narrate && !state.keys.jev) { setStatus('Enter your TypeSafe API key under Your API keys first; nothing was sent.', true); return; }
    if (!narrate) resetAnalysis();
    const generation = state.generation;
    state.busy = true;
    $('analyze').disabled = $('narrate').disabled = true;
    setStatus(narrate ? 'Requesting optional narrative…' : resuming ? 'Resuming analysis; answered Jev calls are reused…'
      : BROWSER ? 'Sending events from this browser directly to TypeSafe…' : 'Sending events to the configured local backend…');
    try {
      const result = BROWSER ? await browserRun(kind, generation, seedId, description)
        : narrate ? await post('/api/narrate', {analysis_id:state.analysisId}, generation)
        : await post('/api/analyze', {events:state.events, seed_id:seedId, description, ...(resuming ? {resume:true} : fresh ? {fresh:true} : {})}, generation);
      if (generation !== state.generation) return;
      if (narrate) { validateNarrative(result); renderNarrative(result); page('table'); setStatus('Narrative received; verify every claim against evidence.'); }
      else {
        const decisions = validateDecisions(result);
        state.decisions = decisions;
        state.analysisId = result.analysis_id;
        if (BROWSER) { state.lastRun = result; $('download').hidden = false; }
        renderTimeline(); renderTable(); renderFindings(result); page('events');
        $('narrative').textContent = 'Narrative is optional and must be requested separately.';
        const reused = object(result.summary) && Number.isInteger(result.summary.reused_answers) ? result.summary.reused_answers : 0;
        setStatus(resuming ? `Jev relatedness received after resume (${reused} answer${reused === 1 ? '' : 's'} reused); analyst review required.` : 'Jev relatedness received; analyst review required.');
      }
    } catch (error) {
      if (generation === state.generation && error.name !== 'AbortError') {
        // 409 with a resume point: saved progress from an interrupted run, not a failure.
        const saved = !narrate && error.resumeAvailable && error.status === 409;
        setStatus(saved ? error.message : `${narrate ? 'Narrative' : 'Analysis'} failed: ${error.message}`, !saved);
        if (!narrate && error.resumeAvailable) offerResume(error.reusable);
        // The resume point is saved on the server, so it survives a lost response or a restart;
        // only an explicit 409 (nothing saved for these inputs) withdraws it.
        else if (resuming && error.status !== 409) offerResume(resumeCount);
      }
    } finally {
      if (generation === state.generation) {
        state.busy = false; state.controller = null;
        $('analyze').disabled = !$('seed').value;
        $('narrate').disabled = !state.analysisId || !state.providers.openrouter_configured;
      }
    }
  }
  // Browser mode runs the ported engine here; results have the same shape as /api/analyze and /api/narrate.
  async function browserRun(kind, generation, seedId, description) {
    const engine = globalThis.JevEngine;
    const controller = new AbortController();
    state.controller = controller;
    if (kind === 'narrate') return engine.narrate(state.events, [...state.decisions.values()], state.keys.openrouter, {signal:controller.signal});
    if (kind === 'analyze') state.resumeCache = new Map();
    return engine.analyze(state.events, seedId, description, state.keys.jev, {cache:state.resumeCache, resume:kind === 'resume', signal:controller.signal,
      onProgress:count => { if (generation === state.generation) setStatus(`Asking Jev from this browser… ${count} answer${count === 1 ? '' : 's'} so far`); }});
  }
  function downloadRun() {
    if (!state.lastRun) return;
    const bundle = {generated_by:'Casebench (browser)', seed_id:$('seed').value, description:$('description').value.trim(),
      summary:state.lastRun.summary, decisions:state.lastRun.decisions, attempts:state.lastRun.attempts};
    const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2) + '\n'], {type:'application/json'}));
    const link = document.createElement('a');
    link.href = url;
    link.download = `casebench-run-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  // The static site loads the bundled example as a script, so its policy needs no connection to its own host.
  function exampleScript() {
    if (globalThis.CASEBENCH_EXAMPLE) return Promise.resolve(globalThis.CASEBENCH_EXAMPLE);
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'examples/malicious_events.js';
      script.onload = () => globalThis.CASEBENCH_EXAMPLE ? resolve(globalThis.CASEBENCH_EXAMPLE) : reject(Error('Bundled example unavailable.'));
      script.onerror = () => reject(Error('Bundled example unavailable on this site.'));
      document.head.append(script);
    });
  }
  async function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_BYTES) { setStatus('File exceeds the 2 MiB limit; nothing loaded.', true); return; }
    try { load(JSON.parse(await file.text()), file.name); }
    catch (error) { setStatus(`Import failed: ${error.message}`, true); }
  }
  for (const id of ['setup', 'events', 'table']) $(`nav-${id}`).addEventListener('click', () => page(id));
  page(['setup','events','table'].includes(location.hash.slice(1)) ? location.hash.slice(1) : 'setup');
  if (BROWSER) {
    setupKeys();
    setupPrivacyNote();
    $('download').addEventListener('click', downloadRun);
  } else {
    $('backend').value = location.protocol !== 'file:' ? location.origin : 'http://127.0.0.1:8765';
    refreshProviders();
    $('refresh-provider').addEventListener('click', refreshProviders);
    $('unlock').addEventListener('click', unlock);
    $('access-code').addEventListener('keydown', e => { if (e.key === 'Enter') unlock(); });
  }
  $('choose').addEventListener('click', () => $('file').click());
  $('file').addEventListener('change', e => { loadFile(e.target.files[0]); e.target.value = ''; });
  $('preview').addEventListener('click', async () => {
    try {
      if (BROWSER) { load(await exampleScript(), 'Bundled malicious-events example'); return; }
      const response = await fetch('/examples/malicious_events.json', {credentials:'omit', cache:'no-store'});
      if (!response.ok) throw Error('Bundled example unavailable on this local server.');
      const body = await response.text();
      if (body.length > MAX_BYTES) throw Error('Bundled example exceeds the 2 MiB limit.');
      load(JSON.parse(body), 'Bundled malicious-events example');
    } catch (error) { setStatus(`Example load failed: ${error.message}`, true); }
  });
  for (const id of BROWSER ? ['seed', 'description'] : ['seed', 'description', 'backend']) $(id).addEventListener(id === 'description' || id === 'backend' ? 'input' : 'change', () => {
    state.resumeCache = new Map();  // Saved answers belong to the exact inputs they were asked with.
    if (state.analysisId || state.busy || state.resumeOffered) { resetAnalysis(); renderTimeline(); setStatus('Analysis cleared after input change; run Analyze again.'); }
    else if (id === 'seed') { renderTimeline(); renderTable(); }
  });
  $('analyze').addEventListener('click', () => runAction('analyze'));
  $('narrate').addEventListener('click', () => runAction('narrate'));
  $('resume').addEventListener('click', () => runAction('resume'));
  const drop = $('drop');
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); loadFile(e.dataTransfer.files[0]); });
  if (typeof module !== 'undefined' && module.exports) module.exports = {parseEvents, isExecution, backendOrigin, validateNarrative};
})();
