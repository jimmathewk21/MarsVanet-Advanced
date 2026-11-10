/* MarsNet visual client. No third-party JS framework or external APIs. */
'use strict';
const $ = (id) => document.getElementById(id);
const q = (selector) => document.querySelector(selector);
const qa = (selector) => [...document.querySelectorAll(selector)];
const WORLD = { width: 1100, height: 660 };
const SCENARIOS = {
  normal: 'Network operating normally',
  flood: 'UDP flood active · mobility-aware detection',
  misinformation: 'Malicious safety messages · trust evaluation',
  combined: 'Combined attack · multi-layer defense',
};
let state = null;
let lastPacketAt = 0;
let selectedVehicle = 'V07';
let vehicleInspected = false;
let selectedRsu = null;
const mapView = {zoom:1,x:0,y:0};
let drag = null;
let suppressMapClick = false;
let lastEventHash = '';
let initializedFields = false;
const animatedCars = new Map();
const motion = new Map();
const mapDisplay = {coverage:false, associations:false, packets:true, labels:false, attacks:true, lowEffects:false};
const reducedMotion = globalThis.matchMedia?.('(prefers-reduced-motion: reduce)');
const seenHandovers = new Set();
let handoverFx = null;
let demo = null;
let demoBusy = false;
let demoMessage = '';
let toastHandle;
let currentTab = 'overview';
let lastMapFrame = 0;
let timelineAfterId = 0;
let previewRequestId = 0;

function fmtNum(value) { return Intl.NumberFormat('en-US').format(value || 0); }
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function toast(message, error = false) {
  const node = $('toast');
  node.textContent = message;
  node.classList.toggle('error', error);
  node.classList.add('show');
  clearTimeout(toastHandle);
  toastHandle = setTimeout(() => node.classList.remove('show'), 3100);
}
async function post(path, data) {
  const json=await requestJSON(path,data);
  if(path==='/api/reset' || path==='/api/mobility')timelineAfterId=0;
  updateState(json);
  return json;
}
async function requestJSON(path,data) {
  const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  let json;
  try { json = await response.json(); } catch { throw new Error('Unexpected server response'); }
  if (!response.ok) throw new Error(json.error || `HTTP ${response.status}`);
  return json;
}
async function guarded(action, success) {
  try { await action(); if (success) toast(success); } catch (error) { toast(error.message, true); }
}
function showTab(name) {
  currentTab = name;
  qa('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.tab === name));
  qa('.tab-pane').forEach(n => n.classList.toggle('hidden', n.id !== `tab-${name}`));
  const info = {
    overview: ['OVERVIEW', 'Network overview', 'A living view of vehicle-to-vehicle and vehicle-to-infrastructure communication.'],
    policies: ['SDN CONTROL CENTER', 'SDN Control Center', 'Inspect simulated policy execution, configure rules, and test hypothetical packets.'],
    evidence: ['EXPERIMENT EVIDENCE', 'Controller evidence', 'Explore simulated throughput, forwarding decisions, and security events.'],
  }[name];
  $('breadcrumb').textContent = info[0];
  $('pageTitle').innerHTML = '';
  $('pageTitle').append(document.createTextNode(info[1]), el('span', 'title-period', '.'));
  $('pageDescription').textContent = info[2];
  if (name === 'policies' && state) { renderRules(); renderRuntimeFlows(); renderControlCenter(); renderEvents(); }
  if (name === 'evidence' && state) { renderReasons(); renderEvents(); }
}
function makeVehicleOptions(select, withAny = false) {
  if (withAny) { const option = el('option', '', 'Any source (*)'); option.value = '*'; select.append(option); }
  for (let i = 1; i <= 12; i++) {
    const id = `V${String(i).padStart(2, '0')}`;
    const option = el('option', '', id);
    option.value = id;
    select.append(option);
  }
  if (withAny) for (let i = 1; i <= 3; i++) {
    const option = el('option', '', `RSU-${i}`);
    option.value = `RSU-${i}`;
    select.append(option);
  }
}
function initializeControls() {
  makeVehicleOptions($('attackerSelect'));
  makeVehicleOptions($('victimSelect'));
  makeVehicleOptions($('ruleSource'), true);
  makeVehicleOptions($('ruleDestination'),true);
  $('ruleDestination').options[0].textContent='Any destination (*)';
  makeVehicleOptions($('eventVehicle'));
  $('attackerSelect').value = 'V07';
  $('victimSelect').value = 'V02';
  $('ruleSource').value = '*';
  qa('.nav-item').forEach(n => n.addEventListener('click', () => showTab(n.dataset.tab)));
  $('seeEventsBtn').addEventListener('click', () => showTab('evidence'));
  $('pauseBtn').addEventListener('click', () => guarded(() => post('/api/run', {running: !state.running})));
  $('resetBtn').addEventListener('click', () => {
    if (confirm('Restart vehicles, counters and reputation? Your configured rules and settings will remain.')) {
      stopDemo();
      guarded(() => post('/api/reset', {}), 'Simulation reset');
    }
  });
  $('speedSelect').addEventListener('change', () => guarded(() => post('/api/speed', {factor: Number($('speedSelect').value)}), 'Speed updated'));
  $('mobilitySelect').addEventListener('change', async () => {
    if (!confirm('Switching mobility engines resets the experiment (but keeps your rules/settings). Continue?')) {
      $('mobilitySelect').value = state.mobility_mode;return;
    }
    stopDemo();
    try { await post('/api/mobility',{mode:$('mobilitySelect').value}); toast('Mobility engine switched'); }
    catch(error) { $('mobilitySelect').value = state.mobility_mode; toast(error.message,true); }
  });
  qa('.scenario-btn').forEach(n => n.addEventListener('click', () => {
    stopDemo();
    guarded(() => post('/api/scenario', {scenario: n.dataset.scenario, attacker: $('attackerSelect').value, victim: $('victimSelect').value}),
      `Scenario: ${n.dataset.scenario.replace('_', ' ')}`);
  }));
  $('demoBtn').addEventListener('click', () => {
    if (!demo) return void startDemo();
    const {attacker, victim} = demo;
    stopDemo();
    demoMessage = 'Guide stopped; normal traffic restored while timed policies recover.';
    renderDemo();
    guarded(() => post('/api/scenario', {scenario:'normal', attacker, victim}));
  });
  for (const id of ['attackerSelect', 'victimSelect']) {
    $(id).addEventListener('change', () => {
      if (state) { stopDemo(); guarded(() => post('/api/scenario', {scenario: state.scenario, attacker: $('attackerSelect').value, victim: $('victimSelect').value})); }
    });
  }
  for (const [id, key] of [['m1Toggle', 'm1_enabled'], ['m2Toggle', 'm2_enabled'], ['m3Toggle', 'm3_enabled']]) {
    $(id).addEventListener('change', () => guarded(() => post('/api/config', {[key]: $(id).checked}), `${key.toUpperCase()} updated`));
  }
  $('configForm').addEventListener('submit', (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const config = {};
    for (const [key, value] of form.entries()) config[key] = Number(value);
    guarded(() => post('/api/config', config), 'Controller parameters applied live');
  });
  $('ruleAction').addEventListener('change', () => $('rateField').classList.toggle('rate-hidden', $('ruleAction').value !== 'METER'));
  $('clearRuleForm').addEventListener('click', clearRuleForm);
  $('ruleForm').addEventListener('submit', (event) => {
    event.preventDefault();
    const data = ruleDraft();
    const id = data.id;
    delete data.id;
    guarded(async () => {
      try {
        const result=await post(id ? `/api/rules/${encodeURIComponent(id)}` : '/api/rules', data);
        clearRuleForm();
        $('ruleFeedback').textContent=`Rule ${id?'updated':'installed'}. ${result.rule_warnings.length} active rule warning(s); inspect the warning list.`;
      } catch(error){$('ruleFeedback').textContent=error.message;throw error;}
    }, id ? 'Rule updated' : 'New rule installed');
  });
  $('checkRuleBtn').addEventListener('click',()=>guarded(async()=>{
    try{const result=await requestJSON('/api/rules-analyze',ruleDraft());
      $('ruleFeedback').textContent=result.warnings.length?result.warnings.map(w=>w.message).join(' '):'Draft valid. No active-rule overlap warnings. Nothing installed.';
    }catch(error){$('ruleFeedback').textContent=error.message;throw error;}
  }));
  $('policyPreviewForm').addEventListener('submit',event=>{
    event.preventDefault();const data=Object.fromEntries(new FormData(event.currentTarget).entries());
    data.size=Number(data.size);for(const key of ['src_port','dst_port'])data[key]=data[key]===''?null:Number(data[key]);
    const request=++previewRequestId;
    guarded(async()=>{
      try{const result=await requestJSON('/api/policy-preview',data);
        if(request===previewRequestId)$('policyPreviewResult').textContent=previewSummary(result);
      }catch(error){if(request===previewRequestId)$('policyPreviewResult').textContent=error.message;throw error;}
    });
  });
  for(const id of ['flowOrigin','flowStatus','flowSearch'])$(id).addEventListener('input',renderControlCenter);
  for(const id of ['eventOrigin','eventVehicle','eventSearch'])$(id).addEventListener('input',renderEvents);
  $('clearTimelineBtn').addEventListener('click',()=>{
    clearTimelineView();renderEvents();
    toast('Displayed history cleared; controller history retained');
  });
  $('exportBtn').addEventListener('click', () => { window.location.href = '/api/report'; toast('Downloading simulated evidence report'); });
  $('mapCanvas').addEventListener('click', (event) => {
    if (!state || suppressMapClick) { suppressMapClick=false; return; }
    const bounds = event.currentTarget.getBoundingClientRect();
    const {x,y} = mapPoint(event.clientX,event.clientY,bounds);
    const nearest = state.vehicles.reduce((best, vehicle) => {
      if (vehicle.mobility_active === false) return best;
      const pos = animatedCars.get(vehicle.id) || vehicle;
      const distance = Math.hypot(pos.x - x, pos.y - y);
      return distance < best.distance ? {vehicle, distance} : best;
    }, {vehicle:null, distance:28});
    if (nearest.vehicle) { selectedRsu=null;selectedVehicle = nearest.vehicle.id; vehicleInspected = true; updateInspector(); toast(`Inspecting ${selectedVehicle}`); }
    else {
      selectedRsu=state.rsus.find(r=>Math.hypot(r.x-x,r.y-y)<26)?.id || null;
      updateInspector();
    }
  });
  const canvas=$('mapCanvas');
  canvas.addEventListener('wheel',event=>{
    event.preventDefault();const bounds=canvas.getBoundingClientRect();
    zoomMap(event.deltaY<0?1.15:1/1.15,(event.clientX-bounds.left)/bounds.width*WORLD.width,(event.clientY-bounds.top)/bounds.height*WORLD.height);
  },{passive:false});
  canvas.addEventListener('pointerdown',event=>{drag={x:event.clientX,y:event.clientY,moved:false};suppressMapClick=false;canvas.setPointerCapture(event.pointerId);});
  canvas.addEventListener('pointermove',event=>{
    if(!drag)return;const bounds=canvas.getBoundingClientRect();
    const dx=event.clientX-drag.x,dy=event.clientY-drag.y;
    if(Math.abs(dx)+Math.abs(dy)>3 || drag.moved){mapView.x+=dx/bounds.width*WORLD.width;mapView.y+=dy/bounds.height*WORLD.height;clampView();drag.moved=true;}
    drag.x=event.clientX;drag.y=event.clientY;
  });
  canvas.addEventListener('pointerup',()=>{suppressMapClick=drag?.moved || false;drag=null;});
  canvas.addEventListener('pointercancel',()=>{drag=null;});
  $('zoomInBtn').addEventListener('click',()=>zoomMap(1.25));
  $('zoomOutBtn').addEventListener('click',()=>zoomMap(.8));
  $('resetViewBtn').addEventListener('click',()=>Object.assign(mapView,{zoom:1,x:0,y:0}));
  for (const input of qa('[data-map-display]')) {
    input.checked = mapDisplay[input.dataset.mapDisplay];
    input.addEventListener('change', () => setMapDisplay(input.dataset.mapDisplay,input.checked));
  }
  window.addEventListener('resize', () => { prepareCanvas($('mapCanvas')); prepareCanvas($('trafficCanvas')); });
  showTab('overview');
}
function clearRuleForm() {
  $('ruleForm').reset();
  $('ruleId').value = '';
  $('ruleSource').value = '*';
  $('ruleAction').value = 'DROP';
  $('rateField').classList.add('rate-hidden');
  $('saveRuleBtn').textContent = 'Save SDN rule';
}
function ruleDraft() {
  const form=new FormData($('ruleForm')),data=Object.fromEntries(form.entries());
  data.enabled=form.has('enabled');data.priority=Number(data.priority);data.rate_kbps=Number(data.rate_kbps);
  for(const key of ['src_port','dst_port'])data[key]=data[key]===''?null:Number(data[key]);
  if(!data.id)delete data.id;
  return data;
}
function demoTransition(phase, snapshot, startedAt, attackerId) {
  const attacker = snapshot.vehicles.find(v => v.id === attackerId);
  const elapsed = snapshot.time - startedAt;
  if (phase === 'baseline' && elapsed >= 5) return 'flood';
  if (phase === 'flood' && attacker?.m2_state === 'METER') return 'detected';
  if ((phase === 'flood' || phase === 'detected') && attacker?.m2_state === 'BLOCK') return 'mitigated';
  if ((phase === 'flood' || phase === 'detected') && elapsed >= 45) return 'stalled';
  if (phase === 'mitigated' && elapsed >= 3) return 'recovering';
  if (phase === 'recovering' && attacker?.m2_state === 'NORMAL' && elapsed >= 1) return 'complete';
  return phase;
}
function renderDemo() {
  const labels = {baseline:'Normal operation for 5 simulated seconds', flood:'Attack active; waiting for M2 Stage 1 detection',
    detected:'Stage 1 metering; waiting for the original dwell and Stage 2',
    mitigated:'Stage 2 temporary block observed; stopping the attack shortly',
    recovering:'Attack stopped; waiting for the timed M2 block to expire',
    stalled:'Stage 2 was not observed. Check M2, source coverage, and M1 DROP rules.',
    complete:'Recovery observed. The original rules and settings were preserved.'};
  const phase = demo?.phase || 'idle';
  $('demoStatus').textContent = labels[phase] || demoMessage || 'Baseline → attack → detection → mitigation → recovery. Uses your current rules and settings.';
  $('demoBtn').textContent = demo ? 'Stop guided demo' : 'Start guided demo';
  const order = ['baseline','flood','detected','mitigated','recovering'];
  const active = order.indexOf(phase);
  [...$('demoSteps').children].forEach((node, i) => node.classList.toggle('current', i === Math.max(0, active)));
}
function stopDemo() { if (demo) demoMessage = 'Guide stopped; scenario controls remain available.'; demo = null; renderDemo(); }
async function startDemo() {
  if (!state) return;
  if (!state.config.m2_enabled) { toast('Enable M2 before the guided DoS demo', true); return; }
  demoBusy = true;
  try {
    const attacker = $('attackerSelect').value, victim = $('victimSelect').value;
    const currentRsu = state.vehicles.find(v => v.id === attacker)?.rsu;
    const previewId=state.decision_inspector?.[attacker]?.preview.selected_static_rule;
    const staticDrop = previewId ? state.rules.find(r=>r.id===previewId && r.action==='DROP') : state.rules.find(r => !state.decision_inspector && r.enabled && r.action === 'DROP' &&
      (r.source === '*' || r.source === attacker) &&
      (r.traffic === '*' || r.traffic === 'UDP_FLOOD') &&
      (r.rsu === '*' || r.rsu === currentRsu));
    if (staticDrop && state.config.m1_enabled) throw new Error(`Disable M1 rule "${staticDrop.label}" for the M2 demo`);
    await post('/api/reset', {});
    if (!state.running) await post('/api/run', {running:true});
    await post('/api/scenario', {scenario:'normal', attacker, victim});
    demoMessage = '';
    demo = {phase:'baseline', at:state.time, attacker, victim};
    renderDemo();
  } catch(error) { toast(error.message, true); stopDemo(); }
  finally { demoBusy = false; }
}
async function advanceDemo() {
  if (!demo || demoBusy || !state.running) return;
  const next = demoTransition(demo.phase, state, demo.at, demo.attacker);
  if (next === demo.phase) return;
  demoBusy = true;
  try {
    if (next === 'flood' || next === 'recovering' || next === 'stalled') {
      await post('/api/scenario', {scenario:next === 'flood' ? 'flood' : 'normal',
        attacker:demo.attacker, victim:demo.victim});
    }
    demo.phase = next;
    demo.at = state.time;
    renderDemo();
    if (next === 'complete' || next === 'stalled') { demoMessage = $('demoStatus').textContent; toast(demoMessage, next === 'stalled'); demo = null; renderDemo(); }
  } catch(error) { toast(error.message, true); stopDemo(); }
  finally { demoBusy = false; }
}
function rememberHandovers(snapshot) {
  for (const event of [...snapshot.events].reverse()) {
    if (event.kind !== 'HANDOVER') continue;
    const key = `${event.time}:${event.message}`;
    if (seenHandovers.has(key)) continue;
    seenHandovers.add(key);
    if (snapshot.time - event.time <= 2) {
      const match = event.message.match(/^(V\d+): (RSU-\d+) → (RSU-\d+)/);
      if (match) handoverFx = {vehicle:match[1], from:match[2], to:match[3], at:snapshot.time};
    }
  }
  if (seenHandovers.size > 200) seenHandovers.clear();
  const banner = $('handoverBanner');
  banner.hidden = !handoverFx || snapshot.time - handoverFx.at > 4;
  if (!banner.hidden) banner.textContent = `HANDOVER  ${handoverFx.vehicle}: ${handoverFx.from} → ${handoverFx.to}`;
}
function setMapDisplay(key,enabled) {
  if (Object.hasOwn(mapDisplay,key)) mapDisplay[key] = Boolean(enabled);
}
function clearAnimationState() {
  animatedCars.clear(); motion.clear(); seenHandovers.clear(); handoverFx = null;
}
function mapPoint(clientX,clientY,bounds) {
  return {x:((clientX-bounds.left)/bounds.width*WORLD.width-mapView.x)/mapView.zoom,
    y:((clientY-bounds.top)/bounds.height*WORLD.height-mapView.y)/mapView.zoom};
}
function clampView() {
  mapView.x=Math.max(WORLD.width*(1-mapView.zoom),Math.min(0,mapView.x));
  mapView.y=Math.max(WORLD.height*(1-mapView.zoom),Math.min(0,mapView.y));
}
function zoomMap(factor,x=WORLD.width/2,y=WORLD.height/2) {
  const old=mapView.zoom;
  mapView.zoom=Math.min(3,Math.max(1,old*factor));
  mapView.x=x-(x-mapView.x)*mapView.zoom/old;
  mapView.y=y-(y-mapView.y)*mapView.zoom/old;clampView();
}
function updateState(newState) {
  if (state && newState.time < state.time - .1) {
    clearAnimationState();
    timelineAfterId=0;
  }
  if(state?.controller_events?.[0]?.id > newState.controller_events?.[0]?.id)timelineAfterId=0;
  const receivedAt = performance.now();
  const previous = state;
  const noAnimation = reducedMotion?.matches;
  for (const vehicle of newState.vehicles) {
    const old = previous?.vehicles.find(v => v.id === vehicle.id);
    const start = animatedCars.get(vehicle.id) || old || vehicle;
    const elapsed = old ? newState.time - previous.time : 0;
    if (old && elapsed===0 && newState.running && old.x===vehicle.x && old.y===vehicle.y) continue;
    const trace=vehicle.motion_trace || [];
    const startTime=start.time ?? previous?.time ?? newState.time;
    const stale=trace.length && startTime<trace[0].time-.1;
    const duration = motionDuration(elapsed,newState.speed_factor,newState.running,noAnimation || stale || old?.mobility_active===false);
    motion.set(vehicle.id, {from:{x:start.x,y:start.y,angle:start.angle,time:startTime}, to:{...vehicle,time:newState.time},
      at:receivedAt, duration, corner:routeCorner(start,vehicle),trace});
    if (!animatedCars.has(vehicle.id)) animatedCars.set(vehicle.id, {x:vehicle.x,y:vehicle.y,angle:vehicle.angle,time:newState.time,rsu:vehicle.rsu});
  }
  for (const id of animatedCars.keys()) if (!newState.vehicles.some(v => v.id === id)) { animatedCars.delete(id); motion.delete(id); }
  state = newState;
  lastPacketAt = receivedAt;
  rememberHandovers(state);
  $('attackerSelect').value = state.attacker;
  $('victimSelect').value = state.victim;
  renderStats();
  updateInspector();
  const eventHash = state.events.slice(0, 65).map(e => `${e.id}:${e.time}:${e.kind}:${e.message}`).join('|');
  if (eventHash !== lastEventHash) { lastEventHash = eventHash; renderEvents(); }
  if (currentTab === 'policies') { renderRules(); renderRuntimeFlows(); renderControlCenter(); }
  if (currentTab === 'evidence') renderReasons();
  if (!initializedFields) {
    $('configForm').querySelectorAll('input').forEach(input => { input.value = state.config[input.name]; });
    initializedFields = true;
  }
  for (const [id, key] of [['m1Toggle', 'm1_enabled'], ['m2Toggle', 'm2_enabled'], ['m3Toggle', 'm3_enabled']]) $(id).checked = state.config[key];
  $('connDot').classList.remove('offline');
  $('connText').textContent = 'SYSTEM ONLINE';
  if (demo) void advanceDemo();
}
function renderStats() {
  const stats = state.stats;
  $('statSent').textContent = fmtNum(stats.sent);
  $('statPdr').textContent = `${stats.pdr.toFixed(1)}%`;
  $('statLegit').textContent = `${stats.legit_pdr.toFixed(1)}%`;
  $('statDrops').textContent = fmtNum(stats.dropped);
  $('statMeter').textContent = fmtNum(stats.rate_limited);
  $('statMitigations').textContent = String(stats.enforced_vehicles);
  $('statHandovers').textContent = fmtNum(stats.handovers);
  const s = Math.floor(state.time);
  $('simClock').textContent = `T + ${String(Math.floor(s/60)).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`;
  $('pauseText').textContent = state.running ? 'Pause' : 'Resume';
  $('pauseIcon').textContent = state.running ? 'Ⅱ' : '▶';
  $('speedSelect').value = String(state.speed_factor);
  $('mobilitySelect').value = state.mobility_mode || 'builtin';
  $('mobilityBadge').textContent=state.mobility_mode==='sumo'?'SUMO / TraCI':state.mobility_model==='legacy'?'Built-in / legacy':'Built-in / lane v2';
  qa('.scenario-btn').forEach(n => n.classList.toggle('active', n.dataset.scenario === state.scenario));
  $('scenarioDescription').textContent = SCENARIOS[state.scenario];
  $('scenarioLed').classList.toggle('alert', state.scenario !== 'normal');
  $('livePps').textContent = `${stats.pps} pkt/s`;
  $('dataPlaneText').textContent = `${fmtNum(stats.delivered)} forwarded`;
  $('controlPlaneText').textContent = `${['m1_enabled', 'm2_enabled', 'm3_enabled'].filter(k => state.config[k]).length} policies active`;
  $('reportForwarded').textContent = fmtNum(stats.delivered);
  $('reportM1').textContent = fmtNum(stats.m1_dropped);
  $('reportM2').textContent = fmtNum(stats.m2_dropped);
  $('reportMeter').textContent = fmtNum(stats.rate_limited);
  $('reportBad').textContent = fmtNum(stats.invalid_safety);
  $('reportHandover').textContent = fmtNum(stats.handovers);
}
function updateInspector() {
  if (!state) return;
  const rsu=state.rsus.find(r=>r.id===selectedRsu);
  $('vehicleInspector').hidden=Boolean(rsu);$('rsuInspector').hidden=!rsu;
  if(rsu){
    $('inspectorTitle').textContent=rsu.id;
    $('nodeBadge').textContent='ROADSIDE UNIT';$('nodeBadge').classList.toggle('disconnected',false);
    $('rsuCoverage').textContent=`${state.config.rsu_range} m modeled radius`;
    $('rsuVehicles').textContent=(rsu.associated_vehicles || []).join(', ') || 'No associated vehicles';
    const traffic=rsu.traffic || {};
    $('rsuTraffic').textContent=`${fmtNum(traffic.path_attempts)} path attempts · ${fmtNum(traffic.path_delivered)} delivered · ${fmtNum(traffic.path_dropped)} dropped`;
    $('rsuBytes').textContent=`${fmtNum(traffic.delivered_bytes)} bytes on successful modeled paths`;
    return;
  }
  const vehicle = state.vehicles.find(v => v.id === selectedVehicle) || state.vehicles[0];
  $('inspectorTitle').textContent = `Vehicle ${vehicle.id}`;
  $('vehicleId').textContent = vehicle.id;
  $('vehicleLocation').textContent = `x ${Math.round(vehicle.x)}m · y ${Math.round(vehicle.y)}m · ${state.packet_schema?.node_ips[vehicle.id] || 'modeled node'}`;
  $('nodeBadge').textContent = vehicle.rsu ? 'CONNECTED' : 'V2V ONLY';
  $('nodeBadge').classList.toggle('disconnected', !vehicle.rsu);
  $('trustValue').textContent = vehicle.reputation.toFixed(2);
  $('trustValue').style.color = vehicle.reputation < .4 ? '#f5777b' : vehicle.reputation < .7 ? '#ffac62' : '#71dcb2';
  $('trustBar').style.width = `${vehicle.reputation * 100}%`;
  $('trustBar').style.background = vehicle.reputation < .4 ? '#f5777b' : vehicle.reputation < .7 ? '#ffac62' : 'linear-gradient(90deg,#28b3a0,#79e2bc)';
  $('nodeSecurity').textContent = vehicle.m2_state === 'BLOCK' ? 'M2 TEMP BLOCK' : vehicle.m3_state;
  $('nodeSecurity').style.color = vehicle.m2_state === 'BLOCK' || vehicle.reputation < .4 ? '#f5777b' : '#dce7ee';
  $('nodeRsu').textContent = vehicle.rsu || 'Out of range';
  $('nodeSpeed').textContent = `${vehicle.speed.toFixed(0)} km/h · ${vehicle.movement || 'driving'}`;
  $('nodePps').textContent = `${vehicle.pps} pkt/s`;
  const policy = state.runtime_policies.find(p => p.vehicle === vehicle.id);
  $('nodeM2').textContent = `${vehicle.m2_state} / ${vehicle.threshold} pps`;
  $('nodeM3').textContent = vehicle.m3_kbps ? `${vehicle.m3_state} · ${vehicle.m3_kbps} kbps` : vehicle.m3_state;
  const staticRule = state.rules.find(r => r.id === policy?.static_rule_id);
  $('nodeRule').textContent = staticRule ? `${staticRule.label} (${staticRule.action})` : 'None';
  $('nodeMeter').textContent = policy?.effective_udp_action === 'DROP' ? 'UDP DROP' :
    policy?.effective_udp_meter_kbps ? `${policy.effective_udp_meter_kbps} kbps (UDP)` : 'NONE';
  $('nodeHandovers').textContent = vehicle.handovers;
  const decision=state.decision_inspector?.[vehicle.id];
  $('nodeDecisionPreview').textContent=decision?previewSummary(decision.preview):'No authoritative policy preview available.';
  $('nodeLastDecision').textContent=actualDecisionSummary(decision?.last_packet);
  $('nodeMessages').textContent=`${fmtNum(vehicle.sent)} sent · ${fmtNum(vehicle.received)} received · ${fmtNum(vehicle.dropped)} source drops`;
  const attached=state.rsus.find(r=>r.id===vehicle.rsu);
  const margin=attached?state.config.rsu_range-Math.hypot(vehicle.x-attached.x,vehicle.y-attached.y):null;
  $('nodeCoverage').textContent=vehicle.mobility_active===false?'Not present in SUMO':margin===null?'Outside coverage':margin<45?`Boundary approaching (${Math.max(0,margin).toFixed(0)} m margin)`:`${margin.toFixed(0)} m to boundary`;
}
function renderEvents() {
  if (!state) return;
  for (const [id, max] of [['eventList', 5], ['fullEventList', 180],['controlEventList',180]]) {
    const target = $(id);
    target.replaceChildren();
    const events=id==='eventList'?state.events:filterControllerEvents(state.controller_events || state.events,{
      origin:$('eventOrigin').value,vehicle:$('eventVehicle').value,query:$('eventSearch').value,afterId:timelineAfterId});
    if(!events.length)target.append(el('p','subline','No events match this view. Controller history is unchanged.'));
    for (const e of events.slice(0, max)) {
      const entry = el('div', 'event');
      const symbol = el('span', `event-symbol ${e.level}`, e.level === 'danger' ? '!' : e.level === 'warning' ? '⚠' : e.level === 'success' ? '✓' : '↳');
      const content = el('div', 'event-content');
      content.append(el('strong', '', `${e.origin || 'System'} · ${e.vehicle || 'network'} · ${e.kind}`), el('p', '', e.message));
      entry.append(symbol, content, el('span', 'event-time', `${e.time.toFixed(1)}s`));
      target.append(entry);
    }
  }
}
function renderRules() {
  if (!state) return;
  const target = $('rulesList');
  target.replaceChildren();
  const sorted = [...state.rules].sort((a,b) => b.priority-a.priority);
  $('ruleCount').textContent = sorted.length;
  if (!sorted.length) target.append(el('p','subline','No static rules configured yet. Add one using the editor.'));
  for (const r of sorted) {
    const box = el('article',`rule-item ${r.enabled ? '' : 'rule-disabled'}`);
    const head = el('div','rule-top');
    const title = el('div');
    const hits=state.flow_table?.find(flow=>flow.id===r.id)?.match_count || 0;
    title.append(el('h4','',r.label),el('small','',`${r.id} · Priority ${r.priority} · ${r.enabled?'ENABLED':'DISABLED'} · ${hits} selected packet hits`));
    head.append(title,el('span',`rule-chip ${r.action.toLowerCase()}`,r.action));
    const chips = el('div','rule-details');
    for (const item of [`SRC ${r.source} / ${r.source_ip || '*'}`,`DST ${r.destination || '*'} / ${r.destination_ip || '*'}`,`${r.protocol || '*'} ${r.src_port ?? '*'} → ${r.dst_port ?? '*'}`,`TYPE ${r.traffic}`,`RSU ${r.rsu}`,...(r.action==='METER'?[`${r.rate_kbps} kbps`]:[])]) chips.append(el('span','rule-chip',item));
    const actions = el('div','rule-actions');
    for (const [name, handler] of [
      ['Edit', () => editRule(r)],
      [r.enabled?'Disable':'Enable', () => guarded(() => post(`/api/rules/${r.id}/toggle`,{}),
        `Rule ${r.enabled ? 'disabled' : 'enabled'}: ${r.label}`)],
      ['Delete', () => { if (confirm(`Delete rule "${r.label}"?`)) guarded(() => post('/api/rules-delete',{id:r.id}),'Rule removed'); }],
    ]) { const button = el('button','',name);button.type='button';button.addEventListener('click',handler);actions.append(button); }
    box.append(head,chips,actions);
    target.append(box);
  }
}
function editRule(rule) {
  const form = $('ruleForm');
  form.reset();
  for (const [key,value] of Object.entries(rule)) if (form.elements[key] && key!=='enabled') form.elements[key].value = value === null ? '' : value;
  form.elements.enabled.checked = rule.enabled;
  $('rateField').classList.toggle('rate-hidden',rule.action!=='METER');
  $('saveRuleBtn').textContent='Update SDN rule';
  form.scrollIntoView({behavior:reducedMotion?.matches?'auto':'smooth',block:'center'});
}
function renderRuntimeFlows() {
  const target = $('runtimeFlowList');
  if (!target || !state) return;
  target.replaceChildren();
  const flows = state.runtime_policies || [];
  if (!flows.length) {
    target.append(el('p','subline','No dynamic mitigations currently installed. Start a flood or misinformation scenario to see automatic policy changes.'));
    return;
  }
  for(const r of flows) {
    const row = el('div','runtime-row');
    const label = el('strong','',r.vehicle);
    const source = el('small','',r.rsu || 'V2V / uncovered');
    const cells = el('div','runtime-chips');
    if(r.static_action)cells.append(el('span','rule-chip',`M1 ${r.static_action}`));
    if(r.m2_state !== 'NORMAL' && r.m2_state !== 'DISABLED')cells.append(el('span',`rule-chip ${r.m2_state==='BLOCK'?'drop':'meter'}`,`M2 ${r.m2_state}`));
    if(r.m3_meter_kbps)cells.append(el('span','rule-chip meter',`M3 ${r.m3_meter_kbps} kbps`));
    cells.append(el('span','rule-chip',`UDP ${r.effective_udp_action}${r.effective_udp_meter_kbps ? ` ${r.effective_udp_meter_kbps} kbps` : ''}`));
    row.append(label,source,cells);target.append(row);
  }
}
function previewSummary(result) {
  return `PREVIEW: ${result.action}${result.meter_rate_kbps ? ` · ${result.meter_rate_kbps} kbps` : ''} · ${result.deciding_rule}. `+
    `${result.reason} Matching static rules: ${result.matching_rules.join(', ') || 'none'}. `+
    `Candidate meters: ${(result.meters || []).map(m=>`${m.id} ${m.rate_kbps} kbps`).join(', ') || 'none'}. `+
    'No packet was observed; detector updates, token availability and link delivery are not predicted.';
}
function actualDecisionSummary(result) {
  if(!result)return 'No packet from this source has been processed.';
  return `ACTUAL #${result.sequence} at ${result.time.toFixed(3)}s: ${result.packet.traffic} → ${result.packet.destination}. `+
    `${result.policy_action} by ${result.deciding_rule}; outcome ${result.outcome}. ${result.reason || ''} Selected/applied rules: ${result.matched_rules.join(', ')}.`;
}
function clearTimelineView() {
  timelineAfterId=Math.max(0,...(state?.controller_events || []).map(e=>e.id));
}
function filterControllerEvents(events,{origin='',vehicle='',query='',afterId=0}={}) {
  const text=(query || '').toLowerCase();
  return events.filter(e=>e.id>afterId && (!origin || e.origin===origin) && (!vehicle || e.vehicle===vehicle) &&
    (!text || `${e.kind} ${e.message}`.toLowerCase().includes(text)));
}
function filterFlows(flows,{origin='',status='',query=''}={}) {
  const text=(query || '').toLowerCase();
  return flows.filter(row=>(!origin || row.origin===origin) && (!status || row.active===(status==='active')) &&
    (!text || [row.id,row.source,row.destination,row.source_ip,row.destination_ip].join(' ').toLowerCase().includes(text)));
}
function renderControlCenter() {
  if(!state)return;
  const target=$('flowTable');target.replaceChildren();
  const table=el('table','flow-table'),head=el('thead'),tr=el('tr');
  for(const name of ['Rule ID','Origin / tier','Priority','Source / IPv4','Destination / IPv4','Protocol / ports','Traffic / RSU','Action','Rate kbps','Hits','Last match s','Status','Lifetime'])tr.append(el('th','',name));
  head.append(tr);table.append(head);const body=el('tbody');
  const flows=filterFlows(state.flow_table || [],{origin:$('flowOrigin').value,status:$('flowStatus').value,query:$('flowSearch').value});
  for(const flow of flows){
    const row=el('tr',flow.active?'':'inactive-flow');
    const cells=[flow.id,`${flow.origin} / ${['User','M1'].includes(flow.origin)?'static':'dynamic/system'}`,flow.priority,
      `${flow.source || '*'} / ${flow.source_ip || '*'}`,`${flow.destination || '*'} / ${flow.destination_ip || '*'}`,
      `${flow.protocol || '*'} ${flow.src_port ?? '*'} → ${flow.dst_port ?? '*'}`,`${flow.traffic || '*'} / ${flow.rsu || '*'}`,
      flow.action,flow.rate_kbps ?? '—',fmtNum(flow.match_count),flow.last_matched===null?'—':flow.last_matched.toFixed(3),
      flow.active?'ACTIVE':'INACTIVE',flow.temporary?flow.origin==='M3'?'Dynamic reputation':flow.active?`Temporary to ${flow.expires_at.toFixed(2)}s`:'Temporary / inactive':'Persistent'];
    for(const value of cells)row.append(el('td','',String(value)));
    body.append(row);
  }
  table.append(body);target.append(table);
  if(!flows.length)target.append(el('p','subline','No flows match these filters.'));
  const warnings=$('ruleWarnings');warnings.replaceChildren();
  for(const warning of state.rule_warnings || [])warnings.append(el('p','',`${warning.kind.toUpperCase()} · ${warning.rule_id}: ${warning.message}`));
}
function renderReasons() {
  if (!state) return;
  const target = $('reasonBars');
  target.replaceChildren();
  const filtered = Object.entries(state.reasons).filter(([reason,count]) => reason !== 'FORWARDED' && count > 0).sort((a,b) => b[1]-a[1]).slice(0,7);
  if (!filtered.length) return target.append(el('p','subline','No packet drops have been recorded yet.'));
  const max = Math.max(...filtered.map(r => r[1]));
  for (const [reason,count] of filtered) {
    const row=el('div');
    const label=el('div','reason-label');label.append(el('span','',reason.replaceAll('_',' ')),el('b','',fmtNum(count)));
    const rail=el('div','reason-bar');
    const fill=el('div');fill.style.width=`${100*count/max}%`;rail.append(fill);
    row.append(label,rail);target.append(row);
  }
}
function prepareCanvas(canvas) {
  const rect=canvas.getBoundingClientRect();
  const dpr=Math.min(window.devicePixelRatio||1,2);
  if (!rect.width || !rect.height) return null;
  const width=Math.round(rect.width*dpr),height=Math.round(rect.height*dpr);
  if (canvas.width!==width || canvas.height!==height) {canvas.width=width;canvas.height=height;}
  const ctx=canvas.getContext('2d');
  return {ctx,width,height};
}
function rr(ctx,x,y,w,h,r,fill,stroke) {
  ctx.beginPath();ctx.roundRect(x,y,w,h,r);
  if(fill){ctx.fillStyle=fill;ctx.fill();}
  if(stroke){ctx.strokeStyle=stroke;ctx.stroke();}
}
function road(ctx,points,width=62) {
  ctx.beginPath();
  ctx.moveTo(points[0][0],points[0][1]);
  for(let i=1;i<points.length;i++)ctx.lineTo(points[i][0],points[i][1]);
  ctx.strokeStyle='#24343f';ctx.lineWidth=width+7;ctx.lineJoin='round';ctx.lineCap='round';ctx.stroke();
  ctx.strokeStyle='#2a3b46';ctx.lineWidth=width;ctx.stroke();
  ctx.setLineDash([16,14]);ctx.strokeStyle='#ccd5bc70';ctx.lineWidth=1.5;ctx.stroke();ctx.setLineDash([]);
  ctx.lineWidth=1;
}
function drawBackground(ctx,clock) {
  const W=WORLD.width,H=WORLD.height;
  ctx.fillStyle='#10202a';ctx.fillRect(0,0,W,H);
  ctx.strokeStyle='#1c344038';ctx.lineWidth=1;
  for(let x=0;x<W;x+=26){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
  for(let y=0;y<H;y+=26){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
  const parks=[[100,42,138,75],[345,213,128,82],[610,377,154,90],[889,560,134,63]];
  for(const [x,y,w,h] of parks){rr(ctx,x,y,w,h,7,'#1b3431','#294b48');ctx.fillStyle='#254b42';for(let k=0;k<11;k++){const xx=x+15+(k*31)%(w-26),yy=y+13+(k*19)%(h-24);ctx.beginPath();ctx.arc(xx,yy,5,0,Math.PI*2);ctx.fill();}}
  const buildings=[[385,57,110,69],[533,60,145,63],[715,45,80,70],[932,236,91,57],[68,234,110,52],[357,403,103,68],[668,221,99,75],[880,405,114,72],[70,577,101,51],[386,550,100,47]];
  for(const [x,y,w,h] of buildings){rr(ctx,x+7,y+7,w,h,5,'#15212a');rr(ctx,x,y,w,h,5,'#1c2b35','#355260');ctx.fillStyle='#3b5360';for(let i=16;i<w-8;i+=22)for(let j=12;j<h-8;j+=18)ctx.fillRect(x+i,y+j,7,4);}
  road(ctx,[[90,90],[1010,90]],52);road(ctx,[[90,170],[1010,170]],62);road(ctx,[[90,330],[1010,330]],63);
  road(ctx,[[90,520],[1010,520]],62);road(ctx,[[90,590],[1010,590]],50);
  road(ctx,[[90,90],[90,590]],53);road(ctx,[[270,90],[270,590]],61);road(ctx,[[840,90],[840,590]],61);road(ctx,[[1010,90],[1010,590]],58);
  const intersections=[[270,170],[840,170],[270,330],[840,330],[270,520],[840,520]];
  for(const [x,y] of intersections){
    ctx.fillStyle='#2a3b46';ctx.fillRect(x-29,y-29,58,58);
    ctx.strokeStyle='#c5d5da65';ctx.lineWidth=2;
    for(const sign of [-1,1]){ctx.beginPath();ctx.moveTo(x+sign*24,y+sign*3);ctx.lineTo(x+sign*24,y+sign*20);ctx.stroke();}
    const phase=(state?.time || 0)%32;
    for(const [dx,dy,green] of (state?.mobility_mode==='sumo' || state?.mobility_model==='legacy' ? [] : [[-25,24,phase<14],[25,-24,phase>=16&&phase<30]])){
      ctx.fillStyle=green?'#71dcb2':'#f5777b';ctx.beginPath();ctx.arc(x+dx,y+dy,3,0,Math.PI*2);ctx.fill();
    }
  }
  ctx.save();ctx.font='700 11px Segoe UI,Arial';ctx.fillStyle='#799aaa';ctx.globalAlpha=.8;
  for(const [x,y,name] of [[140,127,'NORTH ARTERIAL'],[569,298,'CENTRAL EXPRESSWAY'],[400,485,'SOUTH LOOP'],[290,635,'NETWORK GRID / SIMULATED METERS']])ctx.fillText(name,x,y);
  ctx.restore();
  // Radar sweep from software-defined control plane, intentionally non-physical visualization.
  const cx=548,cy=320;
  ctx.save();ctx.globalAlpha=.28;ctx.setLineDash([4,10]);ctx.strokeStyle='#4bdfd9';ctx.beginPath();ctx.arc(cx,cy,62,0,Math.PI*2);ctx.stroke();ctx.restore();
}
function drawRSUs(ctx,now) {
  if(!state)return;
  for(const r of state.rsus){
    if (mapDisplay.coverage || selectedRsu===r.id || (vehicleInspected && state.vehicles.find(v=>v.id===selectedVehicle)?.rsu===r.id)) {
      const radius=state.config.rsu_range;
      const gradient=ctx.createRadialGradient(r.x,r.y,10,r.x,r.y,radius);
      gradient.addColorStop(0,'rgba(68,159,208,.075)');gradient.addColorStop(1,'rgba(68,159,208,0)');
      ctx.fillStyle=gradient;ctx.beginPath();ctx.arc(r.x,r.y,radius,0,Math.PI*2);ctx.fill();
      ctx.strokeStyle='#4e9ecb28';ctx.lineWidth=1;ctx.setLineDash([8,11]);ctx.beginPath();ctx.arc(r.x,r.y,radius,0,Math.PI*2);ctx.stroke();ctx.setLineDash([]);
    }
    ctx.save();ctx.translate(r.x,r.y);ctx.rotate(Math.PI/4);rr(ctx,-15,-15,30,30,4,'#214b67','#7cc6ef');ctx.restore();
    ctx.fillStyle='#b7e8fc';ctx.beginPath();ctx.arc(r.x,r.y,5,0,Math.PI*2);ctx.fill();
    rr(ctx,r.x-43,r.y+27,86,30,4,'#0c1b2cdd','#3b5d70');
    ctx.fillStyle='#c4eafa';ctx.font='700 11px Segoe UI,Arial';ctx.textAlign='center';ctx.fillText(r.id,r.x,r.y+39);
    ctx.fillStyle='#89acc0';ctx.font='10px Segoe UI,Arial';ctx.fillText(`${r.vehicles} connected`,r.x,r.y+52);
    ctx.textAlign='left';
  }
}
function drawAssociations(ctx) {
  if (!state) return;
  ctx.save();
  for (const v of state.vehicles) {
    if (!mapDisplay.associations && (!vehicleInspected || v.id !== selectedVehicle)) continue;
    if(v.mobility_active===false)continue;
    const car = animatedCars.get(v.id);
    const association=car && Object.hasOwn(car,'rsu') ? car.rsu : v.rsu;
    const rsu = state.rsus.find(r => r.id === association);
    if (!rsu || !car) continue;
    const selected = v.id === selectedVehicle;
    ctx.strokeStyle = selected ? '#87eadb88' : '#69b9d326';
    ctx.lineWidth = selected ? 2 : 1;
    ctx.setLineDash([5, 8]);ctx.beginPath();ctx.moveTo(car.x,car.y);ctx.lineTo(rsu.x,rsu.y);ctx.stroke();
  }
  ctx.restore();
}
function drawPackets(ctx,now) {
  if(!state || !mapDisplay.packets)return;
  const quiet = mapDisplay.lowEffects || reducedMotion?.matches;
  const fractionalTime=state.time+Math.min(.65,(now-lastPacketAt)/1000)*(state.running?state.speed_factor:0);
  let count=0,attacks=0;
  for(const packet of state.pulses.slice().reverse()){
    if (count >= (quiet ? 5 : 14)) break;
    const age=fractionalTime-packet.t;
    if(age<0||age>1.15||!packet.route||packet.route.length<2)continue;
    if(packet.traffic==='UDP_FLOOD' && attacks >= (quiet ? 2 : 5))continue;
    count++;
    if(packet.traffic==='UDP_FLOOD')attacks++;
    const visual=packetVisual(packet), color=visual.color;
    const isThreat=packet.traffic==='UDP_FLOOD';
    const alpha=Math.max(0,Math.min(1,(1.15-age)*1.7));
    const path=packet.route;
    ctx.save();
    let lengths=[],whole=0;
    for(let k=1;k<path.length;k++){const len=Math.hypot(path[k].x-path[k-1].x,path[k].y-path[k-1].y);lengths.push(len);whole+=len;}
    let progress=(reducedMotion?.matches?visual.stop:Math.min(visual.stop,age/.6*visual.stop))*whole;
    let pt=path[path.length-1];
    for(let k=0;k<lengths.length;k++)if(progress<=lengths[k]){const ratio=lengths[k]?progress/lengths[k]:0;pt={x:path[k].x+(path[k+1].x-path[k].x)*ratio,y:path[k].y+(path[k+1].y-path[k].y)*ratio};break;}else progress-=lengths[k];
    ctx.globalAlpha=alpha;ctx.shadowBlur=quiet?0:8;ctx.shadowColor=color;ctx.fillStyle=color;ctx.beginPath();ctx.arc(pt.x,pt.y,isThreat?4.2:3.3,0,Math.PI*2);ctx.fill();
    ctx.shadowBlur=0;
    if(packet.traffic==='SAFETY' && packet.link==='V2V'){ctx.strokeStyle=color;ctx.strokeRect(pt.x-5,pt.y-5,10,10);}
    if(packet.traffic==='BEACON'){ctx.strokeStyle=color;ctx.beginPath();ctx.arc(pt.x,pt.y,7,0,Math.PI*2);ctx.stroke();}
    if(!packet.ok && age>.3){ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();ctx.moveTo(pt.x-4,pt.y-4);ctx.lineTo(pt.x+4,pt.y+4);ctx.moveTo(pt.x+4,pt.y-4);ctx.lineTo(pt.x-4,pt.y+4);ctx.stroke();}
    ctx.restore();
  }
}
function packetVisual(packet) {
  if (packet.reason === 'RATE_LIMIT') return {color:'#ffbf6b', stop:.58, label:'Rate-limited'};
  if (!packet.ok) return {color:packet.reason === 'RADIO_LOSS' ? '#abb5c2' : '#f5777b', stop:.58, label:'Dropped'};
  if (packet.traffic === 'UDP_FLOOD') return {color:'#ff857c', stop:1, label:'Flood delivered'};
  if (packet.traffic === 'SAFETY') return {color:'#8cf2df', stop:1, label:'Safety delivered'};
  if (packet.traffic === 'BEACON') return {color:'#b3a0f3', stop:1, label:'RSU beacon'};
  return {color:'#55d8e5', stop:1, label:'Data delivered'};
}
function drawHandover(ctx,now) {
  if (!handoverFx || !state || state.time - handoverFx.at > 4) return;
  if (!state.vehicles.some(v=>v.id===handoverFx.vehicle && v.mobility_active!==false))return;
  const car=animatedCars.get(handoverFx.vehicle);
  if (!car) return;
  ctx.save();ctx.strokeStyle='#f8d17c';ctx.lineWidth=2;
  ctx.beginPath();ctx.arc(car.x,car.y,29+(reducedMotion?.matches || mapDisplay.lowEffects ? 0 : Math.sin(now*.01)*3),0,Math.PI*2);ctx.stroke();ctx.restore();
}
function drawCar(ctx,v,pos,now) {
  const bad=mapDisplay.attacks&&state.scenario!=='normal'&&v.id===state.attacker;
  const selected=selectedVehicle===v.id;
  const dangerous=mapDisplay.attacks&&(v.m2_state==='BLOCK'||v.reputation<.4);
  const paint=bad?'#f38a7f':dangerous?'#ffad70':selected?'#91f6e3':'#6acdc9';
   if (selected || bad){ctx.save();ctx.strokeStyle=bad?'#ff7b786b':'#82e8db72';ctx.lineWidth=2;ctx.setLineDash([4,5]);ctx.beginPath();ctx.arc(pos.x,pos.y,25+(reducedMotion?.matches || mapDisplay.lowEffects ? 0 : Math.sin(now*.004)*2),0,Math.PI*2);ctx.stroke();ctx.restore();}
  ctx.save();ctx.translate(pos.x,pos.y);ctx.rotate(pos.angle*Math.PI/180);
  // SUMO uses real-width lanes and close headways; avoid drawing a 28 m car
  // over several native vehicles. Built-in lanes use enlarged teaching glyphs.
  if(state.mobility_mode==='sumo')ctx.scale(.18,.18);
  ctx.shadowBlur=mapDisplay.lowEffects || reducedMotion?.matches ? 0 : bad?16:9;ctx.shadowColor=paint;
  rr(ctx,-14,-8,28,16,5,paint,'#d8ffff80');ctx.shadowBlur=0;
  rr(ctx,-5,-6,11,12,2,'#244556');ctx.fillStyle='#e1ffff';ctx.fillRect(12,-4,3,3);ctx.fillRect(12,3,3,3);
  ctx.restore();
  const labelY=state.rsus.some(r=>Math.hypot(pos.x-r.x,pos.y-r.y)<75)?pos.y+18:pos.y-32;
  if (selected || (bad && mapDisplay.labels)){
    rr(ctx,pos.x-20,labelY,40,18,4,bad?'#432629e8':'#12383be8',bad?'#aa5f60':'#478e8d');
    ctx.fillStyle=bad?'#ffb0a7':'#9aece5';ctx.textAlign='center';ctx.font='700 11px Segoe UI,Arial';ctx.fillText(v.id,pos.x,labelY+13);ctx.textAlign='left';
  } else if (mapDisplay.labels && !state.vehicles.some(other=>other.id!==v.id && Math.hypot((animatedCars.get(other.id)?.x ?? other.x)-pos.x,(animatedCars.get(other.id)?.y ?? other.y)-pos.y)<38)) {
    ctx.fillStyle='#c9dde7';ctx.font='700 9px Segoe UI,Arial';ctx.textAlign='center';ctx.fillText(v.id,pos.x,labelY+12);ctx.textAlign='left';
  }
}
function routeCorner(from,to) {
  const turn=Math.abs(((to.angle-from.angle+540)%360)-180);
  if (turn < 40 || turn > 140) return null;
  const a=from.angle*Math.PI/180, b=to.angle*Math.PI/180;
  const ax=Math.cos(a),ay=Math.sin(a),bx=Math.cos(b),by=Math.sin(b);
  const cross=ax*by-ay*bx;
  if (Math.abs(cross)<.2) return null;
  const dx=to.x-from.x,dy=to.y-from.y;
  const first=(dx*by-dy*bx)/cross, second=(dy*ax-dx*ay)/cross;
  if (first<0 || second<0 || first+second>Math.hypot(dx,dy)*1.8) return null;
  return {x:from.x+first*ax,y:from.y+first*ay,first,second};
}
function motionDuration(elapsed,speed,running,reduced) {
  return elapsed > 0 && running && !reduced
    ? Math.min(650,Math.max(100,elapsed/Math.max(.5,speed)*1000)) : 0;
}
function sampleTrace(trace,time) {
  if(time<=trace[0].time)return {...trace[0]};
  for(let i=1;i<trace.length;i++){
    const a=trace[i-1],b=trace[i];
    if(time<=b.time){const t=(time-a.time)/(b.time-a.time || 1),delta=((b.angle-a.angle+540)%360)-180;
      return {x:a.x+(b.x-a.x)*t,y:a.y+(b.y-a.y)*t,angle:a.angle+delta*t,time,rsu:time<b.time?a.rsu:b.rsu};}
  }
  return {...trace[trace.length-1]};
}
function interpolateVehicle(segment,now,reduced=false) {
  const {from,to,at,duration,corner}=segment;
  const t=reduced || !duration ? 1 : Math.max(0,Math.min(1,(now-at)/duration));
  if(segment.trace?.length) return sampleTrace(segment.trace,from.time+(to.time-from.time)*t);
  let x=from.x+(to.x-from.x)*t,y=from.y+(to.y-from.y)*t;
  if (corner) {
    const distance=t*(corner.first+corner.second);
    const fraction=corner.first ? Math.min(1,distance/corner.first) : 1;
    if (distance<=corner.first) {x=from.x+(corner.x-from.x)*fraction;y=from.y+(corner.y-from.y)*fraction;}
    else {const tail=corner.second ? Math.min(1,(distance-corner.first)/corner.second) : 1;
      x=corner.x+(to.x-corner.x)*tail;y=corner.y+(to.y-corner.y)*tail;}
  }
  const delta=((to.angle-from.angle+540)%360)-180;
  return {x,y,angle:from.angle+delta*t,time:to.time,rsu:to.rsu};
}
function drawMap(now) {
  const canvas=$('mapCanvas'),measure=prepareCanvas(canvas);
  if(!measure)return;
  const {ctx,width,height}=measure;
  ctx.setTransform(1,0,0,1,0,0);ctx.fillStyle='#10202a';ctx.fillRect(0,0,width,height);
  ctx.setTransform(width/WORLD.width*mapView.zoom,0,0,height/WORLD.height*mapView.zoom,width/WORLD.width*mapView.x,height/WORLD.height*mapView.y);
  drawBackground(ctx,now);
  if(!state)return;
  for (const v of state.vehicles) {
    const segment=motion.get(v.id);
    if (segment) Object.assign(animatedCars.get(v.id),interpolateVehicle(segment,now,reducedMotion?.matches));
  }
  drawRSUs(ctx,now);
  drawAssociations(ctx);
  drawPackets(ctx,now);
  for(const v of state.vehicles){
    if(v.mobility_active===false)continue;
    const pos=animatedCars.get(v.id);
    drawCar(ctx,v,pos,now);
  }
  drawHandover(ctx,now);
}
function drawTraffic() {
  const canvas=$('trafficCanvas'),measure=prepareCanvas(canvas);
  if(!measure||!state)return;
  const {ctx,width,height}=measure;
  ctx.setTransform(1,0,0,1,0,0);ctx.clearRect(0,0,width,height);
  const padding={left:36,right:8,top:12,bottom:18};
  const W=width-padding.left-padding.right,H=height-padding.top-padding.bottom;
  const data=state.history.slice(-60);
  const max=Math.max(12,...data.map(p=>p.pps))*1.15;
  ctx.lineWidth=1;ctx.strokeStyle='#29404b';ctx.font=`${Math.max(9,Math.round(width/80))}px Segoe UI,Arial`;ctx.fillStyle='#718b9d';
  for(let i=0;i<4;i++){const y=padding.top+H*i/3;ctx.beginPath();ctx.moveTo(padding.left,y);ctx.lineTo(width-padding.right,y);ctx.stroke();ctx.textAlign='right';ctx.fillText(Math.round(max*(1-i/3)),padding.left-7,y+3);}
  if(data.length<2)return;
  function line(key,color,fill){
    ctx.beginPath();
    data.forEach((p,i)=>{const x=padding.left+i/Math.max(1,data.length-1)*W,y=padding.top+H-H*p[key]/max;if(!i)ctx.moveTo(x,y);else ctx.lineTo(x,y);});
    if(fill){const xEnd=padding.left+W;ctx.lineTo(xEnd,padding.top+H);ctx.lineTo(padding.left,padding.top+H);ctx.closePath();ctx.fillStyle=fill;ctx.fill();}
    ctx.beginPath();data.forEach((p,i)=>{const x=padding.left+i/Math.max(1,data.length-1)*W,y=padding.top+H-H*p[key]/max;if(!i)ctx.moveTo(x,y);else ctx.lineTo(x,y);});ctx.strokeStyle=color;ctx.lineWidth=2.3;ctx.stroke();
  }
  line('delivered','#50d6d1','rgba(56,194,183,.055)');line('dropped','#f5777b','rgba(249,117,123,.035)');
  ctx.textAlign='left';ctx.fillStyle='#6c8093';ctx.font='10px Segoe UI,Arial';ctx.fillText('-60s',padding.left,padding.top+H+16);ctx.textAlign='right';ctx.fillText('NOW',width-padding.right,padding.top+H+16);
}
function frame(now) {
  const interval = mapDisplay.lowEffects || reducedMotion?.matches ? 100 : 33;
  try { if(currentTab==='overview' && now-lastMapFrame>=interval){drawMap(now);drawTraffic();lastMapFrame=now;} }
  catch(err) {console.error('Render error:',err);}
  requestAnimationFrame(frame);
}
async function poll() {
  try {
    const response=await fetch('/api/state',{cache:'no-store'});
    if(!response.ok)throw new Error(`HTTP ${response.status}`);
    updateState(await response.json());
  } catch(e) { $('connDot').classList.add('offline');$('connText').textContent='DISCONNECTED'; }
  finally { setTimeout(poll,450); }
}
document.addEventListener('DOMContentLoaded',()=>{
  initializeControls();
  poll();
  requestAnimationFrame(frame);
});
