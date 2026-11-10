/* Node's built-in test runner checks presentation logic without a browser or network. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '..', 'static', 'index.html'), 'utf8');
const nodes = new Map();
const document = {
  addEventListener() {},
  createElement(tag){return {tagName:tag,children:[],textContent:'',append(...children){this.children.push(...children);}};},
  getElementById(id) {
    if (!nodes.has(id)) nodes.set(id, {
      hidden: true, textContent: '',
      classList: {toggle() {}},style:{},
      value:'',replaceChildren(...children){this.children=[...children];},append(...children){this.children.push(...children);},
      children: Array.from({length: 5}, () => ({classList: {toggle() {}}})),
    });
    return nodes.get(id);
  },
};
const context = vm.createContext({document, console});
vm.runInContext(source, context);
const call = (expression) => vm.runInContext(expression, context);

test('packet colors and endpoints distinguish forwarding, rate limits, and drops', () => {
  assert.equal(call("packetVisual({ok:true,traffic:'SAFETY',reason:'FORWARDED'}).label"), 'Safety delivered');
  assert.equal(call("packetVisual({ok:true,traffic:'UDP_FLOOD',reason:'FORWARDED'}).label"), 'Flood delivered');
  assert.equal(call("packetVisual({ok:false,traffic:'UDP_FLOOD',reason:'RATE_LIMIT'}).label"), 'Rate-limited');
  assert.equal(call("packetVisual({ok:false,traffic:'UDP_FLOOD',reason:'M2_TEMP_BLOCK'}).label"), 'Dropped');
  assert.equal(call("packetVisual({ok:false,traffic:'UDP_FLOOD',reason:'RATE_LIMIT'}).stop"), .58);
});

test('guided sequence waits for observed stages and a timed recovery', () => {
  const snapshot = {time: 5, vehicles:[{id:'V07',m2_state:'NORMAL'}]};
  context.snapshot = snapshot;
  assert.equal(call("demoTransition('baseline',snapshot,0,'V07')"), 'flood');
  assert.equal(call("demoTransition('flood',snapshot,5,'V07')"), 'flood');
  snapshot.vehicles[0].m2_state = 'METER';
  assert.equal(call("demoTransition('flood',snapshot,5,'V07')"), 'detected');
  snapshot.time = 15; snapshot.vehicles[0].m2_state = 'BLOCK';
  assert.equal(call("demoTransition('detected',snapshot,5,'V07')"), 'mitigated');
  snapshot.time = 18;
  assert.equal(call("demoTransition('mitigated',snapshot,15,'V07')"), 'recovering');
  assert.equal(call("demoTransition('recovering',snapshot,18,'V07')"), 'recovering');
  snapshot.time = 48; snapshot.vehicles[0].m2_state = 'NORMAL';
  assert.equal(call("demoTransition('recovering',snapshot,18,'V07')"), 'complete');
});

test('demo surfaces an unobserved mitigation instead of claiming success', () => {
  context.snapshot = {time: 50, vehicles:[{id:'V07',m2_state:'NORMAL'}]};
  assert.equal(call("demoTransition('flood',snapshot,5,'V07')"), 'stalled');
});

test('handover cue appears only for a recent completed handover', () => {
  context.snapshot = {time: 12, events:[{kind:'HANDOVER',time:11,message:'V07: RSU-1 → RSU-2'}]};
  call('rememberHandovers(snapshot)');
  assert.equal(nodes.get('handoverBanner').hidden, false);
  assert.match(nodes.get('handoverBanner').textContent, /V07: RSU-1 → RSU-2/);
  context.snapshot = {time: 17, events:[]};
  call('rememberHandovers(snapshot)');
  assert.equal(nodes.get('handoverBanner').hidden, true);
});

test('vehicle interpolation is time bounded and follows a right-angle road turn', () => {
  const segment = call('({from:{x:0,y:0,angle:0},to:{x:10,y:10,angle:90},at:100,duration:400,corner:routeCorner({x:0,y:0,angle:0},{x:10,y:10,angle:90})})');
  context.segment = segment;
  assert.equal(call('interpolateVehicle(segment,100).x'), 0);
  assert.equal(call('interpolateVehicle(segment,300).x'), 10);
  assert.equal(call('interpolateVehicle(segment,300).y'), 0);
  assert.equal(call('interpolateVehicle(segment,700).y'), 10);
  assert.equal(call('interpolateVehicle(segment,150,true).y'), 10);
  assert.equal(call('motionDuration(.45,1,true,false)'), 450);
  assert.equal(call('motionDuration(3,1,true,false)'), 650);
  assert.equal(call('motionDuration(.45,1,false,false)'), 0);
  assert.equal(call('motionDuration(.45,1,true,true)'), 0);
  assert.equal(call('motionDuration(0,1,true,false)'), 0);
});

test('map display defaults avoid clutter and every layer has a control', () => {
  assert.equal(call('mapDisplay.associations'), false);
  assert.equal(call('mapDisplay.labels'), false);
  for (const key of ['coverage','associations','packets','labels','attacks','lowEffects']) {
    assert.match(html, new RegExp(`data-map-display="${key}"`));
  }
  call('setMapDisplay("coverage",false);setMapDisplay("packets",false);setMapDisplay("unknown",true)');
  assert.equal(call('mapDisplay.associations'), false);
  assert.equal(call('mapDisplay.packets'), false);
  assert.equal(call('Object.hasOwn(mapDisplay,"unknown")'), false);
});

test('reset cleanup drops old animation and handover state', () => {
  call('animatedCars.set("V01",{x:1});motion.set("V01",{});seenHandovers.add("old");handoverFx={vehicle:"V01"};clearAnimationState()');
  assert.equal(call('animatedCars.size + motion.size + seenHandovers.size'), 0);
  assert.equal(call('handoverFx'), null);
  assert.match(source, /if \(state && newState\.time < state\.time - \.1\) \{\s*clearAnimationState\(\)/);
  assert.match(source, /if \(count >= \(quiet \? 5 : 14\)\) break/);
  assert.match(source, /!mapDisplay\.associations && \(!vehicleInspected \|\| v\.id !== selectedVehicle\)/);
  assert.match(source, /mapDisplay\.lowEffects \|\| reducedMotion\?\.matches \? 100 : 33/);
});

test('authoritative motion trace keeps turns and handovers on the sampled path', () => {
  context.trace=[{time:0,x:0,y:0,angle:0,rsu:'RSU-1'},
    {time:1,x:10,y:0,angle:0,rsu:'RSU-1'},
    {time:2,x:10,y:10,angle:90,rsu:'RSU-2'}];
  assert.equal(call('sampleTrace(trace,.5).y'),0);
  assert.equal(call('sampleTrace(trace,1.5).x'),10);
  assert.equal(call('sampleTrace(trace,1.5).rsu'),'RSU-1');
  assert.equal(call('sampleTrace(trace,2).rsu'),'RSU-2');
  assert.equal(call('sampleTrace(trace,20).y'),10);
  context.segment=call('({from:{time:0},to:{time:2},at:0,duration:1000,trace})');
  assert.equal(call('interpolateVehicle(segment,250).y'),0);
  assert.equal(call('interpolateVehicle(segment,100,true).y'),10);
});

test('zoom preserves cursor position, inverse hit testing and bounded reset', () => {
  call('Object.assign(mapView,{zoom:1,x:0,y:0});zoomMap(2,200,100)');
  context.bounds={left:0,top:0,width:1100,height:660};
  assert.equal(call('mapPoint(200,100,bounds).x'),200);
  assert.equal(call('mapPoint(200,100,bounds).y'),100);
  call('zoomMap(100);mapView.x=900;clampView()');
  assert.equal(call('mapView.zoom'),3);
  assert.equal(call('mapView.x'),0);
  call('zoomMap(.01)');
  assert.equal(call('mapView.zoom'),1);
  assert.equal(call('mapView.x'),0);
  for(const id of ['zoomInBtn','zoomOutBtn','resetViewBtn','mobilityBadge'])assert.match(html,new RegExp(`id="${id}"`));
});

test('RSU inspection presents associations and honest modeled path counters', () => {
  context.inspection={rsus:[{id:'RSU-1',associated_vehicles:['V01','V02'],traffic:{path_attempts:12,path_delivered:10,path_dropped:2,delivered_bytes:4200}}],config:{rsu_range:330}};
  call('state=inspection;selectedRsu="RSU-1";updateInspector()');
  assert.equal(nodes.get('vehicleInspector').hidden,true);
  assert.equal(nodes.get('rsuInspector').hidden,false);
  assert.match(nodes.get('rsuVehicles').textContent,/V01, V02/);
  assert.match(nodes.get('rsuTraffic').textContent,/12 path attempts/);
  call('selectedRsu=null');
});

test('flood visualization is bounded while actual packet totals remain untouched', () => {
  let dots=0;
  context.fakeCtx=new Proxy({}, {get(target,key){if(key==='arc')return ()=>dots++;return ()=>{};},set(){return true;}});
  context.effects={time:1,running:false,speed_factor:1,stats:{sent:800},pulses:Array.from({length:80},(_,i)=>({t:1,traffic:'UDP_FLOOD',ok:true,route:[{x:0,y:0},{x:50,y:0}]}))};
  call('state=effects;mapDisplay.packets=true;mapDisplay.lowEffects=false;drawPackets(fakeCtx,0)');
  assert.equal(dots,5);
  assert.equal(context.effects.stats.sent,800);
  dots=0;
  call('mapDisplay.lowEffects=true;drawPackets(fakeCtx,0)');
  assert.equal(dots,2);
  assert.equal(call('packetVisual({ok:true,traffic:"BEACON"}).label'),'RSU beacon');
});

test('a rendered disconnect never borrows the newest snapshot association', () => {
  let strokes=0;
  context.linkCtx=new Proxy({}, {get(target,key){return key==='stroke'?()=>strokes++:()=>{};},set(){return true;}});
  call('state={vehicles:[{id:"V01",rsu:"RSU-2"}],rsus:[{id:"RSU-2",x:10,y:10}]};selectedVehicle="V01";vehicleInspected=true;mapDisplay.associations=false;animatedCars.set("V01",{x:0,y:0,rsu:null});drawAssociations(linkCtx)');
  assert.equal(strokes,0);
  call('animatedCars.get("V01").rsu="RSU-2";drawAssociations(linkCtx)');
  assert.equal(strokes,1);
});

test('control center distinguishes previews from actual outcomes and filters flow metadata', () => {
  context.preview={action:'METER',meter_rate_kbps:100,deciding_rule:'m3-meter:V07',reason:'Independent budgets',matching_rules:['rule-1']};
  assert.match(call('previewSummary(preview)'),/PREVIEW: METER/);
  assert.match(call('previewSummary(preview)'),/No packet was observed/);
  assert.match(call('actualDecisionSummary(null)'),/No packet/);
  context.actual={sequence:3,time:1,packet:{traffic:'UDP_FLOOD',destination:'V02'},policy_action:'METER',deciding_rule:'m3-meter:V07',outcome:'RATE_LIMIT',matched_rules:['m3-meter:V07']};
  assert.match(call('actualDecisionSummary(actual)'),/ACTUAL #3/);
  assert.match(call('actualDecisionSummary(actual)'),/RATE_LIMIT/);
  context.flows=[{id:'rule-1',source_ip:'10.0.0.7',origin:'User',active:false},{id:'m2-meter:V07',origin:'M2',active:true}];
  assert.equal(call('filterFlows(flows,{origin:"M2",status:"active"}).length'),1);
  assert.equal(call('filterFlows(flows,{query:"10.0.0.7",status:"inactive"})[0].id'),'rule-1');
  assert.equal(context.flows.length,2);
});

test('clearing a filtered timeline changes only its browser watermark', () => {
  context.events=[{id:2,origin:'M2',vehicle:'V07',kind:'RATE',message:'threshold crossing'},
    {id:1,origin:'M3',vehicle:'V08',kind:'SCORE',message:'trust recovery'}];
  const before=JSON.stringify(context.events);
  call('state={controller_events:events};clearTimelineView()');
  assert.equal(call('filterControllerEvents(events,{afterId:timelineAfterId}).length'),0);
  assert.equal(JSON.stringify(context.events),before);
  assert.equal(call('filterControllerEvents(events,{origin:"M3",vehicle:"V08",query:"recovery"}).length'),1);
  context.events.unshift({id:3,origin:'M1',kind:'RULE',message:'installed'});
  assert.equal(call('filterControllerEvents(events,{afterId:timelineAfterId})[0].id'),3);
});

test('preview HTTP helper does not feed a policy result into the snapshot renderer', async () => {
  let updates=0;
  context.fetch=async()=>({ok:true,json:async()=>({action:'ALLOW',scope:'preview'})});
  const original=call('updateState');
  context.updateProbe=()=>updates++;
  call('updateState=updateProbe');
  try{
    const result=await call('requestJSON("/api/policy-preview",{})');
    assert.equal(result.action,'ALLOW');assert.equal(updates,0);
    await call('post("/api/run",{})');assert.equal(updates,1);
  }finally{context.originalUpdate=original;call('updateState=originalUpdate');}
});

test('flow table renders actual zero and missing timestamps without fabricated matches', () => {
  call('state={flow_table:[{id:"rule-1",origin:"User",priority:800,source:"V07",source_ip:"10.0.0.7",destination:"V02",destination_ip:"10.0.0.2",protocol:"UDP",src_port:40007,dst_port:9999,traffic:"UDP_FLOOD",rsu:"*",action:"DROP",rate_kbps:null,match_count:0,last_matched:null,active:false,temporary:false}],rule_warnings:[]};renderControlCenter()');
  const table=nodes.get('flowTable').children[0];
  const cells=table.children[1].children[0].children;
  assert.equal(cells[0].textContent,'rule-1');
  assert.equal(cells[9].textContent,'0');
  assert.equal(cells[10].textContent,'—');
  assert.equal(cells[11].textContent,'INACTIVE');
  for(const id of ['ruleDestination','ruleFeedback','policyPreviewForm','eventOrigin','clearTimelineBtn','nodeDecisionPreview','nodeLastDecision'])assert.match(html,new RegExp(`id="${id}"`));
});
