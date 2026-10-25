import {createChannel} from "./channel.js";

const trusted = chrome.runtime.getURL("popup.html");
const PREFIX = "gabriel.channel.";
const channels = new Map();
let stopAllPending = null;
let epoch = 0;
let rosterQueue = Promise.resolve();
const ready = Promise.all([
  chrome.storage.session.setAccessLevel({accessLevel: "TRUSTED_CONTEXTS"}),
  chrome.storage.local.setAccessLevel({accessLevel: "TRUSTED_CONTEXTS"})
]);

function channel(id) {
  if (!channels.has(id)) {
    const key = PREFIX + id;
    let writes = Promise.resolve();
    const update = fn => {
      const next = writes.then(async () => {
        const record = (await chrome.storage.session.get(key))[key] || {};
        const value = fn(record);
        if (value === null) await chrome.storage.session.remove(key);
        else await chrome.storage.session.set({[key]: value});
      });
      writes = next.catch(()=>{});
      return next;
    };
    const storage = {
      get: async keys => {
        await writes;
        const record = (await chrome.storage.session.get(key))[key] || {};
        return Object.fromEntries((typeof keys === "string" ? [keys] : keys).map(k=>[k,record[k]]));
      },
      set: values => update(record=>({...record,...values})),
      remove: keys => update(record=>Object.fromEntries(Object.entries(record).filter(([k])=>!(typeof keys === "string" ? [keys] : keys).includes(k)))),
      clear: () => update(()=>null)
    };
    channels.set(id,createChannel(storage,Number(id)));
  }
  return channels.get(id);
}
async function records() {
  const all = await chrome.storage.session.get(null);
  return Object.entries(all).filter(([key,value])=>key.startsWith(PREFIX) && value.selected).map(([key,value])=>({id:key.slice(PREFIX.length),...value}));
}
async function stopAll() {
  epoch++;
  if (stopAllPending) return stopAllPending;
  const work = (async()=>{
    const current = await records();
    const ids = new Set(current.map(row=>row.id));
    await Promise.all([...channels.entries()].filter(([id])=>!ids.has(id)).map(([,engine])=>engine.stop()));
    const results = await Promise.all(current.map(row=>channel(row.id).stop()));
    return {message: results.length===1 ? results[0].message : "Stopped all "+results.length+" selected tabs. "+
      (results.some(r=>r.message.includes("unconfirmed")) ? "Some gateway disconnects are unconfirmed; server revocation/expiry remains authoritative." : "Gateway disconnects confirmed.")};
  })();
  stopAllPending = work;
  try { return await work; } finally { if (stopAllPending===work) stopAllPending=null; }
}
async function dispatch(message) {
  if (message?.monitorTick) throw new Error("Scheduled work is internal to the approved monitor.");
  if (!message || typeof message.operation!=="string") throw new Error("Unsupported operation.");
  if (message.operation==="stop") return stopAll();
  if (stopAllPending) throw new Error("Stopping all tabs. Wait before selecting another source.");
  const current = await records();
  if (message.operation==="select") {
    const revision = epoch;
    const [tab] = await chrome.tabs.query({active:true,currentWindow:true});
    if (!tab || tab.incognito) throw new Error("Select a normal HTTPS console tab.");
    const id = String(tab.id);
    if (!current.some(r=>r.id===id) && current.length>=8) throw new Error("Eight-tab limit reached. Stop a tab before adding another.");
    const result = await channel(id).handle(message);
    if (revision!==epoch) { await channel(id).stop(); throw new Error("Selection was stopped."); }
    await chrome.storage.session.set({selectedChannel:id});
    return result;
  }
  if (message.operation==="channel-select") {
    if (!current.some(r=>r.id===message.channel_id)) throw new Error("Unknown selected tab.");
    await chrome.storage.session.set({selectedChannel:message.channel_id});
    return dispatch({operation:"state"});
  }
  const {selectedChannel} = await chrome.storage.session.get("selectedChannel");
  if (message.operation==="state") {
    const result = selectedChannel ? await channel(selectedChannel).handle(message) : {};
    return {...result, selected_channel: selectedChannel, channels:current.map(row=>({id:row.id,
      account_label:row.selected.account_label, page_url:row.selected.page_url, paired:Boolean(row.session),
      organization_id:row.session?.organization_id,case_id:row.session?.case_id,
      monitoring:row.monitoring ? {state:row.monitoring.state,enabled:row.monitoring.enabled,
        scheduling_gap:Boolean(row.monitoring.enabled && Date.now()-row.monitoring.last_tick>45000)} : null}))};
  }
  if (!selectedChannel) throw new Error("Select a page first.");
  if (message.operation==="stop-tab") return channel(selectedChannel).stop();
  if (message.operation==="pause") {
    const results = await Promise.all(current.map(row=>channel(row.id).handle(message)));
    return {message: results[0]?.message || "Paused all selected tabs."};
  }
  return channel(selectedChannel).handle(message);
}
chrome.runtime.onMessage.addListener((message,sender,respond)=>{
  if (sender.id!==chrome.runtime.id || sender.url!==trusted || sender.tab && sender.tab.url!==trusted) return false;
  // Selection changes are serialized; Stop remains able to interrupt active operations.
  const result = ready.then(()=>{
    if (!["select","channel-select"].includes(message?.operation)) return dispatch(message);
    const next = rosterQueue.then(()=>dispatch(message));
    rosterQueue = next.catch(()=>{});
    return next;
  });
  result.then(result=>respond({ok:true,result})).catch(error=>respond({ok:false,error:error.message}));
  return true;
});
chrome.tabs.onRemoved.addListener(tabId=>{ready.then(async()=>{if ((await records()).some(r=>r.id===String(tabId))) await channel(String(tabId)).stop();});});
chrome.tabs.onUpdated.addListener((tabId,change)=>{ready.then(async()=>{if ((await records()).some(r=>r.id===String(tabId))) await channel(String(tabId)).onUpdated(tabId,change);});});
chrome.permissions.onRemoved.addListener(()=>ready.then(stopAll));
chrome.alarms.onAlarm.addListener(alarm=>{
  if (alarm.name!=="gabriel-review") return;
  ready.then(async()=>{await Promise.all((await records()).map(row=>channel(row.id).tick()));});
});
ready.then(async()=>{
  if (!await chrome.alarms.get("gabriel-review")) await chrome.alarms.create("gabriel-review",{periodInMinutes:0.5});
});
