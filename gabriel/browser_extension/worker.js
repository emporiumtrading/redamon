import {inspectPage} from "./collector.js";

const trusted = chrome.runtime.getURL("popup.html");
let busy = false;
let generation = 0;
const inflight = new Set();
const ready = Promise.all([
  chrome.storage.session.setAccessLevel({accessLevel: "TRUSTED_CONTEXTS"}),
  chrome.storage.local.setAccessLevel({accessLevel: "TRUSTED_CONTEXTS"})
]);

function stillCurrent(revision) {
  if (revision !== generation) throw new Error("Sharing stopped. Inspect any in-flight receipt.");
}
async function persist(values, revision) {
  stillCurrent(revision);
  await chrome.storage.session.set(values);
  if (revision !== generation) { await chrome.storage.session.clear(); stillCurrent(revision); }
}

function safeURL(value) {
  const url = new URL(value);
  let decoded = value;
  for (let i = 0; i < 4; i++) decoded = decodeURIComponent(decoded);
  if (decodeURIComponent(decoded) !== decoded || url.protocol !== "https:" || url.username || url.password ||
      url.search || /[?\\\x00-\x20\x7f]/.test(decoded) || /[=&]/.test(decoded.split("#").slice(1).join("#")) ||
      /\/(login|signin|sign-in|oauth|sso|mfa|password|authorize)/i.test(decoded) || url.href !== value) throw new Error("Unsupported or sensitive page. Restore access manually and select an approved page.");
  return value;
}

function gatewayURL(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash ||
      ![url.origin, url.origin + "/"].includes(value)) throw new Error("Enter the exact approved HTTPS gateway origin.");
  return url.origin;
}

function wireContext(selected) {
  const document = selected.document_id;
  if (typeof document !== "string" || !/^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/i.test(document))
    throw new Error("Unsupported browser document identifier.");
  const hex = document.replaceAll("-", "").toLowerCase();
  return {...selected, document_id: [hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),hex.slice(16,20),hex.slice(20)].join("-")};
}

async function current(selected, collect = false) {
  const tab = await chrome.tabs.get(selected.tab_id);
  if (tab.incognito || safeURL(tab.url) !== selected.page_url) throw new Error("Page changed. Stop and obtain fresh pairing.");
  const results = await chrome.scripting.executeScript({target: {tabId: selected.tab_id, documentIds: [selected.document_id]}, func: inspectPage, args: [collect]});
  if (results.length !== 1 || results[0].frameId !== 0 || results[0].documentId !== selected.document_id || results[0].result.page_url !== selected.page_url)
    throw new Error("Document changed or visibility was lost. Fresh pairing is required.");
  return results[0].result;
}

async function request(session, operation, body) {
  const controller = new AbortController();
  inflight.add(controller);
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(session.endpoint + "/v1/browser/" + operation, {method: "POST", redirect: "error", credentials: "omit",
      cache: "no-store", referrerPolicy: "no-referrer", signal: controller.signal,
      headers: {"Content-Type": "application/json", ...(session.token ? {Authorization: "Bearer " + session.token} : {})}, body: JSON.stringify(body)});
    const raw = await response.text();
    if (raw.length > 1500000) throw new Error("Gateway response exceeded its limit.");
    const value = JSON.parse(raw);
    if (!response.ok || value.status !== "ok") throw new Error(operation === "observe" ? "Capture outcome is unconfirmed. Inspect receipts before retrying." : "Gateway denied access. Check scope, expiry and human session.");
    return value.result;
  } finally { clearTimeout(timer); inflight.delete(controller); }
}

async function stop() {
  generation++;
  for (const controller of inflight) controller.abort();
  const {session} = await chrome.storage.session.get("session");
  await chrome.storage.session.clear();
  if (!session) return {message: "Stopped locally. No active pairing."};
  try { await request(session, "disconnect", {}); return {message: "Sharing stopped; gateway disconnect confirmed."}; }
  catch { return {message: "Stopped locally. Gateway disconnect is unconfirmed; lease expiry and human revocation remain authoritative."}; }
}

async function handle(message) {
  if (!message || typeof message !== "object" || !["state","select","pair","preview","share","status","receipts","pause","resume","stop"].includes(message.operation)) throw new Error("Unsupported operation.");
  if (message.operation === "stop") return stop();
  if (message.operation === "state") {
    const {selected, session, paused} = await chrome.storage.session.get(["selected","session","paused"]);
    return {context: selected, extension_origin: "chrome-extension://" + chrome.runtime.id, stored_pairing: !!session, paused: !!paused,
      expires_at: session?.expires_at, organization_id: session?.organization_id, case_id: session?.case_id, task_id: session?.task_id,
      message: session ? "Stored pairing; check live scope before sharing." : "Disconnected. Nothing is shared."};
  }
  if (message.operation === "pause") {
    generation++;
    for (const controller of inflight) controller.abort();
    await chrome.storage.session.set({paused: true});
    return {message: "Paused locally. In-flight capture outcomes may need receipt review; resume rechecks live scope."};
  }
  if (busy) throw new Error("Another operation is in progress.");
  busy = true;
  const revision = generation;
  try {
    if (message.operation === "select") {
      await stop();
      const selectionRevision = generation;
      const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
      if (!tab || tab.incognito) throw new Error("Select a normal HTTPS console tab.");
      safeURL(tab.url);
      const [view] = await chrome.scripting.executeScript({target: {tabId: tab.id, frameIds: [0]}, func: inspectPage, args: [false]});
      if (!view?.documentId || view.frameId !== 0 || view.result.page_url !== tab.url) throw new Error("Cannot bind the selected document.");
      let {installation_id} = await chrome.storage.local.get("installation_id");
      if (!installation_id) { installation_id = crypto.randomUUID(); await chrome.storage.local.set({installation_id}); }
      if (!["chrome","brave"].includes(message.browser) || typeof message.account !== "string" || !message.account.trim() || message.account.length > 64 || /[\x00-\x1f\x7f]/.test(message.account)) throw new Error("Choose the browser and a non-secret account label.");
      const context = {browser: message.browser, extension_version: chrome.runtime.getManifest().version, installation_id, tab_id: tab.id,
        document_id: view.documentId, page_url: tab.url, account_label: message.account.trim()};
      await persist({selected: context}, selectionRevision);
      return {context, extension_origin: "chrome-extension://" + chrome.runtime.id};
    }
    const {selected, session, pending, paused} = await chrome.storage.session.get(["selected","session","pending","paused"]);
    if (!selected) throw new Error("Select and approve a page first.");
    if (message.operation === "pair") {
      await current(selected);
      const target = gatewayURL(message.endpoint);
      if (!await chrome.permissions.contains({origins: [target + "/*"]})) throw new Error("Grant permission for the selected Gabriel endpoint first.");
      const context = wireContext(selected);
      const result = await request({endpoint: target}, "claim", {ticket: message.ticket, context});
      if (revision !== generation) throw new Error("Sharing was stopped.");
      if (!result.context || Object.keys(result.context).length !== Object.keys(context).length ||
          Object.keys(context).some(key => result.context[key] !== context[key]) || !/^gbp1_[A-Za-z0-9_-]{43}$/.test(result.token)) throw new Error("Gateway scope mismatch.");
      await current(selected);
      await persist({session: {endpoint: target, token: result.token, context: selected, expires_at: result.expires_at,
        lease_id: result.lease_id, organization_id: result.organization_id, case_id: result.case_id, task_id: result.task_id,
        sharing_approved: result.sharing_approved, sequence: 0}}, revision);
      return {message: "Paired. Sharing requires preview and explicit approval.", expires_at: result.expires_at,
        organization_id: result.organization_id, case_id: result.case_id, task_id: result.task_id};
    }
    if (!session || Date.parse(session.expires_at) <= Date.now()) throw new Error("Pairing is missing or expired. Obtain fresh approval.");
    if (paused && ["preview","share"].includes(message.operation)) throw new Error("Sharing is paused. Resume and recheck scope first.");
    if (message.operation === "receipts") {
      await current(selected);
      const result = await request(session, "receipts", {context: wireContext(selected)});
      if (result.observations.some(row => row.state === "prepared")) throw new Error("An observation is pending. Ask the engineer to reconcile it before continuing.");
      if (revision !== generation) throw new Error("Sharing was stopped.");
      session.sequence = result.observations.length ? Math.max(...result.observations.map(row => row.sequence)) : 0;
      await persist({session}, revision);
      await chrome.storage.session.remove("pending");
      return {message: "Receipts checked. " + result.observations.length + " captured observations.", observations: result.observations};
    }
    await current(selected);
    await request(session, "heartbeat", {context: wireContext(selected)});
    if (revision !== generation) throw new Error("Sharing was stopped.");
    if (message.operation === "resume") { await persist({paused: false}, revision); return {message: "Live scope checked. Sharing resumed; a new reviewed preview is required."}; }
    if (message.operation === "status") return {message: "Current scope and heartbeat confirmed.", scope: selected, expires_at: session.expires_at,
      organization_id: session.organization_id, case_id: session.case_id, task_id: session.task_id};
    if (message.operation === "preview") {
      if (pending) throw new Error("Previous capture outcome is unconfirmed. Inspect receipts first.");
      const view = await current(selected, true);
      return {content: view.content, observed_at: new Date().toISOString(), gaps: view.gaps};
    }
    if (!session.sharing_approved || pending || typeof message.content !== "string" || !message.content.length || new TextEncoder().encode(message.content).length > 65536 || message.approved !== true)
      throw new Error("Explicit sharing approval, reviewed text and a resolved previous capture are required.");
    const observed = Date.parse(message.observed_at);
    if (!Number.isFinite(observed) || Date.now() - observed > 55000 || observed > Date.now() + 5000) throw new Error("Preview is stale. Capture a new preview.");
    const payload = {schema_version: 1, operation: "browser.observe", request_id: crypto.randomUUID(), sequence: session.sequence + 1,
      context: wireContext(selected), observed_at: message.observed_at, visibility: "partial", client_minimized: true, content: message.content};
    // Only a non-sensitive cursor persists; an uncertain write never triggers automatic recapture.
    await persist({pending: {request_id: payload.request_id, sequence: payload.sequence}}, revision);
    await current(selected);
    stillCurrent(revision);
    const receipt = await request(session, "observe", payload);
    if (revision !== generation) throw new Error("Sharing stopped during capture; inspect the server receipt.");
    session.sequence++;
    await persist({session}, revision);
    await chrome.storage.session.remove("pending");
    return {message: "Encrypted evidence receipt confirmed.", receipt};
  } catch (error) {
    throw new Error(error instanceof Error ? error.message : "Operation failed. Visibility is unconfirmed.");
  } finally { busy = false; }
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id || sender.url !== trusted || sender.tab && sender.tab.url !== trusted) return false;
  ready.then(() => handle(message)).then(result => respond({ok: true, result})).catch(error => respond({ok: false, error: error.message}));
  return true;
});

chrome.tabs.onRemoved.addListener(async tabId => {
  const {selected} = await chrome.storage.session.get("selected");
  if (selected?.tab_id === tabId) await stop();
});
chrome.tabs.onUpdated.addListener(async (tabId, change) => {
  const {selected} = await chrome.storage.session.get("selected");
  if (selected?.tab_id === tabId && (change.url || change.status === "loading")) await stop();
});
chrome.permissions.onRemoved.addListener(() => stop());
