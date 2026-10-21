import {inspectPage} from "./collector.js";
import {inspectNavigationIdentity, validatePlan} from "./navigator.js";
import {inspectEventSection} from "./events.js";

const trusted = chrome.runtime.getURL("popup.html");
let busy = false;
let generation = 0;
let expectedMove = null;
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
    if (!response.ok || value.status !== "ok") throw new Error(operation === "observe" ? "Capture outcome is unconfirmed. Inspect receipts before retrying." :
      operation === "events-review" ? "Event review outcome is unconfirmed. Inspect case reviews before retrying." : "Gateway denied access. Check scope, expiry and human session.");
    return value.result;
  } finally { clearTimeout(timer); inflight.delete(controller); }
}

async function stop() {
  generation++;
  expectedMove = null;
  for (const controller of inflight) controller.abort();
  const {session} = await chrome.storage.session.get("session");
  await chrome.storage.session.clear();
  if (!session) return {message: "Stopped locally. No active pairing."};
  try { await request(session, "disconnect", {}); return {message: "Sharing stopped; gateway disconnect confirmed."}; }
  catch { return {message: "Stopped locally. Gateway disconnect is unconfirmed; lease expiry and human revocation remain authoritative."}; }
}

async function handle(message) {
  if (!message || typeof message !== "object" || !["state","select","pair","preview","share","status","receipts","pause","resume","stop","navigation-plan","navigation-run"].includes(message.operation)) throw new Error("Unsupported operation.");
  if (message.operation === "stop") return stop();
  if (message.operation === "state") {
    const {selected, session, paused, navigation, tour} = await chrome.storage.session.get(["selected","session","paused","navigation","tour"]);
    return {context: selected, extension_origin: "chrome-extension://" + chrome.runtime.id, stored_pairing: !!session, paused: !!paused || !!navigation,
      expires_at: session?.expires_at, organization_id: session?.organization_id, case_id: session?.case_id, task_id: session?.task_id,
      tour, message: navigation ? "Navigation outcome unresolved. Stop and pair again; no automatic repeat is permitted." : session ? "Stored pairing; check live scope before sharing." : "Disconnected. Nothing is shared."};
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
  let tourStarted = false;
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
    let {selected, session, pending, paused, navigation, reviewed_plan} = await chrome.storage.session.get(["selected","session","pending","paused","navigation","reviewed_plan"]);
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
    if (navigation) throw new Error("Navigation outcome unresolved. Stop and pair again before continuing.");
    if (paused && ["preview","share","navigation-plan","navigation-run"].includes(message.operation)) throw new Error("Sharing is paused. Resume and recheck scope first.");
    if (message.operation === "navigation-plan" || message.operation === "navigation-run") {
      if (pending) throw new Error("Previous capture outcome is unconfirmed. Inspect receipts first.");
      await current(selected);
      await request(session, "heartbeat", {context: wireContext(selected)});
      const plan = await request(session, "navigation-plan", {context: wireContext(selected)});
      const signature = validatePlan(plan, selected);
      await navigationIdentity(selected.tab_id, selected.page_url, selected.account_label);
      stillCurrent(revision);
      if (message.operation === "navigation-plan") {
        await persist({reviewed_plan: signature}, revision);
        return {plan, message: "Review the assigned sections and approve navigation and automatic minimized-text sharing once for this tour."};
      }
      if (message.approved !== true || reviewed_plan !== signature || !session.sharing_approved)
        throw new Error("Review the current plan and explicitly approve navigation and sharing first.");
      tourStarted = true;
      await chrome.storage.session.remove("reviewed_plan");
      const tour = {plan_id: plan.id, sections: [], state: "running"};
      await persist({tour}, revision);
      for (const destination of plan.destinations) {
        stillCurrent(revision);
        if (Date.parse(plan.expires_at) <= Date.now()) throw new Error("Navigation grant expired. Stop and pair again.");
        await current(selected);
        let intent = null;
        if (destination !== selected.page_url) {
          const requestId = crypto.randomUUID();
          await persist({navigation: {request_id: requestId, destination_url: destination, state: "preparing"}}, revision);
          intent = await request(session, "navigation-prepare", {context: wireContext(selected), request_id: requestId, destination_url: destination});
          if (intent.state !== "prepared" || intent.destination_url !== destination || typeof intent.id !== "string" ||
              !Number.isFinite(Date.parse(intent.expires_at)) || Date.parse(intent.expires_at) <= Date.now() ||
              !intent.source_context || Object.keys(intent.source_context).length !== Object.keys(selected).length ||
              Object.keys(wireContext(selected)).some(key => wireContext(selected)[key] !== intent.source_context[key]))
            throw new Error("Navigation intent does not match the approved source and destination.");
          await persist({navigation: {intent_id: intent.id, destination_url: destination, state: "prepared"}}, revision);
          stillCurrent(revision);
          expectedMove = {tab_id: selected.tab_id, source: selected.page_url, destination, revision};
          await chrome.tabs.update(selected.tab_id, {url: destination});
          stillCurrent(revision);
          const identity = await waitForDestination(selected, destination, Math.min(Date.parse(intent.expires_at), Date.now() + 10000), revision);
          const next = {...selected, page_url: destination, document_id: identity.document_id};
          const completed = await request(session, "navigation-complete", {intent_id: intent.id, context: wireContext(next)});
          if (!completed.current || Object.keys(wireContext(next)).some(key => completed.context?.[key] !== wireContext(next)[key]))
            throw new Error("Navigation completion is unconfirmed. Stop and inspect the receipt.");
          stillCurrent(revision);
          selected = next;
          session.context = next;
          await persist({selected, session}, revision);
          await chrome.storage.session.remove("navigation");
          expectedMove = null;
        }
        await navigationIdentity(selected.tab_id, selected.page_url, selected.account_label);
        await request(session, "heartbeat", {context: wireContext(selected)});
        await current(selected);
        const structured = await chrome.scripting.executeScript({target: {tabId: selected.tab_id, documentIds: [selected.document_id]}, func: inspectEventSection, args: [selected.account_label]});
        if (structured.length !== 1 || structured[0].frameId !== 0 || structured[0].documentId !== selected.document_id || structured[0].result === undefined)
          throw new Error("Event document changed during collection.");
        const view = structured[0].result === null ? await current(selected, true) : structured[0].result;
        const payload = {schema_version: 1, operation: "browser.observe", request_id: crypto.randomUUID(), sequence: session.sequence + 1,
          context: wireContext(selected), observed_at: new Date().toISOString(), visibility: "partial", client_minimized: true, content: view.content};
        await persist({pending: {request_id: payload.request_id, sequence: payload.sequence}}, revision);
        await current(selected);
        stillCurrent(revision);
        const receipt = await request(session, "observe", payload);
        stillCurrent(revision);
        session.sequence++;
        tour.sections.push({page_url: selected.page_url, intent_id: intent?.id, observation_id: receipt.observation_id, evidence_id: receipt.evidence_id});
        await persist({session, tour}, revision);
        await chrome.storage.session.remove("pending");
        if (view.normalization_kind === "generated-browser-events-v1") {
          const analyzed = await request(session, "events-review", {context: wireContext(selected), observation_id: receipt.observation_id});
          stillCurrent(revision);
          tour.latest_review_id = analyzed.review_id;
          tour.candidate_count = analyzed.candidate_count;
          tour.sections.at(-1).review = analyzed;
          await persist({tour}, revision);
        }
      }
      tour.state = "complete";
      await persist({tour}, revision);
      return {tour, context: selected, extension_origin: "chrome-extension://" + chrome.runtime.id,
        message: "Approved section tour complete. " + tour.sections.length + " encrypted evidence receipts confirmed." +
          (tour.latest_review_id ? " " + tour.candidate_count + " suspected pattern" + (tour.candidate_count === 1 ? " requires" : "s require") + " analyst review; confidence is unqualified." : "")};
    }
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
    if (tourStarted) await stop();
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
  const expected = expectedMove;
  const {selected} = await chrome.storage.session.get("selected");
  if (selected?.tab_id !== tabId || (!change.url && change.status !== "loading")) return;
  if (expected?.tab_id === tabId && expected.revision === generation &&
      (!change.url || change.url === expected.source || change.url === expected.destination)) return;
  if (!change.status && change.url === selected.page_url) return;
  await stop();
});
chrome.permissions.onRemoved.addListener(() => stop());

async function navigationIdentity(tabId, pageURL, account) {
  const tab = await chrome.tabs.get(tabId);
  if (tab.incognito || safeURL(tab.url) !== pageURL) throw new Error("Navigation left its assigned page.");
  const results = await chrome.scripting.executeScript({target: {tabId, frameIds: [0]}, func: inspectNavigationIdentity, args: [account]});
  const result = results[0];
  if (results.length !== 1 || result.frameId !== 0 || result.result?.page_url !== pageURL || result.result.account_label !== account || !result.documentId)
    throw new Error("Navigation document or account is unconfirmed.");
  return {document_id: result.documentId};
}

async function waitForDestination(selected, destination, deadline, revision) {
  while (Date.now() < deadline) {
    stillCurrent(revision);
    const tab = await chrome.tabs.get(selected.tab_id);
    if (tab.incognito || ![selected.page_url, destination].includes(tab.url)) throw new Error("Unexpected navigation. Stop and pair again.");
    if (tab.url === destination && tab.status === "complete") return navigationIdentity(selected.tab_id, destination, selected.account_label);
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error("Navigation timed out. Stop and pair again; no automatic repeat is permitted.");
}
