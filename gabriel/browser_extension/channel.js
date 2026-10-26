import {inspectPage} from "./collector.js";
import {inspectNavigationIdentity, validatePlan, approvedURL, readOnlyURL, inspectConsole} from "./navigator.js";
import {inspectEventSection} from "./events.js";

export function createChannel(storage, tabId) {
let busy = false;
let generation = 0;
let expectedMove = null;
let stopping = null;
const inflight = new Set();

function stillCurrent(revision) {
  if (revision !== generation) throw new Error("Sharing stopped. Inspect any in-flight receipt.");
}
async function persist(values, revision) {
  stillCurrent(revision);
  await storage.set(values);
  if (revision !== generation) { await storage.clear(); stillCurrent(revision); }
}

function safeURL(value) { return approvedURL(value); }

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
  if (results.length !== 1 || results[0].frameId !== 0 || results[0].documentId !== selected.document_id || results[0].result?.page_url !== selected.page_url)
    throw new Error("Document changed or visibility was lost. Fresh pairing is required.");
  return results[0].result;
}

async function request(session, operation, body) {
  const controller = new AbortController();
  // Revocation must survive concurrent Stop/Pause events that cancel ordinary work.
  if (operation !== "disconnect") inflight.add(controller);
  const timer = setTimeout(() => controller.abort(), operation === "ai-review" ? 40000 : 15000);
  try {
    const response = await fetch(session.endpoint + "/v1/browser/" + operation, {method: "POST", redirect: "error", credentials: "omit",
      cache: "no-store", referrerPolicy: "no-referrer", signal: controller.signal,
      headers: {"Content-Type": "application/json", ...(session.token ? {Authorization: "Bearer " + session.token} : {})}, body: JSON.stringify(body)});
    const raw = await response.text();
    if (raw.length > 1500000) throw new Error("Gateway response exceeded its limit.");
    const value = JSON.parse(raw);
    if (!response.ok || value.status !== "ok") throw new Error(operation === "observe" ? "Capture outcome is unconfirmed. Inspect receipts before retrying." :
      ["events-review", "specialists-review", "text-review", "ai-review"].includes(operation) ? "Review outcome is unconfirmed. Inspect case reviews before retrying." : "Gateway denied access. Check scope, expiry and human session.");
    return value.result;
  } finally { clearTimeout(timer); inflight.delete(controller); }
}

async function stop() {
  generation++;
  expectedMove = null;
  for (const controller of inflight) controller.abort();
  if (stopping) return stopping;
  const pendingStop = (async () => {
    const {session} = await storage.get("session");
    await storage.clear();
    if (!session) return {message: "Stopped locally. No active pairing."};
    try { await request(session, "disconnect", {}); return {message: "Sharing stopped; gateway disconnect confirmed."}; }
    catch { return {message: "Stopped locally. Gateway disconnect is unconfirmed; lease expiry and human revocation remain authoritative."}; }
  })();
  stopping = pendingStop;
  try { return await pendingStop; }
  finally { if (stopping === pendingStop) stopping = null; }
}

async function handle(message) {
  if (!message || typeof message !== "object" || !["state","select","pair","preview","share","status","receipts","pause","resume","stop","navigation-plan","navigation-run","monitor-start","monitor-stop"].includes(message.operation)) throw new Error("Unsupported operation.");
  if (message.operation === "stop") return stop();
  if (message.operation === "state") {
    const {selected, session, paused, navigation, tour, monitoring} = await storage.get(["selected","session","paused","navigation","tour","monitoring"]);
    return {context: selected, extension_origin: "chrome-extension://" + chrome.runtime.id, stored_pairing: !!session, paused: !!paused || !!navigation,
      expires_at: session?.expires_at, organization_id: session?.organization_id, case_id: session?.case_id, task_id: session?.task_id,
      tour, monitoring: publicMonitoring(monitoring), message: navigation ? "Navigation outcome unresolved. Stop and pair again; no automatic repeat is permitted." : session ? "Stored pairing; check live scope before sharing." : "Disconnected. Nothing is shared."};
  }
  if (["pause","monitor-stop"].includes(message.operation)) {
    generation++;
    for (const controller of inflight) controller.abort();
    const {monitoring} = await storage.get("monitoring");
    await storage.set({paused: true, monitoring: monitoring ? {...monitoring, enabled: false, state: "paused"} : null});
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
      const tab = await chrome.tabs.get(tabId);
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
    let {selected, session, pending, paused, navigation, reviewed_plan} = await storage.get(["selected","session","pending","paused","navigation","reviewed_plan"]);
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
        sharing_approved: result.sharing_approved, scheduled_review_enabled: result.scheduled_review_enabled, discovery_enabled: result.discovery_enabled,
        ai_review_enabled: result.ai_review_enabled === true, sequence: 0}}, revision);
      return {message: "Paired. Sharing requires preview and explicit approval.", expires_at: result.expires_at,
        organization_id: result.organization_id, case_id: result.case_id, task_id: result.task_id};
    }
    if (!session || Date.parse(session.expires_at) <= Date.now()) throw new Error("Pairing is missing or expired. Obtain fresh approval.");
    if (navigation) throw new Error("Navigation outcome unresolved. Stop and pair again before continuing.");
    if (paused && ["preview","share","navigation-plan","navigation-run"].includes(message.operation)) throw new Error("Sharing is paused. Resume and recheck scope first.");
    if (message.operation === "monitor-start") {
      if (message.approved !== true || !session.sharing_approved || !session.scheduled_review_enabled || pending || paused || navigation)
        throw new Error("Approve scheduled sharing with a current, unpaused pairing and resolved receipts first.");
      if (session.ai_review_enabled && message.ai_approved !== true) throw new Error("Explicitly approve minimized-signal AI review before starting this AI-enabled pairing.");
      if (!["page","tour","discover"].includes(message.mode)) throw new Error("Choose selected-page or approved-tour review.");
      await current(selected);
      await request(session, "heartbeat", {context: wireContext(selected)});
      if (["tour","discover"].includes(message.mode)) {
        const plan = await request(session, "navigation-plan", {context: wireContext(selected)});
        const signature=validatePlan(plan,selected);
        if (message.mode === "discover") {
          if (!session.discovery_enabled || plan.contract_version!=="operator-discovered-readonly-v1") throw new Error("Automatic page discovery requires operator approval for this tab.");
        } else if (reviewed_plan!==signature) throw new Error("Review the current navigation plan before scheduling it.");
      }
      await persist({monitoring: {enabled: true, state: "scheduled", mode: message.mode,
        ai_approved: session.ai_review_enabled && message.ai_approved === true,
        last_tick: Date.now(), last_checked: null, last_capture: null, captures: 0, max_captures: message.mode === "discover" ? 32 : 8, unchanged: 0, digests: {}, queue:[selected.page_url], cursor:0}}, revision);
      return {message: "Scheduled review enabled for this tab until pairing expiry. Visibility remains partial; browser sleep can interrupt review."};
    }
    if (message.operation === "navigation-plan" || message.operation === "navigation-run") {
      if (pending) throw new Error("Previous capture outcome is unconfirmed. Inspect receipts first.");
      await current(selected);
      await request(session, "heartbeat", {context: wireContext(selected)});
      const plan = await request(session, "navigation-plan", {context: wireContext(selected)});
      const signature = validatePlan(plan, selected);
      await navigationIdentity(selected.tab_id, selected.page_url, selected.account_label, plan.contract_version);
      stillCurrent(revision);
      if (message.operation === "navigation-plan") {
        await persist({reviewed_plan: signature}, revision);
        return {plan, message: "Review the assigned sections and approve navigation and automatic minimized-text sharing once for this tour."};
      }
      if (message.approved !== true || (!message.monitorTick && reviewed_plan !== signature) || !session.sharing_approved)
        throw new Error("Review the current plan and explicitly approve navigation and sharing first.");
      if (message.monitorTick && !(await storage.get("monitoring")).monitoring?.enabled) throw new Error("Scheduled review is not approved.");
      tourStarted = true;
      await storage.remove("reviewed_plan");
      const tour = {plan_id: plan.id, sections: [], state: "running"};
      await persist({tour}, revision);
      const {monitoring: schedule}=await storage.get("monitoring");
      const discovery=message.monitorTick && schedule?.mode==="discover";
      const queue=discovery ? [...schedule.queue] : plan.destinations;
      const start=discovery ? schedule.cursor % queue.length : 0;
      let processed=0;
      for (let index=start;index<queue.length;index++) {
        if (discovery && processed>=2) break;
        const destination=queue[index];
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
          const identity = await waitForDestination(selected, destination, Math.min(Date.parse(intent.expires_at), Date.now() + 10000), revision, plan.contract_version);
          const next = {...selected, page_url: destination, document_id: identity.document_id};
          const completed = await request(session, "navigation-complete", {intent_id: intent.id, context: wireContext(next)});
          if (!completed.current || Object.keys(wireContext(next)).some(key => completed.context?.[key] !== wireContext(next)[key]))
            throw new Error("Navigation completion is unconfirmed. Stop and inspect the receipt.");
          stillCurrent(revision);
          selected = next;
          session.context = next;
          await persist({selected, session}, revision);
          await storage.remove("navigation");
          expectedMove = null;
        }
        await navigationIdentity(selected.tab_id, selected.page_url, selected.account_label, plan.contract_version);
        await request(session, "heartbeat", {context: wireContext(selected)});
        await current(selected);
        await capture(selected, session, revision, tour, intent, message.monitorTick === true);
        if (discovery) {
          const values=await chrome.scripting.executeScript({target:{tabId:selected.tab_id,documentIds:[selected.document_id]},func:inspectConsole});
          if (values.length!==1 || values[0].documentId!==selected.document_id) throw new Error("Console changed during discovery.");
          const survey=values[0].result;
          for (const link of survey.links) {
            try {
              readOnlyURL(link);
              if (new URL(link).origin===new URL(selected.page_url).origin && !queue.includes(link) && queue.length<20) queue.push(link);
            } catch { /* Unsupported links confer no navigation authority. */ }
          }
          processed++;
          const {monitoring: latest}=await storage.get("monitoring");
          await persist({monitoring:{...latest,queue,cursor:(index+1)%queue.length,interface_title:survey.title,
            discovery_coverage:survey.coverage,identified_by:survey.identification}},revision);
        }
      }
      tour.state = "complete";
      await persist({tour}, revision);
      return {tour, context: selected, extension_origin: "chrome-extension://" + chrome.runtime.id,
        message: "Approved section tour complete. " + tour.sections.length + " encrypted evidence receipts confirmed." +
          (tour.latest_review_id ? " " + tour.candidate_count + " suspected pattern" + (tour.candidate_count === 1 ? " requires" : "s require") + " analyst review; confidence is unqualified." : "") +
          (tour.specialist_count ? " " + tour.specialist_count + " local specialist reviews recorded; " + tour.abstained_count + " abstained for missing facts." : "")};
    }
    if (message.operation === "receipts") {
      await current(selected);
      const result = await request(session, "receipts", {context: wireContext(selected)});
      if (result.observations.some(row => row.state === "prepared")) throw new Error("An observation is pending. Ask the engineer to reconcile it before continuing.");
      if (revision !== generation) throw new Error("Sharing was stopped.");
      session.sequence = result.observations.length ? Math.max(...result.observations.map(row => row.sequence)) : 0;
      await persist({session}, revision);
      await storage.remove("pending");
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
    await storage.remove("pending");
    return {message: "Encrypted evidence receipt confirmed.", receipt};
  } catch (error) {
    if (tourStarted) {
      const {selected, monitoring} = await storage.get(["selected","monitoring"]);
      await stop();
      if (message.monitorTick && selected) await storage.set({selected, monitoring: {...monitoring, enabled: false, state: "interrupted", error: error.message}});
    }
    throw new Error(error instanceof Error ? error.message : "Operation failed. Visibility is unconfirmed.");
  } finally { busy = false; }
}

async function onUpdated(tabId, change) {
  const expected = expectedMove;
  const {selected} = await storage.get("selected");
  if (selected?.tab_id !== tabId || (!change.url && change.status !== "loading")) return;
  if (expected?.tab_id === tabId && expected.revision === generation &&
      (!change.url || change.url === expected.source || change.url === expected.destination)) return;
  if (!change.status && change.url === selected.page_url) return;
  await stop();
}

async function navigationIdentity(tabId, pageURL, account, version) {
  const tab = await chrome.tabs.get(tabId);
  if (tab.incognito || safeURL(tab.url) !== pageURL) throw new Error("Navigation left its assigned page.");
  const results = await chrome.scripting.executeScript({target: {tabId, frameIds: [0]}, func: inspectNavigationIdentity, args: [account, version]});
  const result = results[0];
  if (results.length !== 1 || result.frameId !== 0 || result.result?.page_url !== pageURL || result.result.account_label !== account || !result.documentId)
    throw new Error("Navigation document or account is unconfirmed.");
  return {document_id: result.documentId};
}

async function waitForDestination(selected, destination, deadline, revision, version) {
  while (Date.now() < deadline) {
    stillCurrent(revision);
    const tab = await chrome.tabs.get(selected.tab_id);
    if (tab.incognito || ![selected.page_url, destination].includes(tab.url)) throw new Error("Unexpected navigation. Stop and pair again.");
    if (tab.url === destination && tab.status === "complete") return navigationIdentity(selected.tab_id, destination, selected.account_label, version);
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error("Navigation timed out. Stop and pair again; no automatic repeat is permitted.");
}

function publicMonitoring(value) {
  if (!value) return null;
  const {enabled,state,mode,last_tick,last_checked,last_capture,captures,max_captures,unchanged,error,interface_title,discovery_coverage,candidate_count,review_evidence_id,learning,ai} = value;
  return {enabled,state,mode,last_tick,last_checked,last_capture,captures,max_captures,unchanged,error,interface_title,discovery_coverage,candidate_count,review_evidence_id,learning,ai,
    coverage: "partial", scheduling_gap: Boolean(enabled && Date.now()-last_tick>45000)};
}

async function capture(selected, session, revision, tour, intent = null, deduplicate = false) {
    const structured = await chrome.scripting.executeScript({target: {tabId: selected.tab_id, documentIds: [selected.document_id]}, func: inspectEventSection, args: [selected.account_label]});
        if (structured.length !== 1 || structured[0].frameId !== 0 || structured[0].documentId !== selected.document_id || structured[0].result === undefined)
          throw new Error("Event document changed during collection.");
        const view = structured[0].result === null ? await current(selected, true) : structured[0].result;
        if (deduplicate && structured[0].result === null && !view.content.split("\n").some(line=>line.trim()===selected.account_label))
          throw new Error("Declared account label is no longer visibly identifiable. Check the account and pair again.");
        let hash = null;
        const {monitoring} = await storage.get("monitoring");
        if (deduplicate) {
          if (!monitoring?.enabled || monitoring.captures >= monitoring.max_captures) throw new Error("Scheduled capture budget reached; review the case before renewing.");
          hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(view.content)))).map(x=>x.toString(16).padStart(2,"0")).join("");
          if (monitoring.digests[selected.page_url] === hash) {
            await persist({monitoring: {...monitoring, unchanged: monitoring.unchanged + 1, last_checked: Date.now(), state: "reviewed_unchanged"}}, revision);
            return;
          }
        }
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
        if (view.normalization_kind === "generated-browser-events-v1") {
          const analyzed = await request(session, "events-review", {context: wireContext(selected), observation_id: receipt.observation_id});
          stillCurrent(revision);
          tour.latest_review_id = analyzed.review_id;
          tour.candidate_count = analyzed.candidate_count;
          tour.sections.at(-1).review = analyzed;
          await persist({tour}, revision);
          const specialists = await request(session, "specialists-review", {context: wireContext(selected), observation_id: receipt.observation_id});
          stillCurrent(revision);
          tour.sections.at(-1).specialists = specialists;
          tour.specialist_count = specialists.specialist_count;
          tour.abstained_count = specialists.abstained_count;
          await persist({tour}, revision);
        }
        if (deduplicate && view.normalization_kind !== "generated-browser-events-v1") {
          const reviewed=await request(session,"text-review",{context:wireContext(selected),observation_id:receipt.observation_id});
          stillCurrent(revision);
          tour.sections.at(-1).text_review=reviewed;
          const {monitoring: latest}=await storage.get("monitoring");
          await persist({tour,monitoring:{...latest,candidate_count:reviewed.candidate_count,review_evidence_id:reviewed.review_evidence_id,learning:reviewed.learning}},revision);
        }
        if (deduplicate && session.ai_review_enabled) {
          const {monitoring: schedule}=await storage.get("monitoring");
          if (!schedule?.ai_approved) throw new Error("AI sharing approval is unavailable.");
          await current(selected);
          await request(session,"heartbeat",{context:wireContext(selected)});
          await persist({monitoring:{...schedule,last_tick:Date.now()}},revision);
          const started=Date.now();
          const ai=await request(session,"ai-review",{context:wireContext(selected),observation_id:receipt.observation_id});
          stillCurrent(revision);
          if (Date.now()-started>40000) throw new Error("AI review exceeded the approved waiting interval. Inspect receipts; no automatic resend is permitted.");
          await current(selected);
          await request(session,"heartbeat",{context:wireContext(selected)});
          tour.sections.at(-1).ai=ai;
          const {monitoring: latest}=await storage.get("monitoring");
          await persist({tour,monitoring:{...latest,ai,last_tick:Date.now()}},revision);
        }
        await storage.remove("pending");
        if (deduplicate) {
          const {monitoring: latest} = await storage.get("monitoring");
          await persist({monitoring: {...latest, captures: latest.captures + 1, last_checked: Date.now(), last_capture: Date.now(),
            state: "reviewed", digests: {...latest.digests, [selected.page_url]: hash}}}, revision);
        }

}

async function tick() {
  if (busy || stopping) return;
  const {monitoring, session, selected, pending, navigation, paused} = await storage.get(["monitoring","session","selected","pending","navigation","paused"]);
  if (!monitoring?.enabled || paused) return;
  const revision = generation;
  try {
    if (!session || Date.parse(session.expires_at)<=Date.now()) throw new Error("Pairing expired. Fresh approval is required.");
    if (Date.now()-monitoring.last_tick>45000) throw new Error("Browser scheduling gap. Fresh pairing is required.");
    if (pending || navigation) throw new Error("Unconfirmed capture or navigation. Inspect receipts before renewing.");
    await persist({monitoring: {...monitoring, last_tick: Date.now()}}, revision);
    if (["tour","discover"].includes(monitoring.mode)) {
      await handle({operation: "navigation-run", approved: true, monitorTick: true});
    } else {
      busy = true;
      try {
        await current(selected);
        await request(session,"heartbeat",{context: wireContext(selected)});
        await current(selected);
        const tour = {state: "running", sections: []};
        await capture(selected,session,revision,tour,null,true);
        tour.state = "complete";
        await persist({tour}, revision);
      } finally { busy = false; }
    }
  } catch (error) {
    if (revision !== generation) return;
    // A gap invalidates monitoring; expiry/revocation stays authoritative at the gateway.
    await storage.set({monitoring: {...monitoring, enabled: false, state: "interrupted", error: error.message}});
  }
}
return {handle, stop, onUpdated, tick};
}
