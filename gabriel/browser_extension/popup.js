const byId = id => document.getElementById(id);
let observedAt = null;
let paired = false;
let requestGeneration = 0;
const field = (id) => byId(id).value;
async function run(operation, extra = {}) {
  const revision = ++requestGeneration;
  byId("message").textContent = operation === "stop" ? "Stopping locally…" : "Working…";
  try {
    if (["select","stop"].includes(operation)) {
      byId("scope").textContent = "No paired organization, case or task.";
      byId("context").value = "";
    }
    if (["stop","pause","select"].includes(operation)) paired = false;
    if (["stop","pause","select","navigation-plan","navigation-run"].includes(operation)) {
      byId("preview-text").value = ""; byId("approved").checked = false; observedAt = null;
      byId("navigation-approved").checked = false;
    }
    const value = await chrome.runtime.sendMessage({operation, ...extra});
    if (revision !== requestGeneration) return;
    if (!value?.ok) throw new Error(value?.error || "Connection lost. Nothing is confirmed.");
    const result = value.result;
    if (operation === "state" && !result.stored_pairing) byId("scope").textContent = "No paired organization, case or task.";
    if (result.channels) {
      const select = byId("channels");
      select.replaceChildren();
      for (const row of result.channels) {
        const item = document.createElement("option");
        item.value = row.id;
        item.textContent = row.account_label+" · "+new URL(row.page_url).hostname+" · "+(row.monitoring?.scheduling_gap ? "coverage gap" : row.monitoring?.state || (row.paired ? "paired" : "unpaired"));
        item.selected = row.id===result.selected_channel;
        select.append(item);
      }
      if (!result.channels.length) select.add(new Option("No selected tabs", ""));
    }
    if (operation === "state" || operation === "channel-select") {
      const state = result.monitoring;
      byId("monitor-state").textContent = state ? "Scheduled review: "+(state.scheduling_gap ? "coverage gap" : state.state)+
        "; changed captures "+(state.captures || 0)+" of "+(state.max_captures || 8)+(state.last_checked ? "; last checked "+new Date(state.last_checked).toLocaleTimeString() : "")+
        (state.interface_title ? "; interface: "+state.interface_title+" (page-reported)" : "")+(Number.isInteger(state.candidate_count) ? "; latest captured page: "+state.candidate_count+" candidate passages requiring assessment" : "")+(state.error ? "; "+state.error : "") : "Scheduled review is off.";
    }
    if (result.organization_id) byId("scope").textContent = "Organization " + result.organization_id + "; Case " + result.case_id + "; Task " + result.task_id;
    if (["pair","resume"].includes(operation)) paired = true;
    if (operation === "state") paired = result.stored_pairing && !result.paused;
    if (result.context) {
      byId("context").value = JSON.stringify(result.context, null, 2);
      byId("extension-origin").textContent = result.extension_origin;
      byId("browser").value = result.context.browser;
      byId("account").value = result.context.account_label;
    }
    if (result.content) { byId("preview-text").value = result.content; observedAt = result.observed_at; byId("approved").checked = false; }
    if (result.plan) byId("navigation-sections").textContent = result.plan.destinations.join(" → ") + "; expires " + result.plan.expires_at;
    if (["stop","select"].includes(operation)) byId("navigation-sections").textContent = "";
    if (operation === "share" || operation === "stop") { byId("preview-text").value = ""; byId("approved").checked = false; observedAt = null; }
    byId("message").textContent = result.message || (operation === "preview" ? "Partial preview ready. Review before sharing." : "Page selected. Give this context to your Gabriel operator.");
    byId("result").textContent = result.receipt ? "Observation " + result.receipt.observation_id + "; evidence " + result.receipt.evidence_id : result.expires_at ? "Pairing expires: " + result.expires_at + (result.organization_id ? "; Organization " + result.organization_id + "; Case " + result.case_id + "; Task " + result.task_id : "") : "";
  } catch (error) { if (revision === requestGeneration) byId("message").textContent = error.message; }
}
byId("select").onclick = () => run("select", {browser: field("browser"), account: field("account")});
byId("pair").onclick = () => { const ticket = field("ticket"); byId("ticket").value = ""; return run("pair", {endpoint: field("endpoint"), ticket}); };
byId("preview").onclick = () => run("preview");
byId("share").onclick = () => run("share", {content: field("preview-text"), observed_at: observedAt, approved: byId("approved").checked});
for (const operation of ["status", "receipts", "pause", "resume", "stop"]) byId(operation).onclick = () => run(operation);
byId("channels").onchange = () => {
  byId("preview-text").value = ""; byId("ticket").value = ""; observedAt = null; byId("approved").checked = false;
  byId("navigation-approved").checked = false; byId("monitor-approved").checked = false;
  run("channel-select", {channel_id: field("channels")});
};
byId("refresh-tabs").onclick = () => run("state");
byId("stop-tab").onclick = () => run("stop-tab").then(()=>run("state"));
byId("monitor-start").onclick = () => run("monitor-start", {mode: field("monitor-mode"), approved: byId("monitor-approved").checked});
byId("monitor-stop").onclick = () => run("monitor-stop");
byId("navigation-plan").onclick = () => run("navigation-plan");
byId("navigation-run").onclick = () => run("navigation-run", {approved: byId("navigation-approved").checked});
byId("permission").onclick = async () => {
  try {
    const value = new URL(field("endpoint"));
    if (value.protocol !== "https:" || value.username || value.password || value.pathname !== "/" || value.search || value.hash) throw new Error("Enter an HTTPS origin only.");
    const accepted = await chrome.permissions.request({origins: [value.origin + "/*"]});
    byId("message").textContent = accepted ? "Permission granted only for this Gabriel origin. Pairing is still required." : "Permission declined.";
  } catch { byId("message").textContent = "Endpoint permission was not granted."; }
};
document.addEventListener("visibilitychange", () => { if (document.hidden) { byId("preview-text").value = ""; byId("ticket").value = ""; observedAt = null; byId("approved").checked = false; byId("navigation-approved").checked = false; } });
setInterval(() => { if (paired && !document.hidden) run("status"); }, 20000);
document.body.dataset.gabrielReady = "true";
run("state");
