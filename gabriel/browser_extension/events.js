export function inspectEventSection(account) {
  const node = document.querySelector('pre[data-gabriel-security-events]');
  if (!node) return null;
  const marker = document.querySelector('meta[name="gabriel-generated-console"]');
  const label = document.querySelector('[data-gabriel-account]');
  if (marker?.content !== "generated-console-v1" || label?.getAttribute("data-gabriel-account") !== account || node.children.length ||
      node.closest('form,[contenteditable],[hidden],[aria-hidden="true"]')) throw new Error("Event section or account is unconfirmed.");
  for (const element of [node, label]) {
    for (let parent = element; parent; parent = parent.parentElement) {
      const style = getComputedStyle(parent);
      if (style.display === "none" || style.visibility !== "visible" || Number(style.opacity) === 0)
        throw new Error("Event section or account is hidden.");
    }
    const box = element.getBoundingClientRect();
    const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
    if (box.width <= 0 || box.height <= 0 || box.top < 0 || box.left < 0 || box.bottom > innerHeight || box.right > innerWidth || !hit || !element.contains(hit))
      throw new Error("Event section or account is outside the supported visible area.");
  }
  const content = node.textContent;
  if (new TextEncoder().encode(content).length > 65536) throw new Error("Event section exceeds its capture limit.");
  const value = JSON.parse(content);
  if (JSON.stringify(value) !== content) throw new Error("Generated event snapshots must use unambiguous compact JSON.");
  const fields = ["source_id", "event_id", "event_time", "kind", "actor_id", "asset_id", "source_asset_id", "process_sha256", "object_id", "reported_authority"];
  const exact = (object, keys) => object && typeof object === "object" && !Array.isArray(object) && Object.keys(object).length === keys.length && keys.every(key => Object.hasOwn(object, key));
  const uuid = value => typeof value === "string" && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
  const instant = value => typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$/.test(value) && Number.isFinite(Date.parse(value));
  if (!exact(value, ["version", "as_of", "missing_sources", "events"]) || value.version !== "generated-browser-events-v1" || !instant(value.as_of) ||
      !Array.isArray(value.missing_sources) || value.missing_sources.length > 6 || new Set(value.missing_sources).size !== value.missing_sources.length ||
      value.missing_sources.some(item => !["authentication", "process", "network", "file", "kernel", "boot"].includes(item)) ||
      !Array.isArray(value.events) || !value.events.length || value.events.length > 128) throw new Error("Unsupported event snapshot.");
  for (const row of value.events) {
    if (!exact(row, fields) || !uuid(row.source_id) || !uuid(row.asset_id) ||
        [row.actor_id, row.source_asset_id, row.object_id].some(item => item !== null && !uuid(item)) ||
        typeof row.event_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$/.test(row.event_id) || !instant(row.event_time) ||
        !["auth_failure", "auth_success", "remote_execution", "file_write", "file_rename", "ransom_note", "backup_disabled", "kernel_integrity_violation", "boot_integrity_violation"].includes(row.kind) ||
        !["approved", "denied", "unknown"].includes(row.reported_authority) ||
        row.process_sha256 !== null && (typeof row.process_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(row.process_sha256))) throw new Error("Unsupported event fields.");
  }
  return {content, normalization_kind: "generated-browser-events-v1"};
}
