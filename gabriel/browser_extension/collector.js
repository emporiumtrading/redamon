export function inspectPage(collect = false) {
  const result = {page_url: location.href, content: "", visibility: "partial",
    gaps: ["Top frame only; unloaded rows, frames, images and covered content are not verified."]};
  if (!collect) return result;
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const lines = [];
  let visits = 0, bytes = 0, node;
  while ((node = walker.nextNode())) {
    if (++visits > 10000) throw new Error("Page is too complex. Narrow the selected view.");
    const parent = node.parentElement;
    if (!parent || parent.closest('form,input,textarea,select,button,[contenteditable],script,style,noscript,template,[hidden],[aria-hidden="true"]')) continue;
    const text = node.textContent.trim();
    if (!text) continue;
    let visible = true;
    for (let p = parent; p; p = p.parentElement) {
      const style = getComputedStyle(p);
      if (style.display === "none" || style.visibility !== "visible" || Number(style.opacity) === 0) { visible = false; break; }
    }
    if (!visible) continue;
    const range = document.createRange();
    range.selectNodeContents(node);
    const rects = [...range.getClientRects()];
    if (!rects.length || rects.some(r => r.width <= 0 || r.height <= 0 || r.top < 0 || r.left < 0 || r.bottom > innerHeight || r.right > innerWidth)) continue;
    for (let p = parent; p; p = p.parentElement) {
      const style = getComputedStyle(p), box = p.getBoundingClientRect();
      if (/(hidden|clip|scroll|auto)/.test(style.overflow + style.overflowX + style.overflowY) &&
          rects.some(r => r.top < box.top || r.left < box.left || r.bottom > box.bottom || r.right > box.right)) visible = false;
    }
    if (!visible) continue;
    bytes += new TextEncoder().encode(text + "\n").length;
    if (bytes > 65536) throw new Error("Text exceeds the sharing limit. Narrow the page; nothing was shared.");
    lines.push(text);
  }
  result.content = lines.join("\n");
  if (!result.content) throw new Error("No supported visible text. Select another approved view.");
  return result;
}
