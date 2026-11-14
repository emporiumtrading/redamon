export function inspectStructure(account) {
  if (typeof account !== "string" || !account || account.length > 64) throw new Error("A non-secret selected account label is required.");
  const excluded = 'form,input,textarea,select,button,[contenteditable],script,style,noscript,template,[hidden],[aria-hidden="true"]';
  let visits = 0;
  function textOf(element) {
    if (!element || element.closest(excluded)) return null;
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    const parts = [];
    let node;
    while ((node = walker.nextNode())) {
      if (++visits > 20000) throw new Error("Page structure is too complex. Narrow the selected view.");
      const text = node.textContent.trim(), parent = node.parentElement;
      if (!text) continue;
      if (!parent || parent.closest(excluded)) return null;
      for (let p = parent; p; p = p.parentElement) {
        const style = getComputedStyle(p);
        if (style.display === "none" || style.visibility !== "visible" || Number(style.opacity) === 0) return null;
      }
      const range = document.createRange();
      range.selectNodeContents(node);
      const rects = [...range.getClientRects()];
      if (!rects.length || rects.some(r => r.width <= 0 || r.height <= 0 || r.top < 0 || r.left < 0 || r.bottom > innerHeight || r.right > innerWidth)) return null;
      for (let p = parent; p; p = p.parentElement) {
        const style = getComputedStyle(p), box = p.getBoundingClientRect();
        if (/(hidden|clip|scroll|auto)/.test(style.overflow + style.overflowX + style.overflowY) &&
            rects.some(r => r.top < box.top || r.left < box.left || r.bottom > box.bottom || r.right > box.right)) return null;
      }
      for (const box of rects) {
        for (const x of [box.left + Math.min(1, box.width / 2), (box.left + box.right) / 2, box.right - Math.min(1, box.width / 2)]) {
          const y = (box.top + box.bottom) / 2;
          const hit = document.elementFromPoint(x, y), caret = document.caretRangeFromPoint?.(x, y);
          if (!hit || !parent.contains(hit) || caret?.startContainer !== node) return null;
        }
      }
      parts.push(text);
    }
    const result = parts.join(" ");
    if (result.length > 1024) throw new Error("A visible structural field exceeds its limit. Narrow the selected view.");
    return result || null;
  }
  const all = document.querySelectorAll("body *");
  if (all.length > 10000) throw new Error("Page structure is too complex. Narrow the selected view.");
  let accountVisible = false;
  for (const element of all) {
    if (element.textContent.trim() === account && textOf(element) === account) {
      accountVisible = true;
      break;
    }
  }
  if (!accountVisible) throw new Error("The selected account label is not fully visible. Verify the account and pair again.");
  const result = {version: "browser-visible-structure-v1", account: {id: "a1", text: account}, headings: [], tables: [], pairs: [],
    gaps: ["partial_top_frame", "unloaded_content_unverified", "event_semantics_unverified", "hidden_covered_offscreen_fields_excluded"]};
  const headings = [...document.querySelectorAll("h1,h2,h3,h4,h5,h6,[role=heading]")];
  if (headings.length > 12) throw new Error("Too many heading positions. Narrow the selected view.");
  for (const [index, element] of headings.entries()) {
    const text = textOf(element);
    if (!text) continue;
    const level = Number(/^H[1-6]$/.test(element.tagName) ? element.tagName.slice(1) : element.getAttribute("aria-level"));
    if (!Number.isInteger(level) || level < 1 || level > 6) continue;
    result.headings.push({id: "h" + (index + 1), level, text});
  }
  const tables = [...document.querySelectorAll("table")];
  if (tables.length > 8) throw new Error("Too many table positions. Narrow the selected view.");
  for (const [index, table] of tables.entries()) {
    if (table.closest(excluded)) continue;
    if (table.querySelector("table")) throw new Error("Nested tables are unsupported. Narrow the selected view.");
    const rows = [...table.rows];
    if (rows.length > 2000) throw new Error("Table structure exceeds its inspection limit. Narrow the selected view.");
    if ([...table.querySelectorAll("th,td")].some(cell => cell.colSpan !== 1 || cell.rowSpan !== 1))
      throw new Error("Merged table fields are unsupported. Narrow the selected view.");
    const headerRows = rows.filter(row => row.cells.length && [...row.cells].every(cell => cell.tagName === "TH"));
    if (headerRows.length > 1) throw new Error("Multiple table header sections are unsupported. Narrow the selected view.");
    const header = headerRows[0];
    if (header && (header !== rows[0] || header.parentElement?.tagName === "TFOOT"))
      throw new Error("Later or footer table headers are unsupported. Narrow the selected view.");
    const id = "t" + (index + 1), headers = [], observed = [];
    if (header) {
      if (header.cells.length > 16) throw new Error("Too many table columns. Narrow the selected view.");
      for (const [column, cell] of [...header.cells].entries()) {
        const text = textOf(cell);
        if (text === null) continue;
        if (cell.colSpan !== 1 || cell.rowSpan !== 1) throw new Error("Merged table fields are unsupported. Narrow the selected view.");
        headers.push({id: id + "/h" + (column + 1), text});
      }
    }
    for (const [rowIndex, row] of rows.entries()) {
      if (row === header || !row.cells.length || [...row.cells].every(cell => cell.tagName === "TH")) continue;
      if (row.cells.length > 16) throw new Error("Too many table columns. Narrow the selected view.");
      const cells = [];
      for (const [column, cell] of [...row.cells].entries()) {
        const text = textOf(cell);
        if (text === null) continue;
        if (cell.colSpan !== 1 || cell.rowSpan !== 1) throw new Error("Merged table fields are unsupported. Narrow the selected view.");
        cells.push({id: id + "/r" + (rowIndex + 1) + "/c" + (column + 1), text});
      }
      if (!cells.length) continue;
      if (observed.length >= 32) throw new Error("Too many visible table rows. Narrow the selected view.");
      observed.push({id: id + "/r" + (rowIndex + 1), cells});
    }
    if (headers.length || observed.length) result.tables.push({id, headers, rows: observed});
  }
  let pairIndex = 0;
  for (const list of document.querySelectorAll("dl")) {
    if (list.closest(excluded)) continue;
    if (list.querySelector("dl")) throw new Error("Nested definition lists are unsupported. Narrow the selected view.");
    const children = [...list.children];
    let groups;
    if (children.every(child => child.tagName === "DIV")) groups = children.map(child => [...child.children]);
    else if (children.length % 2 === 0 && children.every((child, i) => child.tagName === (i % 2 === 0 ? "DT" : "DD")))
      groups = Array.from({length: children.length / 2}, (_, i) => children.slice(i * 2, i * 2 + 2));
    else continue;
    for (const group of groups) {
      if (group.length !== 2 || group[0].tagName !== "DT" || group[1].tagName !== "DD") continue;
      if (++pairIndex > 32) throw new Error("Too many label/value positions. Narrow the selected view.");
      const label = textOf(group[0]), value = textOf(group[1]);
      if (label === null || value === null) continue;
      const id = "p" + pairIndex;
      result.pairs.push({id, label: {id: id + "/label", text: label}, value: {id: id + "/value", text: value}});
    }
  }
  if (!result.headings.length && !result.tables.length && !result.pairs.length) throw new Error("No supported fully visible structure. Select another approved view.");
  const content = JSON.stringify(result);
  if (new TextEncoder().encode(content).length > 65536) throw new Error("Visible structure exceeds its sharing limit. Narrow the page; nothing was shared.");
  return {page_url: location.href, content, visibility: "partial", gaps: result.gaps};
}
