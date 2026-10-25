// Operator-reviewed routes grant bounded reading, not vendor authenticity or threat-detection qualification.
export function validatePlan(plan, context) {
  if (!plan || !["generated-console-v1","operator-reviewed-pages-v1"].includes(plan.contract_version) || typeof plan.id !== "string" ||
      !Array.isArray(plan.destinations) || !plan.destinations.length || plan.destinations.length > 20 ||
      new Set(plan.destinations).size !== plan.destinations.length || !Number.isInteger(plan.max_moves) ||
      plan.max_moves < plan.destinations.length || plan.max_moves > (plan.monitoring_approved === true ? 1000 : 20) ||
      !Number.isFinite(Date.parse(plan.expires_at)) || Date.parse(plan.expires_at) <= Date.now() ||
      plan.sharing_approved !== true) throw new Error("No supported navigation and sharing plan is available.");
  const source = new URL(context.page_url);
  if (plan.contract_version === "generated-console-v1" && source.hostname !== "localhost") throw new Error("This adapter supports the generated local console only.");
  for (const value of plan.destinations) {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.origin !== source.origin || url.username || url.password || url.search || url.hash ||
        (plan.contract_version === "generated-console-v1" && !["/security", "/traffic", "/threats"].includes(url.pathname)) || url.href !== value)
      throw new Error("A section is outside the supported console contract.");
  }
  return JSON.stringify([plan.id, plan.contract_version, plan.destinations, plan.max_moves, plan.expires_at, plan.sharing_approved]);
}

export function inspectNavigationIdentity(account, version = "generated-console-v1") {
  if (version === "operator-reviewed-pages-v1") {
    const nodes = document.querySelectorAll("body *");
    if (nodes.length > 10000) throw new Error("Console identity view is too complex.");
    const labels = Array.from(nodes).filter(node=>!node.children.length && !node.closest('form,input,textarea,select,[contenteditable],script,style,[hidden],[aria-hidden="true"]') && node.textContent.trim() === account);
    const label = labels.find(node=>{
      for (let p=node;p;p=p.parentElement) {
        const style=getComputedStyle(p);
        if (style.display==="none" || style.visibility!=="visible" || Number(style.opacity)===0) return false;
      }
      const box=node.getBoundingClientRect();
      const hit=document.elementFromPoint(box.left+box.width/2,box.top+box.height/2);
      return box.width>0 && box.height>0 && box.top>=0 && box.left>=0 && box.bottom<=innerHeight && box.right<=innerWidth && hit && node.contains(hit);
    });
    if (document.readyState!=="complete" || !label) throw new Error("Declared console account is not visibly confirmed. Pair again after checking access.");
    return {page_url:location.href,account_label:account};
  }

  const marker = document.querySelector('meta[name="gabriel-generated-console"]');
  const label = document.querySelector('[data-gabriel-account]');
  if (document.readyState !== "complete" || marker?.content !== "generated-console-v1" ||
      label?.getAttribute("data-gabriel-account") !== account || label.hidden || label.closest('[hidden],[aria-hidden="true"]'))
    throw new Error("Console identity or account is unconfirmed.");
  for (let element = label; element; element = element.parentElement) {
    const style = getComputedStyle(element);
    if (style.display === "none" || style.visibility !== "visible" || Number(style.opacity) === 0)
      throw new Error("Console account is not visible.");
  }
  const box = label.getBoundingClientRect();
  const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
  if (box.width <= 0 || box.height <= 0 || box.top < 0 || box.left < 0 || box.bottom > innerHeight || box.right > innerWidth || !hit || !label.contains(hit))
    throw new Error("Console account is covered or outside the visible page.");
  return {page_url: location.href, account_label: account};
}
