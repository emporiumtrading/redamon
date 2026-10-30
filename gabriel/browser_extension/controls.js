export function validateControls(plan, selected) {
  if (!plan || plan.version!=="gabriel-reviewed-controls-v1" || !/^[a-f0-9]{64}$/.test(plan.plan_digest) ||
      !Array.isArray(plan.steps) || !plan.steps.length || plan.steps.length>20 ||
      !Number.isInteger(plan.next_step) || plan.next_step<0 || plan.next_step>plan.steps.length ||
      !Number.isFinite(Date.parse(plan.expires_at)) || Date.parse(plan.expires_at)<=Date.now())
    throw new Error("No current reviewed control plan is available.");
  let source=selected.page_url;
  for (const step of plan.steps.slice(plan.next_step)) {
    if (!step || !["menu","filter","fill","paginate","submit"].includes(step.kind) || step.source_url!==source ||
        new URL(step.destination_url).origin!==new URL(selected.page_url).origin)
      throw new Error("Control plan left the assigned scope.");
    source=step.destination_url;
  }
  return JSON.stringify([plan.plan_digest,plan.steps,plan.next_step,plan.expires_at]);
}

// This function runs in the isolated world of the exact approved document.
export function controlDOM(mode, step=null) {
  const secret=/password|passwd|secret|token|cookie|session|auth|credential|api.?key|otp|credit.?card/i;
  const mutation=/\b(delete|remove|disable|enable|execute|save|create|reset|reboot|shutdown|terminate|block|unblock|approve|revoke|edit|logout|signout)\b/i;
  const clean=value=>(value || "").trim().replace(/\s+/g," ");
  function labelText(node) {
    if (["INPUT","TEXTAREA","SELECT"].includes(node.tagName)) return "";
    const copy=node.cloneNode(true);
    for(const field of copy.querySelectorAll('input,textarea,select')) field.remove();
    return clean(copy.textContent);
  }
  function name(node) {
    const labelled=node.getAttribute("aria-labelledby");
    if (labelled) {
      const labels=labelled.split(/\s+/).map(id=>document.getElementById(id));
      if (labels.some(label=>!label || !visible(label,false))) throw new Error("Control label is not visible.");
      return clean(labels.map(labelText).join(" "));
    }
    if (node.getAttribute("aria-label")) return clean(node.getAttribute("aria-label"));
    if (node.labels?.length) return clean(Array.from(node.labels).map(labelText).join(" "));
    if (["INPUT","TEXTAREA","SELECT"].includes(node.tagName)) return "";
    return clean(node.tagName==="FORM" ? node.getAttribute("name") : node.textContent);
  }
  function visible(node,hit=true) {
    if (!(node instanceof HTMLElement) || node.closest('[hidden],[inert],[aria-hidden="true"],[contenteditable]')) return false;
    for(let parent=node;parent;parent=parent.parentElement) {
      const style=getComputedStyle(parent);
      if(style.display==="none" || style.visibility!=="visible" || Number(style.opacity)===0) return false;
    }
    const box=node.getBoundingClientRect();
    if(box.width<=0 || box.height<=0 || box.top<0 || box.left<0 || box.bottom>innerHeight || box.right>innerWidth) return false;
    if (!hit) return true;
    const found=document.elementFromPoint(box.left+box.width/2,box.top+box.height/2);
    return !!found && node.contains(found);
  }
  function safe(node) {
    const tag=node.tagName.toLowerCase();
    return visible(node) && !node.disabled && node.getAttribute("aria-disabled")!=="true" &&
      !secret.test([node.id,node.name,node.getAttribute("autocomplete"),name(node)].join(" ")) &&
      !mutation.test(name(node)) && !node.closest('iframe') &&
      (tag!=="input" || ["text","search","date","number"].includes(node.type));
  }
  function target(spec) {
    if(!spec || !["button","summary","select","input","textarea","a","form"].includes(spec.tag)) throw new Error("Unsupported control.");
    const nodes=document.querySelectorAll(spec.tag);
    if(nodes.length>2000) throw new Error("Too many controls. Narrow this view.");
    const matches=Array.from(nodes).filter(node=>(node.id || "")===spec.id && name(node)===spec.name);
    if(matches.length!==1 || !safe(matches[0])) throw new Error("Control changed, is ambiguous, hidden or unsafe. Review a new plan.");
    return matches[0];
  }
  function postcondition(expected) {
    const nodes=Array.from(document.querySelectorAll('[id]')).filter(node=>node.id===expected.id);
    return nodes.length===1 && visible(nodes[0]) && clean(nodes[0].textContent)===expected.text;
  }
  if(document.readyState!=="complete" || document.querySelectorAll('body *').length>10000)
    throw new Error("The current view is incomplete or too complex.");
  if(mode==="inventory") {
    const result=[];
    for(const node of document.querySelectorAll('button,summary,select,input,textarea,a,form')) {
      if(result.length===40) break;
      if(!safe(node)) continue;
      const label=name(node);
      if(!label || label.length>80 || !/^[A-Za-z0-9_-]{0,80}$/.test(node.id || "")) continue;
      result.push({tag:node.tagName.toLowerCase(),id:node.id || "",name:label});
    }
    return {page_url:location.href,controls:result,coverage:"Visible top-frame controls only; values and credentials omitted."};
  }
  if(!step || location.href!==(mode==="verify" ? step.destination_url : step.source_url)) throw new Error("Control page changed.");
  if(mode==="verify") return {confirmed:postcondition(step.expect),page_url:location.href};
  const node=target(step.target);
  if(mode==="inspect") {
    if(step.source_url===step.destination_url && postcondition(step.expect))
      throw new Error("The expected result already exists. Review a fresh control plan.");
    return {page_url:location.href,target:step.target};
  }
  if(mode!=="execute") throw new Error("Unsupported control operation.");
  if(step.kind==="menu") {
    if(node.tagName==="SUMMARY") {
      if(node.parentElement?.tagName!=="DETAILS" || node.parentElement.open) throw new Error("Menu state changed.");
    } else {
      const panel=document.getElementById(node.getAttribute('aria-controls'));
      if(node.type!=="button" || node.form || !['true','menu','listbox'].includes(node.getAttribute('aria-haspopup')) ||
          node.getAttribute('aria-expanded')!=="false" || !panel || panel.id!==step.expect.id)
        throw new Error("This button is not the reviewed closed menu.");
    }
    node.click();
  } else if(step.kind==="filter" || step.kind==="fill") {
    if(node.tagName==="SELECT") {
      if(step.kind!=="filter" || node.multiple || !Array.from(node.options).some(o=>o.value===step.value && !o.disabled))
        throw new Error("Filter choice changed.");
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(node,step.value);
    } else {
      if(step.kind!=="fill" || !['INPUT','TEXTAREA'].includes(node.tagName) || node.readOnly)
        throw new Error("This is not an editable search field.");
      const prototype=node.tagName==='INPUT' ? HTMLInputElement.prototype : HTMLTextAreaElement.prototype;
      Object.getOwnPropertyDescriptor(prototype,'value').set.call(node,step.value);
    }
    node.dispatchEvent(new Event('input',{bubbles:true}));node.dispatchEvent(new Event('change',{bubbles:true}));
    if(node.value!==step.value || !node.checkValidity()) throw new Error("The reviewed field value was not accepted.");
  } else if(step.kind==="paginate") {
    if(node.tagName==='A') {
      if(node.href!==step.destination_url || node.hasAttribute('download') || node.target && node.target!=='_self')
        throw new Error("Pagination destination changed.");
      return {navigate:step.destination_url};
    }
    if(node.tagName!=='BUTTON' || node.type!=='button' || node.form || step.source_url!==step.destination_url)
      throw new Error("Unsupported pagination control.");
    node.click();
  } else if(step.kind==="submit") {
    if(node.tagName!=='FORM' || node.method.toLowerCase()!=='get' || node.target && node.target!=='_self' || !node.checkValidity())
      throw new Error("Only a reviewed valid GET search form can be submitted.");
    const action=new URL(node.action);const destination=new URL(step.destination_url);
    if(action.origin!==location.origin || action.origin!==destination.origin || action.pathname!==destination.pathname || action.search || action.hash || destination.hash)
      throw new Error("Search form destination changed.");
    const fields={};
    for(const field of node.elements) {
      if(['BUTTON','FIELDSET','OUTPUT'].includes(field.tagName) || !field.name || field.disabled) continue;
      if(!['INPUT','TEXTAREA','SELECT'].includes(field.tagName) || !safe(field) || field.name in fields ||
          !(field.name in step.fields) || field.value!==step.fields[field.name]) throw new Error("Search form fields changed or contain excluded content.");
      fields[field.name]=field.value;
    }
    const query=Array.from(destination.searchParams);
    if(Object.keys(fields).length!==Object.keys(step.fields).length || query.length!==Object.keys(fields).length ||
        query.some(([key,value])=>!(key in fields) || fields[key]!==value)) throw new Error("Search query is outside the reviewed policy.");
    // Navigate the validated GET URL without invoking arbitrary submit handlers.
    return {navigate:step.destination_url};
  } else throw new Error("Unsupported control kind.");
  return {same_document:true};
}
