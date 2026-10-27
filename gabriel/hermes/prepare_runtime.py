"""Repackage verified upstream source and a pinned text-supervisor dependency profile."""
from hashlib import sha256
from importlib import metadata
import json
import os
from pathlib import Path
import shutil
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT=Path('/opt/hermes')
OUT=Path('/payload')
SOURCE='bf0203a794a07aac3ff764972ab9087baa4e4f4e'
stamp=json.loads((ROOT/'install-stamp.json').read_text())
assert stamp['commit']==SOURCE and stamp['baseVersion']=='0.22.5' and not stamp['dirty']
project=tomllib.loads((ROOT/'pyproject.toml').read_text())['project']
# These tool/desktop extras are unavailable in the supervisor: Gabriel owns its
# tools and browser scope; upstream explicitly supports a no-op Relay host.
omit={'firecrawl-anydoc','nemo-relay','browser-harness','pillow-heif','resvg-py'}
selected={};extras={};pending=[]
for value in project['dependencies']:
    r=Requirement(value)
    if (r.marker is None or r.marker.evaluate()) and canonicalize_name(r.name) not in omit:
        pending.append(r)
while pending:
    r=pending.pop();name=canonicalize_name(r.name)
    requested=set(r.extras)
    if name in selected and requested<=extras[name]:continue
    dist=metadata.distribution(r.name)
    selected[name]=dist.version
    extras[name]=extras.get(name,set())|requested
    for value in dist.requires or []:
        dep=Requirement(value)
        if dep.marker is None or any(dep.marker.evaluate({'extra':e}) for e in extras[name]|{''}):
            if canonicalize_name(dep.name) not in omit:pending.append(dep)
if 'brotlicffi' in selected:selected['brotlicffi']='1.2.1.0'
OUT.mkdir()
(OUT/'requirements.lock').write_text(''.join(name+'=='+version+'\n' for name,version in sorted(selected.items())))
assert (OUT/'requirements.lock').read_bytes()==Path('/expected-requirements.lock').read_bytes(), 'upstream_dependency_profile_changed'
source=OUT/'hermes';source.mkdir()
skip={'.venv','venv','.git','node_modules','__pycache__','pm-runtime','tests','docs','.hermes'}
allowed={'.py','.json','.toml','.yaml','.yml','.txt','.md','.j2'}
manifest={}
for current,dirs,files in os.walk(ROOT,followlinks=False):
    dirs[:]=[d for d in dirs if d not in skip and not d.endswith('.dist-info') and not (Path(current)==ROOT/'tools' and d.startswith(('chromium-','node-','npm-','uv-','python-','agent-browser-')))]
    for name in files:
        original=Path(current)/name
        if original.is_symlink():continue
        if (original.suffix not in allowed and not name.upper().startswith(('LICENSE','NOTICE','COPYING','COPYRIGHT'))) or name in {'package.json','package-lock.json','npm-shrinkwrap.json'}:continue
        relative=original.relative_to(ROOT)
        target=source/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(original,target)
        manifest[str(relative)]=sha256(target.read_bytes()).hexdigest()
assert manifest['run_agent.py']==sha256((ROOT/'run_agent.py').read_bytes()).hexdigest()
assert manifest['agent/agent_init.py']==sha256((ROOT/'agent/agent_init.py').read_bytes()).hexdigest()
provenance=dict(schema=1,deployment_kind='image',manager='docker',image='gabriel-hermes-text-supervisor',
    version='0.22.5',revision=SOURCE,profile='gabriel-text-supervisor-v1',
    disabled_components=sorted(omit),source_files=manifest,requirements=selected)
(OUT/'image-provenance.json').write_text(json.dumps(provenance,sort_keys=True)+'\n')
# Record the actual release identity from the verified install stamp. Upstream's
# bootstrap distribution says 0.0.0, which misidentifies this patched source.
dist=source/'hermes_agent-0.22.5.dist-info';dist.mkdir()
(dist/'METADATA').write_text('Metadata-Version: 2.1\nName: hermes-agent\nVersion: 0.22.5\nLicense: MIT\n'+''.join('Requires-Dist: '+n+'=='+v+'\n' for n,v in sorted(selected.items())))
(dist/'licenses').mkdir();shutil.copyfile(ROOT/'LICENSE',dist/'licenses'/'LICENSE')
print('Prepared verified Hermes 0.22.5 source and',len(selected),'exact-pinned supervisor dependencies; no upstream browser/Node/Docker utilities.')
