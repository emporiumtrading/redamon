"""Read Docker metadata; never print environment values or secret material."""
import json
from pathlib import Path
import sys

row=json.loads(Path(sys.argv[1]).read_text())[0]
assert row['Config']['User']=='10001:10001'
assert row['HostConfig']['ReadonlyRootfs']
assert row['HostConfig']['CapDrop']==['ALL']
assert 'no-new-privileges:true' in row['HostConfig']['SecurityOpt']
assert not row['HostConfig']['PortBindings']
assert all(m['Type']=='tmpfs' and m['Destination']=='/tmp' for m in row['Mounts'])
assert list(row['NetworkSettings']['Networks'])==['gabriel-tool-check_toolbus']
assert not any(e.split('=',1)[0].startswith(('GABRIEL_','OPENROUTER_','OPENAI_','ANTHROPIC_','DATABASE_')) for e in row['Config']['Env'])
print('Toolbox isolation verified: no credentials, host ports, persistent mounts or database network.')
