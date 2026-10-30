"""Deterministic, exclusive package publication for the exact reviewed MV3 sources."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import zipfile

FILES={'controls.js','manifest.json','worker.js','channel.js','collector.js','navigator.js','events.js','semantics.js','popup.html','popup.js','popup.css'}


def package(source,output):
    source,output=Path(source),Path(output)
    if source.is_symlink() or not source.is_dir() or {p.name for p in source.iterdir()}!=FILES:
        raise ValueError('exact_extension_sources_required')
    if any((source/name).is_symlink() or not (source/name).is_file() for name in FILES):
        raise ValueError('regular_extension_sources_required')
    manifest=json.loads((source/'manifest.json').read_text())
    if (manifest.get('manifest_version')!=3 or manifest.get('version')!='0.4.0'
            or set(manifest.get('permissions',[]))!={'activeTab','scripting','storage','alarms'}
            or manifest.get('host_permissions') or manifest.get('externally_connectable')
            or manifest.get('optional_host_permissions')!=['https://*/*']):
        raise ValueError('extension_permission_review_required')
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(FILES):
            item=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0))
            item.compress_type=zipfile.ZIP_DEFLATED
            item.external_attr=0o100644<<16
            archive.writestr(item,(source/name).read_bytes())
    return {'schema_version':1,'version':manifest['version'],'files':sorted(FILES),'sha256':sha256(output.read_bytes()).hexdigest()}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('source')
    parser.add_argument('output')
    args=parser.parse_args()
    print(json.dumps(package(args.source,args.output)))

