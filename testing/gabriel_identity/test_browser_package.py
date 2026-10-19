"""Exact source/provenance package, without claiming browser execution."""
import json
from pathlib import Path
import shutil
import zipfile

import pytest
from tooling.scripts.gabriel_extension_package import FILES,package

SOURCE=Path(__file__).resolve().parents[2]/'gabriel'/'browser_extension'


def test_package_is_deterministic_complete_and_never_overwrites(tmp_path):
    first,second=tmp_path/'one.zip',tmp_path/'two.zip'
    a,b=package(SOURCE,first),package(SOURCE,second)
    assert a['sha256']==b['sha256'] and first.read_bytes()==second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert set(archive.namelist())==FILES
        assert all(archive.read(name)==(SOURCE/name).read_bytes() for name in FILES)
    with pytest.raises(FileExistsError): package(SOURCE,first)


@pytest.mark.parametrize('unsafe',['permission','extra','symlink'])
def test_unreviewed_sources_cannot_be_packaged(tmp_path,unsafe):
    source=tmp_path/'sources'
    shutil.copytree(SOURCE,source)
    if unsafe=='permission':
        manifest=json.loads((source/'manifest.json').read_text())
        manifest['permissions'].append('cookies')
        (source/'manifest.json').write_text(json.dumps(manifest))
    elif unsafe=='extra': (source/'unreviewed.js').write_text('unreviewed')
    else:
        (source/'worker.js').unlink()
        (source/'worker.js').symlink_to(SOURCE/'worker.js')
    with pytest.raises(ValueError): package(source,tmp_path/'unsafe.zip')
    assert not (tmp_path/'unsafe.zip').exists()
