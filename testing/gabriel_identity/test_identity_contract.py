"""Input and configuration admission without a database fallback."""
import pytest
import importlib.util
from pathlib import Path

from gabriel.identity.service import (IdentityConfigurationError, IdentityService,
    InvalidIdentityInput, identifier, password, username)


@pytest.mark.parametrize('value', ['', "x'; DROP TABLE users;--", 'name with spaces', None])
def test_invalid_login_names_rejected(value):
    with pytest.raises(InvalidIdentityInput):
        username(value)


@pytest.mark.parametrize('value', ['', 'short', 'x' * 1025, '\ud800' * 16, None])
def test_password_policy_has_length_and_encoding_bounds(value):
    with pytest.raises(InvalidIdentityInput):
        password(value, creating=True)


def test_identity_configuration_missing_is_not_anonymous_access():
    with pytest.raises(IdentityConfigurationError):
        IdentityService('').whoami('gb1_' + 'a' * 43)


def test_secret_preparation_is_private_and_never_overwrites(tmp_path):
    path = Path(__file__).resolve().parents[2] / 'tooling/scripts/gabriel_identity_prepare.py'
    spec = importlib.util.spec_from_file_location('identity_prepare', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    directory = module.prepare(tmp_path / 'secrets')
    assert directory.stat().st_mode & 0o777 == 0o700
    assert set(p.name for p in directory.iterdir()) == {'db_password','owner_dsn','app_dsn','role_init.sql'}
    before = (directory / 'app_dsn').stat().st_mtime_ns
    with pytest.raises(ValueError):
        module.prepare(directory)
    assert (directory / 'app_dsn').stat().st_mtime_ns == before
    with pytest.raises(ValueError):
        module.prepare(path.parents[2] / 'unsafe-secrets')
