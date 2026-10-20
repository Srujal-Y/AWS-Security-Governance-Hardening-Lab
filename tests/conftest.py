import pytest

from governance_lab.validation import load_scenario


@pytest.fixture
def scenario():
    return load_scenario()


@pytest.fixture(autouse=True)
def no_ambient_credentials(monkeypatch):
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
