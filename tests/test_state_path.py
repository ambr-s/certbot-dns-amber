"""Relative journal paths must not bypass retained state after a cwd change."""

import json
from types import SimpleNamespace

import pytest
from certbot.errors import PluginError

from certbot_dns_amber.__main__ import main
from certbot_dns_amber.authenticator import Authenticator
from certbot_dns_amber.core import Engine


@pytest.mark.parametrize("entrypoint", ["engine", "plugin", "recovery"])
def test_relative_state_path_rejected_across_working_directories(
    tmp_path, monkeypatch, capsys, entrypoint
):
    endpoint = "https://console.amber.systems"
    zones = {"example.com": "59ade904-17bc-4e76-9c7e-a0fead90db67"}
    calls = []

    class LocalClient:
        def __init__(self, token, origin):
            self.endpoint = origin

        def __call__(self, method, path, body=None):
            calls.append((method, body))
            if method == "GET":
                return {"zone": {"id": zones["example.com"], "domain": "example.com"}}
            raise PluginError("lost response")

    monkeypatch.setattr("certbot_dns_amber.authenticator.Client", LocalClient)
    credentials = tmp_path / "credentials.json"
    credentials.write_text(json.dumps({"token": "fixture", "zones": zones}))
    credentials.chmod(0o600)
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    retained = first / "state" / "journal.json"
    with pytest.raises(PluginError, match="lost response"):
        Engine(first / "state", LocalClient("fixture", endpoint), endpoint, zones).perform(
            "_acme-challenge.example.com", "value"
        )
    original = retained.read_bytes()
    calls.clear()
    outcomes = []
    for cwd in (first, second):
        monkeypatch.chdir(cwd)
        if entrypoint == "recovery":
            result = main(
                [
                    "recover",
                    "--credentials",
                    str(credentials),
                    "--state-dir",
                    "state",
                    "--confirm-no-active-certbot",
                ]
            )
            outcomes.append((result, capsys.readouterr().err))
        else:
            try:
                if entrypoint == "engine":
                    Engine("state", LocalClient("fixture", endpoint), endpoint, zones)
                else:
                    config = SimpleNamespace(
                        dns_amber_credentials=str(credentials),
                        dns_amber_endpoint=endpoint,
                        dns_amber_state_dir="state",
                        dns_amber_propagation_seconds=60,
                    )
                    Authenticator(config, "dns-amber")._setup_credentials()
            except PluginError as error:
                outcomes.append((1, str(error)))
            else:
                outcomes.append((0, ""))
    assert all(code == 1 and "absolute" in error for code, error in outcomes), outcomes
    assert calls == []
    assert retained.read_bytes() == original
    assert not (second / "state").exists()
