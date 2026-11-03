import importlib.util
import json
from types import SimpleNamespace

import pytest
from certbot.errors import PluginError


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"token": "secret\nheader", "zones": {}},
        {"token": "secret", "zones": {"example.com": "provider:42"}},
        {
            "token": "secret",
            "zones": {"EXAMPLE.com": "59ade904-17bc-4e76-9c7e-a0fead90db67"},
        },
        {
            "token": "secret",
            "zones": {"example.com": "59ade904-17bc-4e76-9c7e-a0fead90db67"},
            "extra": True,
        },
    ],
)
def test_bad_credentials_redacted(tmp_path, data):
    from certbot_dns_amber.authenticator import Authenticator

    credentials = tmp_path / "credentials.json"
    credentials.write_text(json.dumps(data))
    credentials.chmod(0o600)
    config = SimpleNamespace(
        dns_amber_credentials=str(credentials),
        dns_amber_endpoint="https://console.amber.systems",
        dns_amber_state_dir=str(tmp_path / "state"),
        dns_amber_propagation_seconds=60,
    )
    with pytest.raises(PluginError) as exc:
        Authenticator(config, "dns-amber")._setup_credentials()
    assert "secret" not in str(exc.value)


@pytest.mark.parametrize("delay", [-1, True, "60"])
def test_invalid_propagation_delay_fails_before_credentials(delay):
    from certbot_dns_amber.authenticator import Authenticator

    config = SimpleNamespace(dns_amber_propagation_seconds=delay)
    with pytest.raises(PluginError, match="propagation"):
        Authenticator(config, "dns-amber")._setup_credentials()


def test_authenticator_uses_private_explicit_zone_credentials(tmp_path, monkeypatch):
    assert importlib.util.find_spec("certbot_dns_amber.authenticator") is not None
    from certbot.plugins.dns_common import DNSAuthenticator

    from certbot_dns_amber.authenticator import Authenticator

    assert issubclass(Authenticator, DNSAuthenticator)
    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps(
            {
                "token": "secret",
                "zones": {"example.com": "59ade904-17bc-4e76-9c7e-a0fead90db67"},
            }
        )
    )
    credentials.chmod(0o600)
    config = SimpleNamespace(
        dns_amber_credentials=str(credentials),
        dns_amber_endpoint="https://console.amber.systems",
        dns_amber_state_dir=str(tmp_path / "state"),
        dns_amber_propagation_seconds=60,
    )
    auth = Authenticator(config, "dns-amber")
    auth._setup_credentials()
    calls = []
    auth.engine.perform = lambda *args: calls.append(("perform", args))
    auth.engine.cleanup = lambda *args: calls.append(("cleanup", args))
    auth._perform("example.com", "_acme-challenge.example.com", "value")
    auth._cleanup("*.example.com", "_acme-challenge.example.com", "value")
    assert calls == [
        ("perform", ("_acme-challenge.example.com", "value")),
        ("cleanup", ("_acme-challenge.example.com", "value")),
    ]
    assert auth.more_info()
    arguments = {}
    Authenticator.add_parser_arguments(lambda key, **kw: arguments.update({key: kw}))
    assert arguments["propagation-seconds"]["default"] == 60
