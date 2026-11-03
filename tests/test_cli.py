import importlib.util


def test_explicit_recovery_command_requires_acknowledgement(monkeypatch, tmp_path):
    assert importlib.util.find_spec("certbot_dns_amber.__main__") is not None
    import pytest

    from certbot_dns_amber.__main__ import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "recover",
                "--credentials",
                str(tmp_path / "creds"),
                "--state-dir",
                str(tmp_path),
            ]
        )
    assert exc.value.code == 2
    calls = []

    class Auth:
        def __init__(self, config, name):
            assert config.dns_amber_credentials == str(tmp_path / "creds")
            self.engine = self

        def _setup_credentials(self):
            calls.append("setup")

        def recover(self):
            calls.append("recover")

    monkeypatch.setattr("certbot_dns_amber.__main__.Authenticator", Auth)
    assert (
        main(
            [
                "recover",
                "--credentials",
                str(tmp_path / "creds"),
                "--state-dir",
                str(tmp_path),
                "--confirm-no-active-certbot",
            ]
        )
        == 0
    )
    assert calls == ["setup", "recover"]
