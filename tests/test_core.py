import importlib


def test_create_persists_intent_before_network(tmp_path):
    assert importlib.util.find_spec("certbot_dns_amber") is not None
    import json

    from certbot_dns_amber.core import Engine

    calls = []

    def api(method, path, body=None):
        calls.append((method, path, body))
        if method == "GET":
            return {"zone": {"id": ZONE, "domain": "example.com"}}
        state = json.loads((tmp_path / "state" / "journal.json").read_text())
        entry = next(iter(state["entries"].values()))
        assert entry["create"] == body
        assert entry["status"] == "creating"
        return {
            "success": True,
            "record": {"Id": "opaque/42", "Revision": "a" * 64, **body},
        }

    Engine(
        tmp_path / "state", api, "https://console.amber.systems", {"example.com": ZONE}
    ).perform("_acme-challenge.example.com", "ExactValue")
    assert calls[-1][2]["Type"] == 3
    assert calls[-1][2]["Name"] == "_acme-challenge"
    assert calls[-1][2]["Value"] == "ExactValue"


def test_lost_create_replays_exact_intent_across_instances(tmp_path):
    import pytest

    from certbot_dns_amber.core import Engine

    calls = []

    def api(method, path, body=None):
        if method == "GET":
            return {"zone": {"id": ZONE, "domain": "example.com"}}
        calls.append(body.copy())
        if len(calls) == 1:
            raise RuntimeError("lost response")
        return {"success": True, "record": {"Id": 42, "Revision": "a" * 64, **body}}

    def engine():
        return Engine(
            tmp_path / "state",
            api,
            "https://console.amber.systems",
            {"example.com": ZONE},
        )

    with pytest.raises(RuntimeError):
        engine().perform("_acme-challenge.example.com", "value")
    engine().perform("_acme-challenge.example.com", "value")
    assert calls[0] == calls[1]


def test_cleanup_replays_delete_and_original_baseline(tmp_path):
    import json

    import pytest

    from certbot_dns_amber.core import Engine

    deletes = []

    def api(method, path, body=None):
        if method == "GET":
            return {"zone": {"id": ZONE, "domain": "example.com"}}
        if method == "POST":
            return {
                "success": True,
                "record": {"Id": "opaque/42", "Revision": "a" * 64, **body},
            }
        state = json.loads((tmp_path / "state/journal.json").read_text())
        entry = next(iter(state["entries"].values()))
        assert entry["delete"] == body
        assert entry["status"] == "deleting"
        assert path.endswith("/records/opaque%2F42")
        deletes.append(body.copy())
        if len(deletes) == 1:
            raise RuntimeError("lost delete response")
        return {"success": True}

    def engine():
        return Engine(
            tmp_path / "state",
            api,
            "https://console.amber.systems",
            {"example.com": ZONE},
        )

    engine().perform("_acme-challenge.example.com", "value")
    assert hasattr(engine(), "cleanup")
    with pytest.raises(RuntimeError):
        engine().cleanup("_acme-challenge.example.com", "value")
    engine().cleanup("_acme-challenge.example.com", "value")
    engine().cleanup("_acme-challenge.example.com", "value")
    assert len(deletes) == 2
    assert deletes[0] == deletes[1]
    assert deletes[0]["baseline"] == "a" * 64


def test_recover_cleans_abandoned_challenges(tmp_path):
    import pytest

    from certbot_dns_amber.core import Engine

    calls = []

    def api(method, path, body=None):
        calls.append((method, body))
        if method == "GET":
            return {"zone": {"id": ZONE, "domain": "example.com"}}
        if method == "DELETE":
            return {"success": True}
        if len([c for c in calls if c[0] == "POST"]) == 1:
            raise RuntimeError("lost")
        return {"success": True, "record": {"Id": "x", "Revision": "a" * 64, **body}}

    e = Engine(
        tmp_path / "state", api, "https://console.amber.systems", {"example.com": ZONE}
    )
    with pytest.raises(RuntimeError):
        e.perform("_acme-challenge.example.com", "value")
    assert hasattr(e, "recover")
    e.recover()
    assert [c[0] for c in calls] == ["GET", "POST", "POST", "DELETE"]
    assert calls[1][1] == calls[2][1]
    e.recover()
    assert len(calls) == 4


ZONE = "59ade904-17bc-4e76-9c7e-a0fead90db67"
