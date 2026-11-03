import json

import pytest
from certbot.errors import PluginError

from certbot_dns_amber.core import Engine

A = "59ade904-17bc-4e76-9c7e-a0fead90db67"
B = "710864e6-3a56-4fa9-b0ce-3b2ed878b7ab"


def test_multiple_values_and_longest_explicit_zone(tmp_path):
    calls = []

    def api(method, path, body=None):
        calls.append((method, path, body))
        if method == "GET":
            zone = path.rsplit("/", 1)[1]
            return {
                "zone": {
                    "id": zone,
                    "domain": {A: "example.com", B: "sub.example.com"}[zone],
                }
            }
        if method == "DELETE":
            return {"success": True}
        return {
            "success": True,
            "record": {"Id": len(calls), "Revision": "a" * 64, **body},
        }

    e = Engine(
        tmp_path / "state",
        api,
        "https://console.amber.systems",
        {"example.com": A, "sub.example.com": B},
    )
    e.perform("_acme-challenge.example.com", "apex")
    e.perform("_acme-challenge.example.com", "wildcard")
    e.perform("_acme-challenge.sub.example.com", "sub")
    posts = [c for c in calls if c[0] == "POST"]
    assert len({c[2]["request_key"] for c in posts}) == 3
    assert [c[2]["Name"] for c in posts] == ["_acme-challenge"] * 3
    assert B in posts[-1][1]
    e.cleanup("_acme-challenge.example.com", "apex")
    state = json.loads((tmp_path / "state/journal.json").read_text())
    assert sorted(e["status"] for e in state["entries"].values()) == [
        "created",
        "created",
        "deleted",
    ]
    with pytest.raises(PluginError, match="mapping"):
        e.perform("_acme-challenge.evilexample.com", "evil")


@pytest.mark.parametrize("status", [401, 403, 404, 409, 502])
def test_failed_delete_keeps_original_identity(tmp_path, status):
    calls = []

    def api(method, path, body=None):
        if method == "GET":
            return {"zone": {"id": A, "domain": "example.com"}}
        if method == "POST":
            return {
                "success": True,
                "record": {"Id": "opaque", "Revision": "a" * 64, **body},
            }
        calls.append(body.copy())
        raise PluginError("Console HTTP status %d" % status)

    e = Engine(
        tmp_path / "state", api, "https://console.amber.systems", {"example.com": A}
    )
    e.perform("_acme-challenge.example.com", "value")
    for _ in range(2):
        with pytest.raises(PluginError):
            e.cleanup("_acme-challenge.example.com", "value")
    assert calls[0] == calls[1]
    state = json.loads((tmp_path / "state/journal.json").read_text())
    assert next(iter(state["entries"].values()))["status"] == "deleting"
