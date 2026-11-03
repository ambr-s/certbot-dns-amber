import json
import os

import pytest
from certbot.errors import PluginError

from certbot_dns_amber.core import Engine

ZONE = "59ade904-17bc-4e76-9c7e-a0fead90db67"
NAME = "_acme-challenge.example.com"


def engine(tmp_path, api):
    return Engine(
        tmp_path / "state", api, "https://console.amber.systems", {"example.com": ZONE}
    )


def good_api(method, path, body=None):
    if method == "GET":
        return {"zone": {"id": ZONE, "domain": "example.com"}}
    return {"success": True, "record": {"Id": 42, "Revision": "a" * 64, **body}}


def test_cross_process_lock_refuses_parallel_mutation(tmp_path):
    import fcntl
    import multiprocessing

    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    ready = multiprocessing.Event()
    stop = multiprocessing.Event()

    def holder():
        fd = os.open(directory / "lock", os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        ready.set()
        stop.wait(10)
        os.close(fd)

    process = multiprocessing.get_context("fork").Process(target=holder)
    process.start()
    try:
        assert ready.wait(5)
        with pytest.raises(PluginError, match="busy"):
            engine(tmp_path, good_api).perform(NAME, "value")
    finally:
        stop.set()
        process.join(5)
    engine(tmp_path, good_api).perform(NAME, "value")


def test_corrupt_state_refused_with_python_optimization(tmp_path):
    import subprocess
    import sys
    from pathlib import Path

    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    (directory / "journal.json").write_text('{"version":2,"entries":{}}')
    (directory / "journal.json").chmod(0o600)
    script = "from certbot_dns_amber.core import Engine; import sys; Engine(sys.argv[1], None, 'https://console.amber.systems', {}).recover()"
    result = subprocess.run(
        [sys.executable, "-O", "-c", script, str(directory)],
        env={
            **os.environ,
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Invalid journal" in result.stderr


def test_valid_json_corruption_of_request_uuid_fails_closed(tmp_path):
    import uuid

    def lost(method, path, body=None):
        if method == "GET":
            return good_api(method, path)
        raise PluginError("lost")

    with pytest.raises(PluginError):
        engine(tmp_path, lost).perform(NAME, "value")
    path = tmp_path / "state/journal.json"
    data = json.loads(path.read_text())
    next(iter(data["entries"].values()))["create"]["request_key"] = str(uuid.uuid4())
    path.write_text(json.dumps(data))
    with pytest.raises(PluginError, match="journal"):
        engine(tmp_path, good_api).perform(NAME, "value")


def test_new_journal_directory_is_durable_before_post(tmp_path, monkeypatch):
    seen = []
    original = os.fsync

    def fsync(fd):
        seen.append(os.fstat(fd).st_ino)
        original(fd)

    monkeypatch.setattr(os, "fsync", fsync)

    def api(method, path, body=None):
        if method == "POST":
            assert tmp_path.stat().st_ino in seen
        return good_api(method, path, body)

    engine(tmp_path, api).perform(NAME, "value")


def test_unknown_create_blocks_new_validation(tmp_path):
    def lost(method, path, body=None):
        if method == "GET":
            return good_api(method, path)
        raise PluginError("unknown")

    with pytest.raises(PluginError):
        engine(tmp_path, lost).perform(NAME, "old")
    with pytest.raises(PluginError, match="Unresolved"):
        engine(tmp_path, good_api).perform(NAME, "new")


@pytest.mark.parametrize(
    "contents",
    ["{", "{}", '{"version":2,"entries":{}}', '{"version":1,"entries":{"bad":{}}}'],
)
def test_corrupt_state_fails_closed(tmp_path, contents):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    (directory / "journal.json").write_text(contents)
    (directory / "journal.json").chmod(0o600)
    calls = []
    with pytest.raises(PluginError, match="journal"):
        engine(tmp_path, lambda *a: calls.append(a)).perform(NAME, "value")
    assert not calls


@pytest.mark.parametrize("target", ["directory", "journal", "symlink"])
def test_unsafe_state_refused(tmp_path, target):
    engine(tmp_path, good_api).perform(NAME, "value")
    directory = tmp_path / "state"
    if target == "directory":
        directory.chmod(0o755)
    elif target == "journal":
        (directory / "journal.json").chmod(0o644)
    else:
        (directory / "journal.json").rename(directory / "other")
        (directory / "journal.json").symlink_to(directory / "other")
    with pytest.raises(PluginError):
        engine(tmp_path, good_api).perform(NAME, "value")


@pytest.mark.parametrize(
    "record",
    [
        None,
        {},
        {"Id": True, "Revision": "a" * 64},
        {"Id": "x", "Revision": "INVALID"},
        {
            "Id": "x",
            "Revision": "a" * 64,
            "Type": 3,
            "Name": "_acme-challenge",
            "Value": "DIFFERENT",
        },
    ],
)
def test_invalid_create_handle_retains_uncertainty(tmp_path, record):
    def api(method, path, body=None):
        return (
            good_api(method, path)
            if method == "GET"
            else {"success": True, "record": record}
        )

    with pytest.raises(PluginError):
        engine(tmp_path, api).perform(NAME, "value")
    entry = next(
        iter(
            json.loads((tmp_path / "state/journal.json").read_text())[
                "entries"
            ].values()
        )
    )
    assert entry["status"] == "creating"


def test_cleaned_challenge_never_recreated(tmp_path):
    def api(method, path, body=None):
        return {"success": True} if method == "DELETE" else good_api(method, path, body)

    engine(tmp_path, api).perform(NAME, "value")
    engine(tmp_path, api).cleanup(NAME, "value")
    with pytest.raises(PluginError):
        engine(tmp_path, api).perform(NAME, "value")
