"""Durable command journal. No DNS inventory matching or adoption."""

import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from functools import wraps
from pathlib import Path
from urllib.parse import quote

from certbot.errors import PluginError


def require(condition):
    if not condition:
        raise ValueError("Invalid journal")


def private_file(path):
    """Read owner-only regular files without following a final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise PluginError("Unsafe private file permissions or ownership.")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def identity(endpoint, name, value):
    return hashlib.sha256(json.dumps([endpoint, name, value]).encode()).hexdigest()


def valid_record(record, body):
    return (
        isinstance(record, dict)
        and type(record.get("Id")) in (str, int)
        and str(record["Id"]) not in ("", ".", "..")
        and isinstance(record.get("Revision"), str)
        and re.fullmatch("[a-f0-9]{64}", record["Revision"]) is not None
        and type(record.get("Type")) is int
        and record["Type"] == 3
        and record.get("Name") == body["Name"]
        and record.get("Value") == body["Value"]
    )


def locked(method):
    @wraps(method)
    def run(self, *args, **kwargs):
        self.directory.mkdir(mode=0o700, exist_ok=True)
        parent_fd = os.open(self.directory.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        info = self.directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise PluginError("Unsafe journal directory.")
        fd = None
        try:
            fd = os.open(
                self.directory / "lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
            )
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
            ):
                raise PluginError("Unsafe journal lock.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PluginError(
                    "Journal busy; another process holds the lock."
                ) from None
            return method(self, *args, **kwargs)
        except OSError:
            raise PluginError(
                "Journal I/O failed; preserve state and obtain operator assistance."
            ) from None
        finally:
            if fd is not None:
                os.close(fd)

    return run


class Engine:
    def __init__(self, directory, api, endpoint, zones):
        self.directory = Path(directory)
        if not self.directory.is_absolute():
            raise PluginError("State directory must be an absolute path.")
        self.api, self.endpoint, self.zones = api, endpoint, zones

    def _load(self):
        # All callers hold the validated directory's process lock.
        try:
            raw = private_file(self.directory / "journal.json")
        except FileNotFoundError:
            return {"version": 1, "entries": {}}
        except OSError:
            raise PluginError("Unsafe journal file.") from None
        try:
            journal = json.loads(raw)
            require(
                set(journal) == {"version", "entries", "checksum"}
                and type(journal["version"]) is int
                and journal["version"] == 1
            )
            require(
                journal["checksum"]
                == hashlib.sha256(
                    json.dumps(journal["entries"], sort_keys=True).encode()
                ).hexdigest()
            )
            require(isinstance(journal["entries"], dict))
            for key, entry in journal["entries"].items():
                body = entry["create"]
                require(entry["endpoint"] == self.endpoint)
                require(str(uuid.UUID(entry["zone"])) == entry["zone"])
                require(
                    entry["name"]
                    == (body["Name"] + "." if body["Name"] else "") + entry["domain"]
                )
                require(
                    key == identity(entry["endpoint"], entry["name"], body["Value"])
                )
                require(set(body) == {"Type", "Name", "Value", "Ttl", "request_key"})
                require(
                    type(body["Type"]) is int
                    and body["Type"] == 3
                    and body["Ttl"] == 60
                )
                require(isinstance(body["Value"], str) and body["Value"])
                require(str(uuid.UUID(body["request_key"])) == body["request_key"])
                require(
                    entry["status"] in ("creating", "created", "deleting", "deleted")
                )
                if entry["status"] != "creating":
                    require(valid_record(entry["record"], body))
                if entry["status"] in ("deleting", "deleted"):
                    require(set(entry["delete"]) == {"baseline", "request_key"})
                    require(entry["delete"]["baseline"] == entry["record"]["Revision"])
                    require(
                        str(uuid.UUID(entry["delete"]["request_key"]))
                        == entry["delete"]["request_key"]
                    )
                    require(entry["delete"]["request_key"] != body["request_key"])
            return journal
        except (ValueError, TypeError, KeyError, AssertionError):
            raise PluginError(
                "Invalid journal; preserve it and obtain operator assistance."
            ) from None

    def _save(self, journal):
        journal["checksum"] = hashlib.sha256(
            json.dumps(journal["entries"], sort_keys=True).encode()
        ).hexdigest()
        path = self.directory / "journal.json"
        temporary = self.directory / (str(uuid.uuid4()) + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(journal, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)

    def _create(self, journal, entry):
        result = self.api(
            "POST", "/api/v1/dns/zones/" + entry["zone"] + "/records", entry["create"]
        )
        if (
            not isinstance(result, dict)
            or result.get("success") is not True
            or not valid_record(result.get("record"), entry["create"])
        ):
            raise PluginError(
                "Create not confirmed; original UUID retained. Operator assistance may be required."
            )
        entry["record"] = result["record"]
        entry["status"] = "created"
        self._save(journal)

    @locked
    def cleanup(self, name, value):
        journal = self._load()
        entry = journal["entries"].get(identity(self.endpoint, name, value))
        if entry is None:
            raise PluginError("No durable create identity; cleanup refused.")
        self._cleanup_entry(journal, entry)

    @locked
    def recover(self):
        """Explicitly finish cleanup of all abandoned entries, never adopt records."""
        journal = self._load()
        for entry in journal["entries"].values():
            self._cleanup_entry(journal, entry)

    def _cleanup_entry(self, journal, entry):
        if entry["status"] == "creating":
            self._create(journal, entry)
        if entry["status"] == "deleted":
            return
        record = entry["record"]
        entry.setdefault(
            "delete", {"baseline": record["Revision"], "request_key": str(uuid.uuid4())}
        )
        entry["status"] = "deleting"
        self._save(journal)
        result = self.api(
            "DELETE",
            "/api/v1/dns/zones/"
            + entry["zone"]
            + "/records/"
            + quote(str(record["Id"]), safe=""),
            entry["delete"],
        )
        if not isinstance(result, dict) or result.get("success") is not True:
            raise PluginError("Delete not confirmed; durable state retained.")
        entry["status"] = "deleted"
        self._save(journal)

    @locked
    def perform(self, name, value):
        journal = self._load()
        key = identity(self.endpoint, name, value)
        entry = journal["entries"].get(key)
        if entry:
            if entry["status"] == "created":
                return
            if entry["status"] != "creating":
                raise PluginError(
                    "Challenge cleanup already started; will not recreate."
                )
            self._create(journal, entry)
            return
        if any(
            e["status"] in ("creating", "deleting") for e in journal["entries"].values()
        ):
            raise PluginError(
                "Unresolved command blocks new creates; recover original UUIDs first."
            )
        matches = [
            zone for zone in self.zones if name == zone or name.endswith("." + zone)
        ]
        if not matches:
            raise PluginError("No explicit zone mapping for challenge.")
        domain = max(matches, key=len)
        zone = self.zones[domain]
        detail = self.api("GET", "/api/v1/dns/zones/" + zone)
        if (
            not isinstance(detail, dict)
            or not isinstance(detail.get("zone"), dict)
            or detail["zone"].get("id") != zone
            or detail["zone"].get("domain") != domain
        ):
            raise PluginError("Zone identity mismatch.")
        body = {
            "Type": 3,
            "Name": name[: -len(domain) - 1] if name != domain else "",
            "Value": value,
            "Ttl": 60,
            "request_key": str(uuid.uuid4()),
        }
        entry = {
            "zone": zone,
            "domain": domain,
            "name": name,
            "endpoint": self.endpoint,
            "create": body,
            "status": "creating",
        }
        journal["entries"][key] = entry
        self._save(journal)
        self._create(journal, entry)
