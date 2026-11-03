"""Certbot entry point and owner-only JSON credentials."""

import json
import re
import uuid
from pathlib import Path

from certbot.errors import PluginError
from certbot.plugins.dns_common import DNSAuthenticator

from .client import DEFAULT_ENDPOINT, Client
from .core import Engine, private_file


class Authenticator(DNSAuthenticator):
    description = (
        "Obtain certificates using scoped amber.systems console DNS credentials."
    )

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=60):
        super().add_parser_arguments(add, default_propagation_seconds)
        add(
            "credentials", help="Absolute path to private JSON token and zone mappings."
        )
        add("endpoint", default=DEFAULT_ENDPOINT, help="Verified HTTPS console origin.")
        add(
            "state-dir",
            help="Absolute path to persistent private journal directory; defaults to config-dir/dns-amber (must be absolute).",
        )

    def more_info(self):
        return "Creates separate TXT records using scoped console credentials and a durable command journal. Propagation delay is not public DNS proof."

    def _setup_credentials(self):
        delay = self.conf("propagation-seconds")
        if type(delay) is not int or delay < 0:
            raise PluginError("DNS propagation delay must be a nonnegative integer.")
        try:
            filename = self.conf("credentials")
            if not filename or not Path(filename).is_absolute():
                raise ValueError()
            data = json.loads(private_file(filename))
            if not isinstance(data, dict) or set(data) != {"token", "zones"}:
                raise ValueError()
            if not isinstance(data["token"], str) or not re.fullmatch(
                r"[!-~]+", data["token"]
            ):
                raise ValueError()
            if not isinstance(data["zones"], dict) or not data["zones"]:
                raise ValueError()
            for domain, zone in data["zones"].items():
                if len(domain) > 253 or not all(
                    re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label)
                    for label in domain.split(".")
                ):
                    raise ValueError()
                if not isinstance(zone, str) or str(uuid.UUID(zone)) != zone:
                    raise ValueError()
        except (ValueError, TypeError, OSError):
            raise PluginError(
                "Invalid private credentials: use an absolute owner-only JSON file with token and canonical zone mappings."
            ) from None
        client = Client(data["token"], self.conf("endpoint"))
        directory = self.conf("state-dir") or str(
            Path(self.config.config_dir) / "dns-amber"
        )
        self.engine = Engine(directory, client, client.endpoint, data["zones"])

    def _perform(self, domain, validation_name, validation):
        self.engine.perform(validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self.engine.cleanup(validation_name, validation)
