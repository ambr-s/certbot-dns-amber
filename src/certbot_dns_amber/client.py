"""Verified HTTPS transport; errors never include response bodies or secrets."""

import requests
from certbot.errors import PluginError

DEFAULT_ENDPOINT = "https://console.amber.systems"


class Client:
    def __init__(self, token, endpoint=DEFAULT_ENDPOINT):
        from urllib.parse import urlsplit

        try:
            parsed = urlsplit(endpoint)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
                or any(c.isspace() for c in endpoint)
            ):
                raise ValueError()
            _ = parsed.port  # Access validates malformed/out-of-range ports.
        except ValueError:
            raise PluginError(
                "API endpoint must be an HTTPS origin without credentials, path, query or fragment."
            ) from None
        self.endpoint = endpoint.rstrip("/")
        self.token = token
        self.session = requests.Session()
        self.session.trust_env = False

    def __call__(self, method, path, body=None):
        response = None
        try:
            response = self.session.request(
                method,
                self.endpoint + path,
                headers={
                    "Authorization": "Bearer " + self.token,
                    "Accept": "application/json",
                },
                json=body,
                verify=True,
                allow_redirects=False,
                timeout=(10, 30),
            )
            expected = 201 if method == "POST" else 200
            if response.status_code != expected:
                raise PluginError(
                    "Console HTTP status %s; command not confirmed. Durable state retained."
                    % response.status_code
                )
            envelope = response.json()
            if (
                not isinstance(envelope, dict)
                or set(envelope) != {"data"}
                or not isinstance(envelope["data"], dict)
            ):
                raise PluginError(
                    "Invalid console success envelope; command not confirmed."
                )
            return envelope["data"]
        except (requests.RequestException, ValueError):
            raise PluginError(
                "Console transport or JSON failure; command not confirmed. Durable state retained."
            ) from None
        finally:
            if response is not None:
                response.close()
