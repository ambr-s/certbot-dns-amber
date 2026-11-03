import importlib.util

import pytest
from certbot.errors import PluginError


@pytest.mark.parametrize(
    "status,payload",
    [
        (302, {"data": {"success": True}}),
        (404, {"data": {"success": True}}),
        (409, {"error": {"message": "secret"}}),
        (200, {"data": {}, "error": {}}),
        (200, {}),
        (200, {"data": []}),
        (201, {"data": {}}),
    ],
)
def test_client_rejects_unconfirmed_delete(status, payload):
    from certbot_dns_amber.client import Client

    client = Client("secret")

    class Response:
        status_code = status

        def json(self):
            return payload

        def close(self):
            pass

    client.session.request = lambda *a, **kw: Response()
    with pytest.raises(PluginError) as exc:
        client("DELETE", "/api/v1/dns/zones/zone/records/42", {})
    assert "secret" not in str(exc.value)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://console.amber.systems",
        "https://user:secret@console.amber.systems",
        "https://console.amber.systems/other",
        "https://console.amber.systems?token=secret",
        "https://console.amber.systems#secret",
        "//console.amber.systems",
    ],
)
def test_invalid_endpoint_refused(endpoint):
    from certbot_dns_amber.client import Client

    with pytest.raises(PluginError):
        Client("secret", endpoint)


def test_transport_exception_redacted():
    import requests

    from certbot_dns_amber.client import Client

    client = Client("secret")

    def request(*args, **kwargs):
        raise requests.RequestException("secret response")

    client.session.request = request
    with pytest.raises(PluginError) as exc:
        client("GET", "/api/v1/dns/zones/zone")
    assert "secret" not in str(exc.value)
    assert exc.value.__suppress_context__


def test_client_sends_verified_https_without_redirects():
    assert importlib.util.find_spec("certbot_dns_amber.client") is not None
    from certbot_dns_amber.client import Client

    client = Client("secret")

    class Response:
        status_code = 201

        def json(self):
            return {"data": {"success": True}}

        def close(self):
            pass

    def request(method, url, **kwargs):
        assert method == "POST"
        assert url == "https://console.amber.systems/api/v1/dns/zones/zone/records"
        assert kwargs["headers"]["Authorization"] == "Bearer secret"
        assert kwargs["allow_redirects"] is False
        assert kwargs["verify"] is True
        assert kwargs["timeout"] == (10, 30)
        assert client.session.trust_env is False
        return Response()

    client.session.request = request
    assert client("POST", "/api/v1/dns/zones/zone/records", {"Type": 3}) == {
        "success": True
    }
