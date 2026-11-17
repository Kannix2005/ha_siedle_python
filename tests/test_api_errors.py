"""HTTP errors of the Siedle cloud API must reach the caller (stubbed requests)."""
import importlib
import sys
import types
import unittest
from unittest import mock

import test_sip_forwarding  # registers the siedle_ut package


class HTTPError(Exception):
    def __init__(self, response=None):
        super().__init__("http error")
        self.response = response


class RequestException(Exception):
    pass


req = types.ModuleType("requests")
req.HTTPError = HTTPError
req.Response = object
req.exceptions = types.SimpleNamespace(RequestException=RequestException)
req.auth = types.ModuleType("requests.auth")
req.auth.HTTPBasicAuth = object
sys.modules.setdefault("requests", req)
sys.modules.setdefault("requests.auth", req.auth)
ro = types.ModuleType("requests_oauthlib"); ro.OAuth2Session = object
sys.modules.setdefault("requests_oauthlib", ro)
ol = types.ModuleType("oauthlib"); ol2 = types.ModuleType("oauthlib.oauth2")
ol2.LegacyApplicationClient = object
sys.modules.setdefault("oauthlib", ol); sys.modules.setdefault("oauthlib.oauth2", ol2)
api = importlib.import_module("siedle_ut.siedle_api")


def failing(status):
    def call(*a, **kw):
        resp = mock.MagicMock(status_code=status)
        resp.raise_for_status.side_effect = api.requests.HTTPError(response=resp)
        return resp
    return call


class ApiErrorTest(unittest.TestCase):
    def setUp(self):
        self.s = api.Siedle.__new__(api.Siedle)
        self.s._client = mock.MagicMock()

    def test_http_error_is_raised_for_every_verb(self):
        for verb, call in (("get", lambda: self.s._get("/x")),
                           ("post", lambda: self.s._post("/x", {})),
                           ("put", lambda: self.s._put("/x", {}))):
            getattr(self.s._client, verb).side_effect = failing(403)
            with self.assertRaises(api.requests.HTTPError, msg=verb):
                call()

    def test_open_door_fails_loudly_on_server_error(self):
        self.s._client.post.side_effect = failing(500)
        self.s._generate_signature = mock.MagicMock(return_value={})
        with self.assertRaises(api.requests.HTTPError):
            self.s.openDoor(contact_id="c1")

    def test_success_still_returns_payload(self):
        ok = mock.MagicMock(text="{}")
        ok.json.return_value = {"id": 1}
        self.s._client.post.return_value = ok
        self.assertEqual(self.s._post("/x", {}), {"id": 1})


if __name__ == "__main__":
    unittest.main()
