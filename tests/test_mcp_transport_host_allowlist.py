"""A non-loopback bind must be reachable at its own address (issue #241).

`src/server.py` builds `FastMCP(...)` without a host, so the SDK auto-enables
DNS-rebinding protection pinned to loopback. `run_networked` then moved
`settings.host` to the LAN address but left `settings.transport_security`
alone, so the streamable-http app answered every request to that address with
HTTP 421 — after the bearer check, so a wrong token still got 401 and the bind
looked healthy. Reproduced on v4.7.3 with the real SDK app before the fix.
"""
import os
import unittest
from unittest import mock

from src.utils import mcp_transport as T

INIT = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "c", "version": "0"}},
}
ACCEPT = "application/json, text/event-stream"


class AllowlistPolicyTests(unittest.TestCase):
    def test_loopback_bind_leaves_the_sdk_default_alone(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            with self.subTest(host=host):
                self.assertIsNone(T.transport_security_for(host))

    def test_lan_bind_allows_its_own_host_and_loopback_with_protection_on(self):
        sec = T.transport_security_for("192.168.1.50")
        self.assertTrue(sec.enable_dns_rebinding_protection)
        self.assertIn("192.168.1.50:*", sec.allowed_hosts)
        for name in ("127.0.0.1:*", "localhost:*", "[::1]:*"):
            self.assertIn(name, sec.allowed_hosts)
        self.assertIn("http://192.168.1.50:*", sec.allowed_origins)

    def test_extra_names_join_the_allowlist(self):
        sec = T.transport_security_for("192.168.1.50", ["studio-mac.local", "studio"])
        self.assertIn("studio-mac.local:*", sec.allowed_hosts)
        self.assertIn("studio:*", sec.allowed_hosts)
        self.assertIn("http://studio:*", sec.allowed_origins)

    def test_ipv6_bind_is_bracketed(self):
        sec = T.transport_security_for("fd00::5")
        self.assertIn("[fd00::5]:*", sec.allowed_hosts)

    def test_wildcard_bind_without_names_turns_protection_off(self):
        sec = T.transport_security_for("0.0.0.0")
        self.assertFalse(sec.enable_dns_rebinding_protection)
        self.assertEqual(sec.allowed_hosts, [])

    def test_wildcard_bind_with_names_keeps_protection_on(self):
        sec = T.transport_security_for("0.0.0.0", ["studio.lan"])
        self.assertTrue(sec.enable_dns_rebinding_protection)
        self.assertIn("studio.lan:*", sec.allowed_hosts)
        self.assertNotIn("0.0.0.0:*", sec.allowed_hosts)

    def test_env_list_is_split_stripped_and_deduped(self):
        env = {T.ALLOWED_HOSTS_ENV: " a.lan, b.lan ,a.lan,, "}
        self.assertEqual(T.extra_allowed_hosts(env), ["a.lan", "b.lan"])
        self.assertEqual(T.extra_allowed_hosts({}), [])

    def test_loopback_with_exact_proxy_name_keeps_protection_and_https(self):
        proxy = "macbook-pro.tailfacc7e.ts.net"
        sec = T.transport_security_for("127.0.0.1", [proxy])
        self.assertTrue(sec.enable_dns_rebinding_protection)
        self.assertIn(proxy, sec.allowed_hosts)
        self.assertIn(f"{proxy}:*", sec.allowed_hosts)
        for name in ("127.0.0.1:*", "localhost:*", "[::1]:*"):
            self.assertIn(name, sec.allowed_hosts)
        self.assertIn(f"https://{proxy}", sec.allowed_origins)
        self.assertIn(f"https://{proxy}:*", sec.allowed_origins)
        self.assertIn(f"http://{proxy}", sec.allowed_origins)
        self.assertIn(f"http://{proxy}:*", sec.allowed_origins)
        # Listing a proxy name does not open https loopback origins.
        self.assertIn("http://127.0.0.1:*", sec.allowed_origins)
        self.assertNotIn("https://127.0.0.1", sec.allowed_origins)
        self.assertNotIn("https://127.0.0.1:*", sec.allowed_origins)
        self.assertNotIn("*", sec.allowed_hosts)
        self.assertNotIn("*", sec.allowed_origins)

    def test_localhost_and_ipv6_loopback_honor_the_same_exact_name(self):
        proxy = "macbook-pro.tailfacc7e.ts.net"
        for host in ("localhost", "::1"):
            with self.subTest(host=host):
                sec = T.transport_security_for(host, [proxy])
                self.assertTrue(sec.enable_dns_rebinding_protection)
                self.assertIn(proxy, sec.allowed_hosts)
                self.assertIn(f"https://{proxy}", sec.allowed_origins)

    def test_host_port_in_the_list_is_the_same_exact_name(self):
        proxy = "macbook-pro.tailfacc7e.ts.net"
        sec = T.transport_security_for("127.0.0.1", [f"{proxy}:443", proxy])
        self.assertEqual(
            [value for value in sec.allowed_hosts if proxy in value],
            [f"{proxy}:*", proxy])
        self.assertNotIn(f"[{proxy}:443]:*", sec.allowed_hosts)
        ipv6 = T.transport_security_for("127.0.0.1", ["fd00::5"])
        self.assertIn("[fd00::5]:*", ipv6.allowed_hosts)
        self.assertIn("[fd00::5]", ipv6.allowed_hosts)

    def test_wildcard_entries_are_not_installed(self):
        proxy = "macbook-pro.tailfacc7e.ts.net"
        with self.assertLogs("davinci-resolve-mcp", level="WARNING"):
            sec = T.transport_security_for("127.0.0.1", [
                "*", "*.ts.net", "https://evil.example", "  ", proxy, "*",
            ])
        self.assertTrue(sec.enable_dns_rebinding_protection)
        self.assertIn(proxy, sec.allowed_hosts)
        for banned in ("*", "*:*", "*.ts.net", "*.ts.net:*",
                       "https://evil.example", "https://evil.example:*"):
            self.assertNotIn(banned, sec.allowed_hosts)
            self.assertNotIn(banned, sec.allowed_origins)
        # Junk alone does not replace the SDK loopback default.
        with self.assertLogs("davinci-resolve-mcp", level="WARNING"):
            self.assertIsNone(T.transport_security_for(
                "127.0.0.1", ["*", "*.evil.com", "https://evil.example"]))

    def test_wildcard_bind_with_only_rejected_names_stays_protected(self):
        with self.assertLogs("davinci-resolve-mcp", level="WARNING"):
            sec = T.transport_security_for("0.0.0.0", ["*"])
        self.assertTrue(sec.enable_dns_rebinding_protection)
        self.assertNotIn("*", sec.allowed_hosts)
        self.assertNotIn("*:*", sec.allowed_hosts)
        self.assertIn("127.0.0.1:*", sec.allowed_hosts)

    def test_lan_bind_does_not_gain_https_unless_the_name_is_listed(self):
        sec = T.transport_security_for("192.168.1.50")
        self.assertNotIn("https://192.168.1.50", sec.allowed_origins)
        self.assertNotIn("https://192.168.1.50:*", sec.allowed_origins)
        self.assertNotIn("192.168.1.50", sec.allowed_hosts)
        listed = T.transport_security_for(
            "192.168.1.50", ["studio-mac.local"])
        self.assertIn("studio-mac.local", listed.allowed_hosts)
        self.assertIn("https://studio-mac.local", listed.allowed_origins)
        self.assertIn("https://studio-mac.local:*", listed.allowed_origins)
        self.assertNotIn("https://192.168.1.50:*", listed.allowed_origins)


class RealAppTests(unittest.TestCase):
    """Drive the real FastMCP streamable-http app through run_networked."""

    def setUp(self):
        self._env = {k: os.environ.get(k) for k in
                     ("DAVINCI_MCP_HOST", "DAVINCI_MCP_PORT", "DAVINCI_MCP_TOKEN",
                      T.ALLOWED_HOSTS_ENV)}
        os.environ["DAVINCI_MCP_TOKEN"] = "secret"
        os.environ["DAVINCI_MCP_PORT"] = "8000"
        os.environ.pop(T.ALLOWED_HOSTS_ENV, None)

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        T.clear_transport_state()

    def _app_for(self, host, allowed=None):
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("allowlist-test")  # no host, exactly like src/server.py
        os.environ["DAVINCI_MCP_HOST"] = host
        if allowed is None:
            os.environ.pop(T.ALLOWED_HOSTS_ENV, None)
        else:
            os.environ[T.ALLOWED_HOSTS_ENV] = allowed
        built = {}
        real = mcp.streamable_http_app

        def capture():
            built["app"] = real()
            return built["app"]

        with mock.patch("uvicorn.run"), \
                mock.patch.object(mcp, "streamable_http_app", capture):
            T.run_networked(mcp, "streamable-http")
        return mcp, built["app"]

    @staticmethod
    def _post(client, host_header, token="secret", origin=None, include_auth=True):
        headers = {"Accept": ACCEPT, "Host": host_header}
        if include_auth:
            headers["Authorization"] = f"Bearer {token}"
        if origin is not None:
            headers["Origin"] = origin
        return client.post("/mcp", json=INIT, headers=headers)

    def test_lan_bind_serves_initialize_at_its_own_address(self):
        from starlette.testclient import TestClient
        mcp, app = self._app_for("192.168.1.50")
        self.assertIn("192.168.1.50:*", mcp.settings.transport_security.allowed_hosts)
        with TestClient(app) as c:
            self.assertEqual(self._post(c, "192.168.1.50:8000").status_code, 200)
            # The bearer check still runs first, and loopback still works.
            self.assertEqual(self._post(c, "192.168.1.50:8000", token="wrong").status_code, 401)
            self.assertEqual(self._post(c, "127.0.0.1:8000").status_code, 200)
            # DNS-rebinding protection is still on: a foreign Host is refused.
            self.assertEqual(self._post(c, "evil.example:8000").status_code, 421)

    def test_loopback_bind_is_unchanged(self):
        from starlette.testclient import TestClient
        mcp, app = self._app_for("127.0.0.1")
        self.assertEqual(mcp.settings.transport_security.allowed_hosts,
                         ["127.0.0.1:*", "localhost:*", "[::1]:*"])
        with TestClient(app) as c:
            self.assertEqual(self._post(c, "127.0.0.1:8000").status_code, 200)
            self.assertEqual(self._post(c, "192.168.1.50:8000").status_code, 421)
            # An unset allowlist does not accept the proxy hostname.
            self.assertEqual(
                self._post(c, "macbook-pro.tailfacc7e.ts.net").status_code, 421)

    def test_loopback_bind_accepts_exact_https_proxy_and_rejects_the_rest(self):
        """Tailscale Serve forwards the public hostname to 127.0.0.1.

        SDK 1.30 matches ``name:*`` only when a port is present, and its
        loopback default origins are ``http`` only. The three Host forms that
        returned 421 (bare, :443, :8000) and the matching https Origins must
        pass, with the bearer check unchanged and every other name refused.
        """
        from starlette.testclient import TestClient
        proxy = "macbook-pro.tailfacc7e.ts.net"
        mcp, app = self._app_for(
            "127.0.0.1", f"{proxy},*,*.evil.com,https://evil.example")
        hosts = mcp.settings.transport_security.allowed_hosts
        origins = mcp.settings.transport_security.allowed_origins
        self.assertTrue(
            mcp.settings.transport_security.enable_dns_rebinding_protection)
        self.assertIn(proxy, hosts)
        self.assertIn(f"{proxy}:*", hosts)
        self.assertNotIn("*", hosts)
        self.assertNotIn("*:*", hosts)
        self.assertIn(f"https://{proxy}", origins)
        self.assertIn(f"https://{proxy}:*", origins)
        self.assertNotIn("https://127.0.0.1:*", origins)

        accepted_hosts = (proxy, f"{proxy}:443", f"{proxy}:8000")
        accepted_origins = (
            None,
            f"https://{proxy}",
            f"https://{proxy}:443",
            f"https://{proxy}:8000",
            f"http://{proxy}",
        )
        rejected_hosts = (
            "evil.example",
            "evil.example:443",
            "evil.example:8000",
            f"{proxy}.evil.com",
            f"{proxy}.evil.com:443",
            f"not-{proxy}",
            f"not-{proxy}:443",
            "192.168.1.50:8000",
            "100.80.148.53:8000",
        )
        rejected_origins = (
            "https://evil.example",
            "https://evil.example:443",
            f"https://{proxy}.evil.com",
            f"https://not-{proxy}",
            "http://evil.example",
            "https://127.0.0.1:8000",
            "*",
            "https://*",
        )
        with TestClient(app) as c:
            for host in accepted_hosts:
                for origin in accepted_origins:
                    with self.subTest(host=host, origin=origin):
                        response = self._post(c, host, origin=origin)
                        self.assertEqual(response.status_code, 200, response.text)
            # Local clients keep working, including the SDK's http loopback origin.
            self.assertEqual(self._post(c, "127.0.0.1:8000").status_code, 200)
            self.assertEqual(self._post(
                c, "127.0.0.1:8000", origin="http://127.0.0.1:8000").status_code, 200)
            self.assertEqual(self._post(c, "localhost:8000").status_code, 200)
            # Bearer still runs first: missing or wrong token is 401 even when
            # the Host would have been 421.
            self.assertEqual(self._post(
                c, proxy, include_auth=False).status_code, 401)
            self.assertEqual(self._post(
                c, "evil.example", include_auth=False).status_code, 401)
            self.assertEqual(self._post(
                c, f"{proxy}:443", token="wrong",
                origin=f"https://{proxy}").status_code, 401)
            for host in rejected_hosts:
                with self.subTest(host=host):
                    response = self._post(c, host, origin=f"https://{proxy}")
                    self.assertEqual(response.status_code, 421, response.text)
                    self.assertIn("Invalid Host header", response.text)
            for origin in rejected_origins:
                with self.subTest(origin=origin):
                    response = self._post(c, proxy, origin=origin)
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertIn("Invalid Origin header", response.text)


if __name__ == "__main__":
    unittest.main()
