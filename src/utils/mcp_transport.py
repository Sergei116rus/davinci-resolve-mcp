"""Networked transport for the MCP server (opt-in via --transport).

stdio remains the default. The `sse` and `streamable-http` modes bind to
loopback (127.0.0.1) by default and REQUIRE a bearer token on every request, so
turning networking on never silently exposes Resolve. The token comes from
``$DAVINCI_MCP_TOKEN`` or is generated at startup. A small state file (0600,
under the per-user private state dir — never a shared tempdir) lets the control
panel show the live connection URL + token; that file is the only place a
generated token is written. It is never logged: the server's root logger
appends to ``logs/server.log`` with the default file mode and never truncates
it, so a logged token would outlive the session in a file the state file's
0600 was chosen to avoid. An interactive operator sees it once on stderr.

Security posture:
- Default host is loopback; a non-loopback bind logs a loud warning.
- DNS-rebinding protection follows the bind host (see
  ``transport_security_for``); a loopback-only allowlist on a LAN bind
  answered every request with 421 until v4.7.4 (issue #241).
- A loopback bind still keeps that loopback-only allowlist unless
  ``$DAVINCI_MCP_ALLOWED_HOSTS`` lists exact names. Those names are then
  accepted as Host (with or without a port) and as ``http`` and ``https``
  Origin, which is what a TLS proxy such as Tailscale Serve forwards while
  the server stays on 127.0.0.1. ``*`` is not an allowlist entry. Protection
  stays on, and the bearer check still runs first.
- Every HTTP request must carry ``Authorization: Bearer <token>`` (constant-time
  compared); otherwise 401.
- stdio (the default transport) is unaffected by anything here.
"""
import json
import logging
import os
import secrets
import sys
import time

from src.utils.private_state import private_state_dir, write_private_json
from src.utils.proc import windows_pid_alive

logger = logging.getLogger("davinci-resolve-mcp")


def _state_path() -> str:
    return os.path.join(private_state_dir(), "mcp_transport.json")


# Resolved lazily so DAVINCI_RESOLVE_MCP_STATE_DIR set by a test harness is honored.
TRANSPORT_STATE_PATH = _state_path()
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
#: Binds that listen on every interface. A client never sends one of these as
#: its Host header, so an allowlist cannot be derived from the bind address.
WILDCARD_HOSTS = {"0.0.0.0", "::", ""}
ALLOWED_HOSTS_ENV = "DAVINCI_MCP_ALLOWED_HOSTS"


def _host_pattern(name: str) -> str:
    """`Host`-header pattern for one name: any port, IPv6 literals bracketed.

    The MCP SDK matches this only when the header contains a port
    (``name:443``). A header that omits the default port does not match; see
    ``_explicit_name_patterns``.
    """
    name = name.strip()
    if ":" in name and not name.startswith("["):
        name = f"[{name}]"
    return f"{name}:*"


def _exact_host_name(raw):
    """One exact hostname, or None.

    ``DAVINCI_MCP_ALLOWED_HOSTS`` is a list of names, not patterns. ``*``,
    a DNS wildcard, a URL, or a wildcard bind must not become an allowlist
    entry. IPv6 literals (which contain colons) are kept.
    """
    if not isinstance(raw, str):
        return None
    name = raw.strip()
    if not name or name in WILDCARD_HOSTS or "://" in name:
        return None
    if any(c in name for c in "*?/\\#") or any(c.isspace() for c in name):
        return None
    # A trailing :port on a DNS name is the same host. Leave IPv6 literals,
    # which have more than one colon, for _host_pattern to bracket.
    if ":" in name and not name.startswith("["):
        host_part, sep, maybe_port = name.rpartition(":")
        if sep and maybe_port.isdigit() and host_part and ":" not in host_part:
            name = host_part
    return name


def _explicit_name_patterns(name: str):
    """Host values and origins for one operator-listed exact name.

    SDK 1.30 ``TransportSecurityMiddleware._validate_host`` / ``_validate_origin``
    treat ``name:*`` as "the header starts with ``name:``". Browsers and
    Tailscale Serve omit the default port, so ``Host: name`` and
    ``Origin: https://name`` need the bare value beside the any-port pattern.
    Both schemes are listed: the proxy is HTTPS, and an HTTP client of that
    same name stays allowed. This is not a hostname wildcard.
    """
    port_pattern = _host_pattern(name)
    bare = port_pattern[:-2]
    hosts = [port_pattern]
    if bare not in hosts:
        hosts.append(bare)
    origins = []
    for scheme in ("https", "http"):
        for host_value in (bare, port_pattern):
            origin = f"{scheme}://{host_value}"
            if origin not in origins:
                origins.append(origin)
    return hosts, origins


def extra_allowed_hosts(env=None):
    """Names from $DAVINCI_MCP_ALLOWED_HOSTS (comma-separated), stripped, deduped."""
    raw = (env if env is not None else os.environ).get(ALLOWED_HOSTS_ENV, "")
    seen, out = set(), []
    for name in raw.split(","):
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _loopback_http_origins():
    return [f"http://{_host_pattern(n)}" for n in sorted(LOOPBACK_HOSTS)]


def transport_security_for(host, extra_hosts=()):
    """The DNS-rebinding allowlist the transport should run with for `host`.

    Returns None for a loopback bind with no explicit extra names: the SDK
    already pins the allowlist to loopback when FastMCP is built without a
    host, and that is correct there. An explicit ``$DAVINCI_MCP_ALLOWED_HOSTS``
    entry is honored on loopback too. Tailscale Serve (and any other TLS
    proxy) terminates HTTPS and connects to 127.0.0.1, forwarding the public
    hostname as Host and, from a browser, an ``https`` Origin. Ignoring that
    list left every authenticated proxied request at 421.

    Everything else exists because of issue #241. `src/server.py` builds
    `FastMCP(...)` without a host, so the SDK (1.30.0,
    `mcp/server/fastmcp/server.py`) auto-enables DNS-rebinding protection with
    `allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"]`. `run_networked`
    then set `settings.host` to the LAN address but never touched
    `settings.transport_security`, and `streamable_http_app()` / `sse_app()`
    hand that loopback-only allowlist to the transport middleware. Every request
    to the LAN address therefore answered **421 Misdirected Request** — after the
    bearer check, so a wrong token still got 401 and the bind looked healthy.
    A non-loopback bind could never serve anyone.

    - Loopback bind with no usable extra names: return None (SDK loopback list).
    - Loopback bind with exact extra names: protection stays ON. The allowlist
      is loopback plus those names (any explicit port, and the portless form).
      Their origins include ``https`` and ``http``. Other hosts stay rejected.
    - Specific non-loopback host: protection stays ON; the allowlist is the bind
      host, the loopback names, and any extra names from
      `$DAVINCI_MCP_ALLOWED_HOSTS` (for clients that reach the box by a DNS name
      rather than the bound address). Extra names also get the portless form
      and ``https`` origins.
    - Wildcard bind (`0.0.0.0` / `::`): a client never sends the wildcard as its
      Host, so with no extra names there is nothing to allow. Protection is then
      turned OFF with a warning — the bearer token remains on every request, and
      a rebinding page does not hold it. Set `$DAVINCI_MCP_ALLOWED_HOSTS` to keep
      the protection on for a wildcard bind. Entries that are not exact names
      are ignored; if every supplied entry was ignored, protection stays ON
      pinned to loopback instead of being turned off.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    extras = []
    supplied = False
    for raw in extra_hosts:
        if isinstance(raw, str) and raw.strip():
            supplied = True
        name = _exact_host_name(raw)
        if name is None:
            if isinstance(raw, str) and raw.strip():
                logger.warning(
                    "Ignoring %s entry %r — only an exact hostname is accepted "
                    "(no '*', no URL, no wildcard bind).",
                    ALLOWED_HOSTS_ENV, raw.strip(),
                )
            continue
        if name not in extras:
            extras.append(name)

    if host in LOOPBACK_HOSTS and not extras:
        return None

    names = []
    if host not in WILDCARD_HOSTS and host not in LOOPBACK_HOSTS:
        names.append(host)
    names.extend(n for n in extras if n not in names)
    if not names:
        if supplied:
            # A wildcard bind whose allowlist was only junk must not drop the
            # Host check. Pin it to loopback; do not install the rejected text.
            logger.warning(
                "SECURITY: %s had no usable host name — DNS-rebinding "
                "protection stays ON, pinned to loopback.",
                ALLOWED_HOSTS_ENV,
            )
            return TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=[_host_pattern(n) for n in sorted(LOOPBACK_HOSTS)],
                allowed_origins=_loopback_http_origins(),
            )
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)

    loopback = [n for n in sorted(LOOPBACK_HOSTS) if n not in names]
    allowed_hosts = [_host_pattern(n) for n in names]
    allowed_hosts.extend(_host_pattern(n) for n in loopback)
    # Loopback origins stay the SDK's http port-patterns. https for 127.0.0.1
    # is not implied by listing a proxy name.
    allowed_origins = [f"http://{_host_pattern(n)}" for n in names if n not in extras]
    allowed_origins.extend(_loopback_http_origins())

    for name in extras:
        host_values, origin_values = _explicit_name_patterns(name)
        for value in host_values:
            if value not in allowed_hosts:
                allowed_hosts.append(value)
        for origin in origin_values:
            if origin not in allowed_origins:
                allowed_origins.append(origin)

    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


def resolve_token():
    """Return (token, was_generated). Honors $DAVINCI_MCP_TOKEN."""
    tok = os.environ.get("DAVINCI_MCP_TOKEN")
    if tok:
        return tok, False
    return secrets.token_urlsafe(32), True


def _auth_middleware_cls(token):
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    expected = f"Bearer {token}"

    class BearerAuth(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            provided = request.headers.get("authorization", "")
            if not secrets.compare_digest(provided, expected):
                return JSONResponse(
                    {"error": "unauthorized: Authorization: Bearer <token> required"},
                    status_code=401,
                )
            return await call_next(request)

    return BearerAuth


def write_transport_state(transport, host, port, token):
    try:
        write_private_json(TRANSPORT_STATE_PATH, {
            "transport": transport,
            "host": host,
            "port": port,
            "url": f"http://{host}:{port}",
            "token": token,
            "loopback": host in LOOPBACK_HOSTS,
            "pid": os.getpid(),
            "started_at": time.time(),
        })
    except OSError as exc:
        logger.warning("could not write transport state: %s", exc)


def clear_transport_state():
    try:
        os.remove(TRANSPORT_STATE_PATH)
    except OSError:
        pass


def read_transport_state():
    """Return the live transport state dict, or None if no networked instance.

    Treats a state file whose pid is no longer alive as stale (returns None).
    """
    try:
        with open(TRANSPORT_STATE_PATH, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return None
    pid = state.get("pid")
    if isinstance(pid, int):
        if os.name == "nt":
            # os.kill(pid, 0) is TerminateProcess on Windows, not a probe: the
            # state file normally names the running server itself.
            if windows_pid_alive(pid) is not True:
                return None
            return state
        try:
            os.kill(pid, 0)
        except (OSError, ProcessLookupError):
            return None
    return state


def _stderr_is_interactive() -> bool:
    """True only when stderr is a terminal a person is looking at."""
    try:
        return bool(sys.stderr and sys.stderr.isatty())
    except (AttributeError, ValueError):
        return False


def run_networked(mcp, transport):
    """Serve `mcp` over an authenticated HTTP transport ('sse'|'streamable-http')."""
    import uvicorn

    host = os.environ.get("DAVINCI_MCP_HOST") or mcp.settings.host or "127.0.0.1"
    port = int(os.environ.get("DAVINCI_MCP_PORT") or mcp.settings.port or 8000)
    mcp.settings.host = host
    mcp.settings.port = port
    token, generated = resolve_token()

    # Must happen BEFORE the app is built: sse_app()/streamable_http_app() read
    # settings.transport_security once, when they construct the middleware.
    extra = extra_allowed_hosts()
    security = transport_security_for(host, extra)
    if security is not None:
        mcp.settings.transport_security = security
        if security.enable_dns_rebinding_protection:
            logger.info("MCP transport Host allowlist: %s",
                        ", ".join(security.allowed_hosts))
        else:
            logger.warning(
                "SECURITY: MCP transport bound to %r with no %s set — a client "
                "never sends the wildcard as its Host header, so DNS-rebinding "
                "protection is OFF for this bind (the bearer token still gates "
                "every request). Set %s to the names clients will use to keep "
                "it on.", host, ALLOWED_HOSTS_ENV, ALLOWED_HOSTS_ENV,
            )

    app = mcp.sse_app() if transport == "sse" else mcp.streamable_http_app()
    app.add_middleware(_auth_middleware_cls(token))

    if host not in LOOPBACK_HOSTS:
        logger.warning(
            "SECURITY: MCP %s transport bound to NON-loopback host %r — Resolve "
            "control is exposed on the network. Ensure this is intended.",
            transport, host,
        )
    logger.info("MCP %s transport: http://%s:%s (bearer token required)",
                transport, host, port)
    if generated:
        # The token is the transport's only access control. Log WHERE it is,
        # never WHAT it is: this record propagates to the root logger, which
        # src/server.py points at logs/server.log — default file mode, appended
        # forever, no cleanup in our finally: — whereas the state file is 0600
        # and cleared at shutdown. The console gets the value only when a person
        # is watching it (a TTY); a redirected stderr is just another file.
        logger.info(
            "Generated a bearer token; it is recorded in %s (0600). "
            "Set $DAVINCI_MCP_TOKEN to pin your own.",
            TRANSPORT_STATE_PATH,
        )
        if _stderr_is_interactive():
            print(f"davinci-resolve-mcp: bearer token for this session: {token}",
                  file=sys.stderr, flush=True)

    write_transport_state(transport, host, port, token)
    try:
        uvicorn.run(app, host=host, port=port, log_level="warning")
    finally:
        clear_transport_state()
