"""Companion mTLS client for the demo service.

Mirror image of the server: it presents a client certificate and verifies the
server against SERVER_CA.  It calls /info, prints the response, and **exits
non-zero if anything goes wrong** -- which is what makes it usable as a
deployment gate.  Deploy it as:

  * a Manual/Scheduled Task (CLIENT_MODE=once, the default) - it runs, reports
    and exits; a non-zero exit shows up as a failed run; or
  * a Service (CLIENT_MODE=gate) - it must reach the server before it starts
    answering its own /healthz, so a broken mTLS setup becomes a failed
    deployment.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

LOG = logging.getLogger("mtls-client")

DEFAULT_CLIENT_CERT = "/etc/mtls/client.crt"
DEFAULT_CLIENT_KEY = "/etc/mtls/client.key"
DEFAULT_SERVER_CA = "/etc/mtls/server-ca.crt"

EXIT_OK = 0
EXIT_CONFIG = 1      # the client itself is misconfigured
EXIT_MTLS = 2        # the mTLS call failed (handshake, connection or HTTP)

READY = threading.Event()


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _flag(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        LOG.warning("%s=%r is not an integer; using %d", name, raw, default)
        return default


class ClientConfig:
    def __init__(self) -> None:
        self.host = _env("SERVER_HOST")
        self.port = _int("SERVER_PORT", 8443)
        self.path = _env("SERVER_PATH", "/info")
        self.client_cert = _env("CLIENT_CERT", DEFAULT_CLIENT_CERT)
        self.client_key = _env("CLIENT_KEY", DEFAULT_CLIENT_KEY)
        self.server_ca = _env("SERVER_CA", DEFAULT_SERVER_CA)
        # The service DNS name inside Choreo rarely matches the SAN on a
        # self-signed demo certificate, so the name checked during
        # verification can be overridden independently of the dial target.
        self.server_name = _env("SERVER_NAME") or self.host
        self.check_hostname = _flag("CHECK_HOSTNAME", True)
        self.mode = (_env("CLIENT_MODE", "once") or "once").lower()
        self.attempts = _int("RETRY_ATTEMPTS", 5)
        self.delay = _int("RETRY_DELAY_SECONDS", 3)
        self.timeout = _int("REQUEST_TIMEOUT_SECONDS", 10)
        self.health_port = _int("HEALTH_PORT", 8080)
        self.errors: list[str] = []

        if not self.host:
            self.errors.append("SERVER_HOST: required configuration is missing")
        for label, path in (
            ("CLIENT_CERT", self.client_cert),
            ("CLIENT_KEY", self.client_key),
            ("SERVER_CA", self.server_ca),
        ):
            if not path or not os.path.isfile(path):
                self.errors.append(f"{label}: no such file at mount path {path!r}")
        if self.mode not in ("once", "gate"):
            self.errors.append(f"CLIENT_MODE: {self.mode!r} must be 'once' or 'gate'")


def build_ssl_context(cfg: ClientConfig) -> ssl.SSLContext:
    """Present our identity, and verify the server's."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cfg.client_cert, keyfile=cfg.client_key)
    ctx.load_verify_locations(cafile=cfg.server_ca)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = cfg.check_hostname
    if not cfg.check_hostname:
        LOG.warning(
            "CHECK_HOSTNAME=false - the server certificate chain is still verified, "
            "but its SAN is not matched against %s", cfg.server_name,
        )
    return ctx


def call_info(cfg: ClientConfig, ctx: ssl.SSLContext) -> dict:
    """One mTLS request.  Raises on any failure; the caller decides about retries.

    The socket is wrapped by hand rather than left to `HTTPSConnection`, because
    the name we verify the server against (`SERVER_NAME`) often differs from the
    address we dial inside Choreo -- and because it lets us report the
    negotiated TLS parameters from the client's side too.
    """
    raw = socket.create_connection((cfg.host, cfg.port), timeout=cfg.timeout)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=cfg.server_name)
    except BaseException:
        raw.close()
        raise

    LOG.info("handshake ok: %s / %s", tls.version(), (tls.cipher() or [None])[0])
    conn = HTTPConnection(cfg.host, cfg.port, timeout=cfg.timeout)
    conn.sock = tls  # already connected and wrapped
    try:
        conn.request("GET", cfg.path, headers={"Accept": "application/json", "Host": cfg.server_name})
        response = conn.getresponse()
        body = response.read().decode("utf-8", errors="replace")
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} {response.reason}: {body[:400]}")
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"response was not JSON: {exc}: {body[:400]}") from exc
    finally:
        conn.close()


def _describe(payload: dict) -> None:
    """Log the bits a human actually wants to see in a task run's output."""
    mtls = payload.get("mtls", {})
    tls = payload.get("tls", {})
    LOG.info("mTLS call succeeded")
    LOG.info("  TLS           : %s / %s", tls.get("version"), tls.get("cipher"))
    LOG.info("  our cert seen : %s", mtls.get("subject"))
    LOG.info("  issued by     : %s", mtls.get("issuer"))
    LOG.info("  fingerprint   : %s", mtls.get("sha256_fingerprint"))
    LOG.info("  server region : %s", payload.get("config", {}).get("SERVICE_REGION"))


def attempt_with_retries(cfg: ClientConfig, ctx: ssl.SSLContext) -> dict:
    last: Exception | None = None
    for attempt in range(1, cfg.attempts + 1):
        try:
            LOG.info(
                "attempt %d/%d: GET https://%s:%d%s (as %s)",
                attempt, cfg.attempts, cfg.host, cfg.port, cfg.path, cfg.client_cert,
            )
            return call_info(cfg, ctx)
        except ssl.SSLCertVerificationError as exc:
            # Either the server is not who it claims, or -- far more commonly in
            # this demo -- *our* certificate was rejected by the server's CA
            # check and the connection died mid-handshake.
            LOG.error("certificate verification failed: %s", exc)
            last = exc
        except (ssl.SSLError, OSError, RuntimeError) as exc:
            LOG.error("call failed: %s", exc)
            last = exc
        if attempt < cfg.attempts:
            time.sleep(cfg.delay)
    raise RuntimeError(f"giving up after {cfg.attempts} attempt(s): {last}")


class HealthHandler(BaseHTTPRequestHandler):
    """The client's own small REST surface.

    `/healthz` is the gate: it answers 200 only once the mTLS call has been
    proven, so a broken setup fails the deployment rather than running degraded.

    `/diagnostics` re-runs that call on demand and returns what the server saw,
    which is what makes the whole loop testable from Choreo's Test Console.  The
    server itself cannot be tested from there -- it is a TCP passthrough
    endpoint and the console cannot present a client certificate -- but the
    client is an ordinary REST service, so it can act as the way in.
    """

    protocol_version = "HTTP/1.1"

    # Set once in main(); the handler needs them to re-run the call per request.
    config: "ClientConfig | None" = None
    ssl_context: ssl.SSLContext | None = None

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _healthz(self) -> None:
        ready = READY.is_set()
        self._send(
            200 if ready else 503,
            {
                "status": "ok" if ready else "initialising",
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            },
        )

    def _diagnostics(self) -> None:
        """Call the server over mTLS now and report both sides of the exchange."""
        started = datetime.now(timezone.utc)
        cfg, ctx = HealthHandler.config, HealthHandler.ssl_context
        if cfg is None or ctx is None:
            self._send(503, {"ok": False, "error": "client is still starting up"})
            return

        caller = {
            "route": "direct-mtls",
            "target": f"https://{cfg.host}:{cfg.port}{cfg.path}",
            "verified_as": cfg.server_name,
            "client_certificate": cfg.client_cert,
        }
        try:
            payload = call_info(cfg, ctx)
        except (ssl.SSLError, OSError, RuntimeError) as exc:
            # Worth 200-ing this: the Test Console shows the body either way, and
            # the interesting cases here are the failures.
            LOG.error("diagnostics call failed: %s", exc)
            self._send(
                502,
                {
                    "ok": False,
                    "caller": caller,
                    "error": {"type": type(exc).__name__, "message": str(exc)},
                    "timestamp": started.isoformat(timespec="seconds"),
                },
            )
            return

        self._send(
            200,
            {
                "ok": True,
                "caller": caller,
                "server": payload,
                "elapsed_ms": int(
                    (datetime.now(timezone.utc) - started).total_seconds() * 1000
                ),
                "timestamp": started.isoformat(timespec="seconds"),
            },
        )

    def do_GET(self):  # noqa: N802
        route = urlparse(self.path).path.rstrip("/") or "/"
        if route in ("/", "/healthz"):
            self._healthz()
        elif route == "/diagnostics":
            self._diagnostics()
        else:
            self._send(404, {"error": f"no such route: {route}", "routes": ["/healthz", "/diagnostics"]})

    def log_message(self, fmt, *args):
        LOG.debug("http %s", fmt % args)


def main() -> int:
    logging.basicConfig(
        level=getattr(logging, (_env("LOG_LEVEL", "info") or "info").upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stdout,
    )

    cfg = ClientConfig()
    if cfg.errors:
        LOG.error("client configuration is invalid:")
        for message in cfg.errors:
            LOG.error("  * %s", message)
        return EXIT_CONFIG

    try:
        ctx = build_ssl_context(cfg)
    except (ssl.SSLError, OSError) as exc:
        LOG.error("client TLS material failed to load: %s", exc)
        return EXIT_CONFIG

    try:
        payload = attempt_with_retries(cfg, ctx)
    except RuntimeError as exc:
        LOG.error("%s", exc)
        LOG.error(
            "the mTLS handshake or request did not succeed - treat this deployment as broken"
        )
        return EXIT_MTLS

    _describe(payload)
    print(json.dumps(payload, indent=2))

    if cfg.mode == "gate":
        READY.set()
        LOG.info(
            "mode=gate: staying up on :%d now that mTLS is proven "
            "(GET /healthz, GET /diagnostics)",
            cfg.health_port,
        )
        HealthHandler.config = cfg
        HealthHandler.ssl_context = ctx
        server = ThreadingHTTPServer(("0.0.0.0", cfg.health_port), HealthHandler)
        server.daemon_threads = True
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            LOG.info("shutting down")
        finally:
            server.server_close()

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
