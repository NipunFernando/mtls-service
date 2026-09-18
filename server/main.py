"""mTLS-enforcing demo service.

Terminates TLS itself -- Choreo must expose this port as a *TCP* endpoint so the
raw TLS connection reaches the container -- and requires a client certificate
signed by CLIENT_CA.  A connection with no client certificate, or one signed by
anything else, dies in the handshake.  That is the whole point: a broken mTLS
setup fails loudly instead of quietly behaving like plain TLS.

Two listeners:

  * MTLS_PORT   (default 8443) - the real service.  /info and /healthz.
  * HEALTH_PORT (default 8080) - plain HTTP, /healthz only.  Kubernetes-style
    HTTP probes cannot present a client certificate, so they get their own
    door.  This port is deliberately *not* declared as a Choreo endpoint.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import certinfo
import config

LOG = logging.getLogger("mtls-server")

HANDSHAKE_TIMEOUT = 10.0

# Flipped once the TLS listener is bound and serving.  /healthz answers 200
# only after that, so a probe can never see a half-initialised service.
READY = threading.Event()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# TLS plumbing
# ---------------------------------------------------------------------------

def build_ssl_context(cfg: config.Config) -> ssl.SSLContext:
    """Server-side context that *requires* and *verifies* a client certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cfg.server_cert, keyfile=cfg.server_key)
    ctx.verify_mode = ssl.CERT_REQUIRED               # <- mTLS enforcement
    ctx.load_verify_locations(cafile=cfg.client_ca)   # <- trust anchor for clients
    return ctx


class MTLSHTTPServer(ThreadingHTTPServer):
    """HTTP server whose accepted sockets are wrapped in a client-auth TLS context.

    Wrapping at `get_request()` time (rather than wrapping the listening socket)
    keeps failed handshakes out of the handler entirely and lets us log the
    rejection with the peer address, which is what makes a misconfigured client
    debuggable.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler_cls, ssl_context: ssl.SSLContext, cfg: config.Config):
        self.ssl_context = ssl_context
        self.cfg = cfg
        super().__init__(address, handler_cls)

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(HANDSHAKE_TIMEOUT)
        try:
            tls_sock = self.ssl_context.wrap_socket(sock, server_side=True)
        except (ssl.SSLError, ssl.SSLCertVerificationError) as exc:
            LOG.warning("TLS handshake rejected from %s: %s", addr[0], exc)
            sock.close()
            # socketserver treats OSError from get_request() as "nothing to do".
            raise OSError("handshake failed") from exc
        except (OSError, socket.timeout) as exc:
            LOG.warning("connection from %s dropped during handshake: %s", addr[0], exc)
            sock.close()
            raise OSError("handshake aborted") from exc
        tls_sock.settimeout(None)
        return tls_sock, addr

    def handle_error(self, request, client_address):
        LOG.warning("error handling request from %s", client_address[0], exc_info=True)


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------

class _JSONHandler(BaseHTTPRequestHandler):
    server_version = "mtls-demo/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # route access logs through logging
        LOG.info("%s - %s", self.client_address[0], fmt % args)

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2, sort_keys=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class InfoHandler(_JSONHandler):
    """Serves /info and /healthz over the mTLS listener."""

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler contract
        parsed = urlparse(self.path)
        if parsed.path == "/info":
            self._send_json(200, self._info(parse_qs(parsed.query)))
        elif parsed.path in ("/healthz", "/readyz"):
            self._send_json(
                200 if READY.is_set() else 503,
                {"status": "ok" if READY.is_set() else "initialising"},
            )
        else:
            self._send_json(404, {"error": "not found", "try": ["/info", "/healthz"]})

    def _info(self, query: dict) -> dict:
        cfg: config.Config = self.server.cfg
        conn = self.connection

        reveal = cfg.reveal_secrets and query.get("reveal", ["false"])[0].lower() == "true"
        if query.get("reveal") and not cfg.reveal_secrets:
            LOG.warning("?reveal=true ignored: REVEAL_SECRETS is not enabled")

        peer_cert = conn.getpeercert()
        peer_der = conn.getpeercert(binary_form=True)
        cipher = conn.cipher()

        return {
            "config": {
                config.REQUIRED_VAR: cfg.service_region,
                config.OPTIONAL_VAR: cfg.log_level,
                f"{config.OPTIONAL_VAR}_source": "default" if cfg.log_level_is_default else "configured",
                config.REQUIRED_SECRET: config.mask(cfg.api_token, reveal),
                config.OPTIONAL_SECRET: config.mask(cfg.webhook_key, reveal),
            },
            "secrets_revealed": reveal,
            "tls": {
                "version": conn.version(),
                "cipher": cipher[0] if cipher else None,
                "protocol_bits": cipher[2] if cipher else None,
            },
            "mtls": certinfo.peer_summary(peer_cert, peer_der),
            "server_cert": certinfo.decode_cert_file(cfg.server_cert),
            "client_ca": {"path": cfg.client_ca},
            "timestamp": _now(),
        }


class HealthHandler(_JSONHandler):
    """Plain-HTTP /healthz for Choreo liveness / readiness / startup probes."""

    def do_GET(self):  # noqa: N802
        if urlparse(self.path).path not in ("/healthz", "/readyz", "/livez", "/"):
            self._send_json(404, {"error": "not found", "try": ["/healthz"]})
            return
        ready = READY.is_set()
        self._send_json(
            200 if ready else 503,
            {"status": "ok" if ready else "initialising", "timestamp": _now()},
        )

    def log_message(self, fmt, *args):
        LOG.debug("health %s - %s", self.client_address[0], fmt % args)


class _HealthServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stdout,
    )


def fail(messages: list[str]) -> None:
    """Report a fatal startup problem and exit non-zero.

    Exiting here is deliberate: the container dies, the probe never passes, and
    Choreo marks the deployment failed -- which is exactly the signal we want
    when a required config value or certificate is missing.
    """
    LOG.error("startup validation failed - refusing to start:")
    for message in messages:
        LOG.error("  * %s", message)
    LOG.error("fix the configuration in Choreo (DevOps -> Configs & Secrets) and redeploy")
    sys.exit(1)


def main() -> None:
    # Log at the configured level as soon as we know it, but bootstrap at INFO
    # so validation errors are never swallowed.
    _configure_logging(os.environ.get(config.OPTIONAL_VAR, config.LOG_LEVEL_DEFAULT))

    cfg = config.load()
    if cfg.errors:
        fail(cfg.errors)
    _configure_logging(cfg.log_level)

    try:
        ctx = build_ssl_context(cfg)
    except (ssl.SSLError, OSError) as exc:
        fail([f"TLS material failed to load: {exc}"])
        return  # unreachable; keeps type checkers happy

    LOG.info(
        "config ok: %s=%s, %s=%s (%s), %s=%s, %s=%s",
        config.REQUIRED_VAR, cfg.service_region,
        config.OPTIONAL_VAR, cfg.log_level,
        "default" if cfg.log_level_is_default else "configured",
        config.REQUIRED_SECRET, config.mask(cfg.api_token),
        config.OPTIONAL_SECRET, config.mask(cfg.webhook_key),
    )
    LOG.info(
        "TLS material loaded: cert=%s key=%s client_ca=%s",
        cfg.server_cert, cfg.server_key, cfg.client_ca,
    )

    health = _HealthServer(("0.0.0.0", cfg.health_port), HealthHandler)
    threading.Thread(target=health.serve_forever, name="health", daemon=True).start()
    LOG.info("health listener on :%d (plain HTTP, probes only)", cfg.health_port)

    try:
        server = MTLSHTTPServer(("0.0.0.0", cfg.mtls_port), InfoHandler, ctx, cfg)
    except OSError as exc:
        fail([f"could not bind mTLS port {cfg.mtls_port}: {exc}"])
        return

    READY.set()
    LOG.info(
        "mTLS listener on :%d - client certificates are REQUIRED and verified against %s",
        cfg.mtls_port, cfg.client_ca,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("shutting down")
    finally:
        READY.clear()
        server.server_close()
        health.shutdown()


if __name__ == "__main__":
    main()
