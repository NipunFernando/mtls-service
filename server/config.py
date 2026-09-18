"""Configuration contract for the mTLS demo service.

Every value the service needs is read here exactly once, at startup, and any
problem is reported as a list of human-readable errors.  `main.py` turns a
non-empty error list into a log line plus `sys.exit(1)`, which is what makes a
broken Choreo configuration surface as a failed deployment instead of a
silently degraded service.

Two delivery styles are supported for every secret:

  * `NAME`       - the secret is injected as an environment variable
  * `NAME_FILE`  - the secret is injected as a file mount, and the env var
                   holds the path to that file

The `_FILE` form wins when both are present, because file mounts are the safer
way to ship multi-line material.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# Kind of each of the four demo values, echoed back by /info.
REQUIRED_VAR = "SERVICE_REGION"
REQUIRED_SECRET = "API_TOKEN"
OPTIONAL_VAR = "LOG_LEVEL"
OPTIONAL_SECRET = "WEBHOOK_KEY"

LOG_LEVEL_DEFAULT = "info"
VALID_LOG_LEVELS = ("debug", "info", "warning", "error", "critical")

DEFAULT_MTLS_PORT = 8443
DEFAULT_HEALTH_PORT = 8080

DEFAULT_SERVER_CERT = "/etc/mtls/server.crt"
DEFAULT_SERVER_KEY = "/etc/mtls/server.key"
DEFAULT_CLIENT_CA = "/etc/mtls/client-ca.crt"


class ConfigError(Exception):
    """Raised when the configuration contract is not satisfied."""


def _env(name: str) -> str | None:
    """Read an env var, treating whitespace-only as unset."""
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _read_file(path: str, label: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as exc:
        raise ConfigError(f"{label}: cannot read file mount {path!r} ({exc.strerror})") from exc


def _secret(name: str) -> str | None:
    """Resolve a secret from either `<NAME>_FILE` (a mount) or `<NAME>` (env)."""
    path = _env(f"{name}_FILE")
    if path:
        return _read_file(path, name) or None
    return _env(name)


def _port(name: str, default: int, errors: list[str]) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        port = int(raw)
    except ValueError:
        errors.append(f"{name}: {raw!r} is not a valid port number")
        return default
    if not 1 <= port <= 65535:
        errors.append(f"{name}: {port} is outside the valid port range 1-65535")
        return default
    return port


def _flag(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    # --- the four demo values -------------------------------------------------
    service_region: str | None = None          # required configuration
    api_token: str | None = None               # required secret
    log_level: str = LOG_LEVEL_DEFAULT         # optional configuration
    webhook_key: str | None = None             # optional secret

    # --- TLS material (always file mounts; the key is always a secret) --------
    server_cert: str = DEFAULT_SERVER_CERT
    server_key: str = DEFAULT_SERVER_KEY
    client_ca: str = DEFAULT_CLIENT_CA

    # --- runtime knobs --------------------------------------------------------
    mtls_port: int = DEFAULT_MTLS_PORT
    health_port: int = DEFAULT_HEALTH_PORT
    reveal_secrets: bool = False

    errors: list[str] = field(default_factory=list)

    @property
    def log_level_is_default(self) -> bool:
        return _env(OPTIONAL_VAR) is None


def load() -> Config:
    """Read and validate the whole configuration contract.

    Never raises: every problem is accumulated in `Config.errors` so the caller
    can report all of them at once rather than one redeploy at a time.
    """
    errors: list[str] = []
    cfg = Config(errors=errors)

    # Required configuration -------------------------------------------------
    cfg.service_region = _env(REQUIRED_VAR)
    if cfg.service_region is None:
        errors.append(f"{REQUIRED_VAR}: required configuration is missing")

    # Required secret --------------------------------------------------------
    try:
        cfg.api_token = _secret(REQUIRED_SECRET)
    except ConfigError as exc:
        errors.append(str(exc))
    else:
        if cfg.api_token is None:
            errors.append(
                f"{REQUIRED_SECRET}: required secret is missing "
                f"(set {REQUIRED_SECRET} or {REQUIRED_SECRET}_FILE)"
            )

    # Optional configuration with a default ----------------------------------
    log_level = _env(OPTIONAL_VAR) or LOG_LEVEL_DEFAULT
    if log_level.lower() not in VALID_LOG_LEVELS:
        errors.append(
            f"{OPTIONAL_VAR}: {log_level!r} is not one of {', '.join(VALID_LOG_LEVELS)}"
        )
        log_level = LOG_LEVEL_DEFAULT
    cfg.log_level = log_level.lower()

    # Optional secret --------------------------------------------------------
    try:
        cfg.webhook_key = _secret(OPTIONAL_SECRET)
    except ConfigError as exc:
        # An unreadable *optional* mount is still a misconfiguration: the
        # operator asked for a file that is not there.
        errors.append(str(exc))

    # TLS material -----------------------------------------------------------
    cfg.server_cert = _env("SERVER_CERT") or DEFAULT_SERVER_CERT
    cfg.server_key = _env("SERVER_KEY") or DEFAULT_SERVER_KEY
    cfg.client_ca = _env("CLIENT_CA") or DEFAULT_CLIENT_CA
    for label, path in (
        ("SERVER_CERT", cfg.server_cert),
        ("SERVER_KEY", cfg.server_key),
        ("CLIENT_CA", cfg.client_ca),
    ):
        if not os.path.isfile(path):
            errors.append(f"{label}: no such file at mount path {path!r}")

    # Runtime knobs ----------------------------------------------------------
    cfg.mtls_port = _port("MTLS_PORT", DEFAULT_MTLS_PORT, errors)
    cfg.health_port = _port("HEALTH_PORT", DEFAULT_HEALTH_PORT, errors)
    if cfg.mtls_port == cfg.health_port:
        errors.append(
            f"MTLS_PORT and HEALTH_PORT are both {cfg.mtls_port}; they must differ"
        )
    cfg.reveal_secrets = _flag("REVEAL_SECRETS")

    return cfg


def mask(value: str | None, reveal: bool = False) -> str:
    """Render a secret for /info.

    Masked by default; `reveal` is only ever true when the operator explicitly
    opted in via REVEAL_SECRETS *and* asked for it per request.
    """
    if value is None:
        return "unset"
    if reveal:
        return value
    if len(value) <= 4:
        return f"set (masked, length {len(value)})"
    return f"set (masked, length {len(value)}, last4 ...{value[-4:]})"
