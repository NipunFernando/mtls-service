# mTLS-Enforcing Service + Client (Choreo / WSO2 Developer Platform)

A Python service that **requires** TLS **and** mutual TLS, reads a defined set of
configurations and secrets, and reports back everything it sees — the config values it was
given and the details of the client certificate that got through the handshake. Plus a
companion client component that exercises the whole loop and **exits non-zero when mTLS
fails**, so a broken setup shows up as a failed deployment rather than a quiet success.

Everything is standard library only: `ssl` + `http.server`. No pip install, no framework.

```
┌──────────────────────┐        TLS 1.3 + client cert        ┌──────────────────────────┐
│  client component    │ ──────────────────────────────────► │  server component        │
│  (Task or Service)   │      Choreo TCP endpoint :8443      │  terminates TLS itself   │
│  client.crt/.key     │ ◄────────────────────────────────── │  server.crt/.key         │
│  trusts server-ca    │        200 + /info JSON             │  verifies vs client-ca   │
└──────────────────────┘                                     └──────────────────────────┘
                                                               :8080 plain HTTP /healthz
                                                               (probes only, not exposed)
```

---

## Decision #1: TLS terminates in the container, so the endpoint is TCP

Choreo terminates TLS for **HTTP/REST** endpoints at its gateway. A container behind a REST
endpoint receives plain HTTP and never sees a client certificate — app-level mTLS and
certificate reporting are impossible that way.

So the service port is declared as a **TCP endpoint** (`type: TCP` in
`.choreo/component.yaml`), which is TLS passthrough: the raw TLS connection reaches the
container and `server/main.py` performs the handshake itself. This was verified against the
[Expose a TCP Server via a Service](https://wso2.com/choreo/docs/develop-components/develop-services/expose-a-tcp-server-via-a-service/)
sample, which uses exactly this shape (`schemaVersion: 1.2`, `service.port`, `type: TCP`,
`networkVisibilities: [Project]`).

Consequence worth knowing up front: a TCP endpoint is consumed **inside the data plane**
(Project or Organization visibility). The companion client component is therefore the
intended caller. It is not a public HTTPS URL you can hit from your laptop — for that, use
the local workflow below.

### Consequence #2: probes need their own door

An HTTP GET probe cannot present a client certificate, so it could never pass against the
mTLS port. The service therefore opens a **second, plain-HTTP listener on `HEALTH_PORT`
(default 8080)** serving `/healthz`, which is *not* declared as a Choreo endpoint and is only
reachable by the platform's probes. `/healthz` answers `200` only once required config is
validated and the TLS listener is bound; before that it answers `503`.

If you would rather not run a second listener, a **TCP-connect probe on 8443** is the safe
fallback — it proves the socket is bound without needing a certificate. Both options are
described under [Health checks](#5-health-checks) below.

---

## Repository layout

```
server/
  main.py                  TLS/mTLS listener, /info and /healthz, startup validation
  config.py                the config + secret contract, and the fail-fast rules
  certinfo.py              turns ssl certificate structures into readable JSON
  Dockerfile               python:3.12-slim, non-root UID 10014 (Choreo requires 10000-20000)
  .choreo/component.yaml   TCP endpoint + configuration form
client/
  main.py                  mirror-image TLS context, calls /info, exits non-zero on failure
  Dockerfile               non-root UID 10015
  .choreo/component.yaml   config form (+ optional health endpoint for gate mode)
scripts/
  gen-certs.sh             generates the full test certificate set, including a rogue CA
  acceptance-test.sh       runs every acceptance criterion locally (33 checks)
docker-compose.yml         both components wired together the way Choreo wires them
```

---

## Quick start (local)

```bash
# 1. Generate the test certificate set (two CAs + a rogue CA for negative tests)
./scripts/gen-certs.sh certs

# 2. Run everything end to end in containers
docker compose up --build        # client exits 0 after printing /info

# 3. Or run the full acceptance suite against a locally started server
./scripts/acceptance-test.sh     # 33 checks, exits non-zero if any fail
```

Running the server directly:

```bash
cd server
SERVICE_REGION=us-east-1 \
API_TOKEN=supersecrettoken123 \
SERVER_CERT=../certs/server.crt \
SERVER_KEY=../certs/server.key \
CLIENT_CA=../certs/client-ca.crt \
MTLS_PORT=8443 HEALTH_PORT=8080 \
python3 main.py
```

### Calling it with `curl`

The demo server certificate carries `DNS:mtls-demo-server` in its SAN, so `--resolve` is used
to keep hostname verification honest instead of disabling it.

```bash
# Valid client certificate -> 200 + /info JSON
curl --cert certs/client.crt --key certs/client.key --cacert certs/server-ca.crt \
     --resolve mtls-demo-server:8443:127.0.0.1 \
     https://mtls-demo-server:8443/info

# No client certificate -> rejected at the handshake (curl exit 56, no HTTP status)
curl --cacert certs/server-ca.crt \
     --resolve mtls-demo-server:8443:127.0.0.1 \
     https://mtls-demo-server:8443/info

# Certificate from the wrong CA -> rejected (curl exits non-zero, typically 56, no HTTP status)
curl --cert certs/rogue-client.crt --key certs/rogue-client.key --cacert certs/server-ca.crt \
     --resolve mtls-demo-server:8443:127.0.0.1 \
     https://mtls-demo-server:8443/info

# Reveal secrets (only works when REVEAL_SECRETS=true on the server)
curl --cert certs/client.crt --key certs/client.key --cacert certs/server-ca.crt \
     --resolve mtls-demo-server:8443:127.0.0.1 \
     'https://mtls-demo-server:8443/info?reveal=true'
```

### Inspecting the handshake with `openssl s_client`

Piping a request in is the version that actually proves something, because under TLS 1.3 the
rejection only surfaces once data flows:

```bash
# Valid client certificate -> HTTP/1.1 200 OK
printf 'GET /info HTTP/1.1\r\nHost: mtls-demo-server\r\nConnection: close\r\n\r\n' | \
  openssl s_client -quiet -connect 127.0.0.1:8443 -servername mtls-demo-server \
          -cert certs/client.crt -key certs/client.key -CAfile certs/server-ca.crt

# No client certificate -> "SSL alert number 116" (certificate_required); no HTTP response.
# The server logs: TLS handshake rejected ... PEER_DID_NOT_RETURN_A_CERTIFICATE
printf 'GET /info HTTP/1.1\r\nHost: mtls-demo-server\r\nConnection: close\r\n\r\n' | \
  openssl s_client -quiet -connect 127.0.0.1:8443 -servername mtls-demo-server \
          -CAfile certs/server-ca.crt

# Wrong CA -> "SSL alert number 48" (unknown_ca).
# The server logs: TLS handshake rejected ... CERTIFICATE_VERIFY_FAILED
printf 'GET /info HTTP/1.1\r\nHost: mtls-demo-server\r\nConnection: close\r\n\r\n' | \
  openssl s_client -quiet -connect 127.0.0.1:8443 -servername mtls-demo-server \
          -cert certs/rogue-client.crt -key certs/rogue-client.key -CAfile certs/server-ca.crt

# Just the handshake, to read the server certificate chain:
openssl s_client -connect 127.0.0.1:8443 -servername mtls-demo-server \
        -cert certs/client.crt -key certs/client.key -CAfile certs/server-ca.crt </dev/null \
  | grep "Verify return code"     # -> 0 (ok)
```

Note that `s_client </dev/null` **without** a client certificate still prints
`Verify return code: 0 (ok)` — that line is about the *server's* certificate, which verified
fine. It is not evidence that mTLS passed. Also, the service does not advertise an
"Acceptable client certificate CA names" list: Python's `SSLContext` does not send one, so
clients must simply present the right certificate.

> **TLS 1.3 note.** Under TLS 1.3 the client finishes its side of the handshake before the
> server has verified the client certificate, so a rejected client often sees
> `handshake ok` immediately followed by `tlsv1 alert unknown ca` on the first read — rather
> than a failure inside `wrap_socket()`. The connection still never carries a request, and
> the server logs `TLS handshake rejected`. Both the client component and the acceptance
> suite treat this correctly as a failure.

### Generating the certificates

`scripts/gen-certs.sh` builds three independent CAs:

| File | Goes to | Purpose |
|---|---|---|
| `server-ca.crt` / `.key` | — | signs the server certificate |
| `server.crt` / `server.key` | **server** | the service's own identity (key is a secret) |
| `client-ca.crt` | **server** | trust anchor the server verifies client certs against |
| `client.crt` / `client.key` | **client** | a valid client identity (key is a secret) |
| `server-ca.crt` | **client** | trust anchor the client verifies the server against |
| `rogue-ca.crt`, `rogue-client.crt` / `.key` | nobody | a well-formed certificate from an untrusted CA, used to prove rejection |

Override the names before generating, e.g. to add the Choreo service DNS name to the SAN:

```bash
SERVER_SAN="DNS:localhost,DNS:mtls-demo-server,DNS:<choreo-service-dns-name>" \
  ./scripts/gen-certs.sh certs
```

`certs/` is git-ignored. Never commit private keys, not even demo ones.

---

## Configuration contract

The four demo values — one of each kind — plus the certificate mounts.

| Name | Kind | Required | Delivery | Behaviour when absent |
|---|---|---|---|---|
| `SERVICE_REGION` | configuration | **yes** | env | logs the reason and **exits 1** |
| `API_TOKEN` | **secret** | **yes** | env, or `API_TOKEN_FILE` mount | logs the reason and **exits 1** |
| `LOG_LEVEL` | configuration | no | env | defaults to `info` |
| `WEBHOOK_KEY` | **secret** | no | env, or `WEBHOOK_KEY_FILE` mount | treated as unset, reported as `unset` |
| `SERVER_CERT` | path to a mounted **config** | yes | env → file mount | **exits 1** if missing or unloadable |
| `SERVER_KEY` | path to a mounted **secret** | yes | env → file mount | **exits 1** if missing or unloadable |
| `CLIENT_CA` | path to a mounted **config** | yes | env → file mount | **exits 1** if missing or unloadable |
| `MTLS_PORT` | configuration | no | env | defaults to `8443` |
| `HEALTH_PORT` | configuration | no | env | defaults to `8080` |
| `REVEAL_SECRETS` | configuration | no | env | defaults to `false` (secrets stay masked) |

Every secret accepts both delivery styles: `API_TOKEN` as an environment variable, or
`API_TOKEN_FILE=/path/to/mounted/file`. The `_FILE` form wins if both are set.

All validation happens **once, at startup**, and every problem is reported together:

```
ERROR    mtls-server: startup validation failed - refusing to start:
ERROR    mtls-server:   * API_TOKEN: required secret is missing (set API_TOKEN or API_TOKEN_FILE)
ERROR    mtls-server:   * SERVER_CERT: no such file at mount path '/etc/mtls/server.crt'
ERROR    mtls-server: fix the configuration in Choreo (DevOps -> Configs & Secrets) and redeploy
```

Then `sys.exit(1)`. The container dies, the probe never passes, and Choreo marks the
deployment failed. That is the intended behaviour, not a rough edge.

### Client configuration

| Name | Required | Default | Notes |
|---|---|---|---|
| `SERVER_HOST` | **yes** | — | Choreo service DNS name of the server component |
| `SERVER_PORT` | no | `8443` | |
| `SERVER_NAME` | no | `SERVER_HOST` | name checked against the server certificate SAN (SNI) |
| `CLIENT_CERT` | no | `/etc/mtls/client.crt` | mount path |
| `CLIENT_KEY` | no | `/etc/mtls/client.key` | mount path, **secret** |
| `SERVER_CA` | no | `/etc/mtls/server-ca.crt` | mount path |
| `CLIENT_MODE` | no | `once` | `once` = run and exit; `gate` = stay up serving `/healthz` |
| `CHECK_HOSTNAME` | no | `true` | chain verification always stays on |
| `RETRY_ATTEMPTS` / `RETRY_DELAY_SECONDS` | no | `5` / `3` | |

Exit codes: `0` success, `1` the client itself is misconfigured, `2` the mTLS call failed.

---

## `/info` response

```jsonc
{
  "config": {
    "SERVICE_REGION": "us-east-1",
    "LOG_LEVEL": "info",
    "LOG_LEVEL_source": "default",              // "default" or "configured"
    "API_TOKEN": "set (masked, length 19, last4 ...n123)",
    "WEBHOOK_KEY": "unset"
  },
  "secrets_revealed": false,
  "tls": { "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "protocol_bits": 256 },
  "mtls": {
    "client_cert_present": true,
    "subject": "C=LK, O=WSO2, OU=Choreo mTLS Demo, CN=mtls-demo-client",
    "issuer":  "C=LK, O=WSO2, OU=Choreo mTLS Demo, CN=mtls-demo Client CA",
    "serial": "EAAE708B3740672C",
    "version": 3,
    "not_before": "Sep 18 10:26:01 2026 GMT",
    "not_after":  "Dec 21 10:26:01 2028 GMT",
    "subject_alt_names": ["DNS:mtls-demo-client"],
    "sha256_fingerprint": "69:B7:73:A0:...:61:63"
  },
  "server_cert": { "subject": "...", "issuer": "...", "sha256_fingerprint": "...", "...": "..." },
  "client_ca": { "path": "/etc/mtls/client-ca.crt" },
  "timestamp": "2026-09-18T10:26:11+00:00"
}
```

Secrets are **masked by default** — length and last four characters only. `?reveal=true`
returns raw values but only when the server was started with `REVEAL_SECRETS=true`; otherwise
the parameter is ignored and a warning is logged. Keep it off outside a test harness.

The fingerprint matches `openssl x509 -in certs/client.crt -noout -fingerprint -sha256`; the
acceptance suite asserts exactly that.

---

## Deploying on Choreo

### 1. Server component

Create a **Service** component from this repo with build context `server/` (Dockerfile
`server/Dockerfile`). `.choreo/component.yaml` declares the TCP endpoint:

```yaml
schemaVersion: 1.2
endpoints:
  - name: mtls-info
    displayName: mTLS Info Service
    service:
      port: 8443
    type: TCP
    networkVisibilities:
      - Project      # or Organization if the client lives in another project
```

### 2. Configurations and secrets (DevOps → Configs & Secrets)

Environment variables:

| Variable | Type |
|---|---|
| `SERVICE_REGION` | configuration |
| `LOG_LEVEL` | configuration (omit to exercise the default) |
| `API_TOKEN` | **secret** |
| `WEBHOOK_KEY` | **secret** (omit to exercise the optional path) |
| `SERVER_CERT`, `SERVER_KEY`, `CLIENT_CA` | configurations holding the mount paths below |

File mounts (paste the PEM contents; mount path is absolute and includes the filename):

| Content | Mount path | Type |
|---|---|---|
| `certs/server.crt` | `/etc/mtls/server.crt` | configuration |
| `certs/server.key` | `/etc/mtls/server.key` | **secret** |
| `certs/client-ca.crt` | `/etc/mtls/client-ca.crt` | configuration |

> The `configurations` block in `component.yaml` renders the env-var form in the console, but
> its *file* support only covers structured `yaml`/`json`/`toml` files — so PEM material is
> added as file mounts under DevOps → Configs & Secrets rather than declared in
> `component.yaml`. The env vars in the component descriptor then point at those paths.

### 3. Client component

Create a second component from build context `client/`. Deploy it either way:

* **Manual or Scheduled Task** (`CLIENT_MODE=once`) — it calls `/info`, prints the response
  and exits. A failed handshake exits non-zero, so the run is marked failed.
* **Service** (`CLIENT_MODE=gate`) — it must complete the mTLS call before it starts
  answering its own `/healthz`, which turns a broken mTLS setup into a **failed deployment**.
  The descriptor declares a REST health endpoint on port 8080 for this mode; comment that
  `endpoints:` block out when deploying as a task, which needs no endpoint.

Its secrets, mirrored: `client.crt` + `client-ca`-signed `client.key` (**secret**) and
`server-ca.crt`. Set `SERVER_HOST` to the server component's service DNS name and
`SERVER_NAME` to a name present in the server certificate's SAN (or regenerate the server
certificate with the Choreo DNS name included — the cleaner option).

### 4. Health checks

Server component, **startup and/or readiness probe** — pick one:

* **HTTP GET** `/healthz` on port **8080** (the plain-HTTP health listener). Works directly
  with Choreo's HTTP probe form.
* **TCP connect** on port **8443**. The safe fallback if you would rather not expose a second
  port at all; it proves the TLS listener is bound.

Either way a missing required config kills the process before anything binds, so the probe
never passes and the deployment goes red. Choreo's health-check docs describe liveness and
readiness probes explicitly; if the startup-probe form is not available in your data plane,
a readiness probe plus the crash-on-bad-config behaviour gives the same outcome.

---

## Acceptance criteria

All verified by `./scripts/acceptance-test.sh` (33 checks, currently all passing) and, for
the container path, by `docker compose up`.

| Criterion | Where it is proved |
|---|---|
| Required var/secret missing → exits on startup, deployment fails | §1 of the suite; `expect_startup_failure` for `SERVICE_REGION`, `API_TOKEN`, cert mounts, and an unreadable `API_TOKEN_FILE` |
| No client certificate → rejected at the handshake | §5 — `curl` fails with no HTTP status; server logs `PEER_DID_NOT_RETURN_A_CERTIFICATE` |
| Certificate not signed by `CLIENT_CA` → rejected | §5 — server logs `CERTIFICATE_VERIFY_FAILED` |
| Valid client certificate → 200 and correct `/info` | §2, §4 |
| `/info` reports `client_cert_present` + subject/issuer/fingerprint | §4, including a fingerprint comparison against `openssl` |
| All four config values reported correctly, secrets masked | §3, §7 — asserts the raw token never appears in the body |
| Optional var/secret omitted → healthy, defaults applied | §2 |
| Client succeeds with valid certs, exits non-zero otherwise | §9 — exit `0`, `2` (untrusted CA), `1` (missing mounts) |
| README documents `curl`/`openssl s_client` and cert generation | this file |

---

## Notes and trade-offs

* **Why `http.server` + `ssl`.** The client certificate is available directly as
  `self.connection.getpeercert()`. Pulling the same thing out of FastAPI/uvicorn means
  reaching through the ASGI transport, for no gain here.
* **Threading.** `ThreadingHTTPServer` with the TLS wrap done in `get_request()`, so failed
  handshakes are logged with the peer address and never reach a handler.
* **Server certificate parsing** uses `ssl._ssl._test_decode_cert`, the only stdlib route to
  parse a certificate that is not attached to a live socket. It is a private API; if a future
  Python drops it, `/info` degrades to reporting the server certificate's fingerprint and
  path instead of failing the request.
* **Not built:** the API-proxy variant, where Choreo's gateway is the mTLS client and you
  configure backend mTLS on the proxy instead of writing client code. Different scenario —
  see [Secure Communication Between the Gateway and Your Backend with mTLS](https://wso2.com/choreo/docs/authentication-and-authorization/secure-communication-between-the-choreo-gateway-and-your-backend-with-mutual-tls/).
