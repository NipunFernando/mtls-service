#!/usr/bin/env bash
# Runs every acceptance criterion from the handover brief against a locally
# started copy of the service.  Exits non-zero if any check fails.
#
#   ./scripts/gen-certs.sh certs && ./scripts/acceptance-test.sh
#
# Nothing here talks to Choreo: it proves the *behaviour* the Choreo setup then
# has to preserve (TCP passthrough, config/secret injection, probes).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS="${CERTS:-$ROOT/certs}"
PORT="${PORT:-18443}"
HEALTH_PORT="${HEALTH_PORT:-18080}"
HOSTNAME_IN_CERT="mtls-demo-server"
TOKEN="supersecrettoken123"
WEBHOOK="webhookkey456"
LOG="$(mktemp -t mtls-acceptance.XXXXXX)"

PASS=0
FAIL=0
SERVER_PID=""

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

ok()   { green "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { red   "  FAIL  $1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; FAIL=$((FAIL + 1)); }

check() { # check <description> <condition-exit-code> [detail]
  if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1" "${3:-}"; fi
}

cleanup() {
  [ -n "$SERVER_PID" ] || return 0
  kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
  # Wait for the listener to actually go away; starting the next case against a
  # half-dead predecessor is how you end up testing the previous config.
  for _ in $(seq 1 40); do
    curl -s --max-time 1 "http://127.0.0.1:$HEALTH_PORT/healthz" >/dev/null 2>&1 || return 0
    sleep 0.25
  done
  return 0
}
trap cleanup EXIT

start_server() { # start_server [extra env assignments...]
  cleanup
  ( cd "$ROOT/server" && exec env \
      SERVICE_REGION="${SERVICE_REGION:-us-east-1}" \
      API_TOKEN="$TOKEN" \
      SERVER_CERT="$CERTS/server.crt" \
      SERVER_KEY="$CERTS/server.key" \
      CLIENT_CA="$CERTS/client-ca.crt" \
      MTLS_PORT="$PORT" HEALTH_PORT="$HEALTH_PORT" \
      PYTHONUNBUFFERED=1 \
      "$@" python3 main.py >>"$LOG" 2>&1 ) &
  SERVER_PID=$!
  for _ in $(seq 1 40); do
    # Check liveness first: a server that died on a port clash would otherwise
    # be masked by a predecessor still answering on the health port.
    kill -0 "$SERVER_PID" 2>/dev/null || { SERVER_PID=""; return 1; }
    curl -sf "http://127.0.0.1:$HEALTH_PORT/healthz" >/dev/null && return 0
    sleep 0.25
  done
  return 1
}

# run_server_expecting_exit <description> <env...> -- the server must refuse to start
expect_startup_failure() {
  local desc="$1"; shift
  local out rc
  out=$( cd "$ROOT/server" && env "$@" python3 main.py 2>&1 )
  rc=$?
  if [ "$rc" -ne 0 ]; then
    ok "$desc (exit $rc)"
  else
    bad "$desc" "server started when it should have refused"
  fi
}

call_info() { # call_info <cert> <key> -> prints body, returns curl exit code
  local cert="$1" key="$2"
  shift 2
  curl -s --max-time 10 \
    ${cert:+--cert "$cert"} ${key:+--key "$key"} \
    --cacert "$CERTS/server-ca.crt" \
    --resolve "$HOSTNAME_IN_CERT:$PORT:127.0.0.1" \
    "https://$HOSTNAME_IN_CERT:$PORT/info" "$@"
}

jqlike() { # jqlike <json> <python expression over `d`>
  python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(eval(sys.argv[1]))" "$2" <<<"$1"
}

[ -f "$CERTS/server.crt" ] || { red "No certificates in $CERTS - run ./scripts/gen-certs.sh first"; exit 1; }

echo "=== 1. Required config missing => service refuses to start ==="
expect_startup_failure "missing SERVICE_REGION exits non-zero" \
  API_TOKEN="$TOKEN" SERVER_CERT="$CERTS/server.crt" SERVER_KEY="$CERTS/server.key" CLIENT_CA="$CERTS/client-ca.crt"
expect_startup_failure "missing API_TOKEN exits non-zero" \
  SERVICE_REGION=us-east-1 SERVER_CERT="$CERTS/server.crt" SERVER_KEY="$CERTS/server.key" CLIENT_CA="$CERTS/client-ca.crt"
expect_startup_failure "missing certificate mount exits non-zero" \
  SERVICE_REGION=us-east-1 API_TOKEN="$TOKEN" SERVER_CERT="/nonexistent/server.crt" SERVER_KEY="$CERTS/server.key" CLIENT_CA="$CERTS/client-ca.crt"

echo
echo "=== 2. Optional config omitted => healthy, defaults applied ==="
start_server || { red "server did not become healthy"; cat "$LOG"; exit 1; }
ok "service healthy with LOG_LEVEL and WEBHOOK_KEY unset"

BODY="$(call_info "$CERTS/client.crt" "$CERTS/client.key")"
check "valid client certificate => HTTP 200 with JSON body" \
  "$([ -n "$BODY" ] && echo 0 || echo 1)"
check "LOG_LEVEL defaults to 'info'" \
  "$([ "$(jqlike "$BODY" 'd["config"]["LOG_LEVEL"]')" = "info" ] && echo 0 || echo 1)"
check "LOG_LEVEL is reported as a default, not a configured value" \
  "$([ "$(jqlike "$BODY" 'd["config"]["LOG_LEVEL_source"]')" = "default" ] && echo 0 || echo 1)"
check "optional secret WEBHOOK_KEY reported as unset" \
  "$([ "$(jqlike "$BODY" 'd["config"]["WEBHOOK_KEY"]')" = "unset" ] && echo 0 || echo 1)"

echo
echo "=== 3. /info reports config correctly, secrets masked ==="
check "required var SERVICE_REGION echoed" \
  "$([ "$(jqlike "$BODY" 'd["config"]["SERVICE_REGION"]')" = "us-east-1" ] && echo 0 || echo 1)"
check "required secret API_TOKEN masked" \
  "$(grep -q "$TOKEN" <<<"$BODY" && echo 1 || echo 0)" "raw token leaked into the response"
check "API_TOKEN reported as set" \
  "$(grep -q '"API_TOKEN": "set (masked' <<<"$BODY" && echo 0 || echo 1)"

echo
echo "=== 4. /info reports the real client certificate ==="
check "mtls.client_cert_present is true" \
  "$([ "$(jqlike "$BODY" 'd["mtls"]["client_cert_present"]')" = "True" ] && echo 0 || echo 1)"
check "client subject matches the issued certificate" \
  "$(grep -q 'CN=mtls-demo-client' <<<"$(jqlike "$BODY" 'd["mtls"]["subject"]')" && echo 0 || echo 1)"
check "client issuer is the client CA" \
  "$(grep -q 'CN=mtls-demo Client CA' <<<"$(jqlike "$BODY" 'd["mtls"]["issuer"]')" && echo 0 || echo 1)"
EXPECTED_FP="$(openssl x509 -in "$CERTS/client.crt" -noout -fingerprint -sha256 | sed 's/.*=//')"
check "sha256 fingerprint matches openssl" \
  "$([ "$(jqlike "$BODY" 'd["mtls"]["sha256_fingerprint"]')" = "$EXPECTED_FP" ] && echo 0 || echo 1)"
check "TLS version and cipher reported" \
  "$(grep -q '"version": "TLSv1' <<<"$BODY" && echo 0 || echo 1)"
check "server certificate subject reported" \
  "$(grep -q 'CN=mtls-demo-server' <<<"$(jqlike "$BODY" 'd["server_cert"]["subject"]')" && echo 0 || echo 1)"

echo
echo "=== 5. Handshake rejection ==="
call_info "" "" >/dev/null 2>&1
check "no client certificate => connection rejected, no 200" "$([ $? -ne 0 ] && echo 0 || echo 1)"
call_info "$CERTS/rogue-client.crt" "$CERTS/rogue-client.key" >/dev/null 2>&1
check "certificate from an untrusted CA => rejected" "$([ $? -ne 0 ] && echo 0 || echo 1)"
check "rejections are logged loudly by the server" \
  "$(grep -q 'TLS handshake rejected' "$LOG" && echo 0 || echo 1)"

echo
echo "=== 6. ?reveal=true is gated behind REVEAL_SECRETS ==="
REVEALED="$(call_info "$CERTS/client.crt" "$CERTS/client.key" --url "https://$HOSTNAME_IN_CERT:$PORT/info?reveal=true" 2>/dev/null)"
check "reveal ignored while REVEAL_SECRETS is off" \
  "$(grep -q "$TOKEN" <<<"$REVEALED" && echo 1 || echo 0)" "secret was revealed without opt-in"

echo
echo "=== 7. Optional config supplied => used instead of the default ==="
start_server LOG_LEVEL=debug WEBHOOK_KEY="$WEBHOOK" REVEAL_SECRETS=true || { red "server did not start"; exit 1; }
BODY2="$(call_info "$CERTS/client.crt" "$CERTS/client.key")"
check "LOG_LEVEL reflects the configured value" \
  "$([ "$(jqlike "$BODY2" 'd["config"]["LOG_LEVEL"]')" = "debug" ] && echo 0 || echo 1)"
check "LOG_LEVEL reported as configured" \
  "$([ "$(jqlike "$BODY2" 'd["config"]["LOG_LEVEL_source"]')" = "configured" ] && echo 0 || echo 1)"
check "optional secret reported as set and masked" \
  "$(grep -q '"WEBHOOK_KEY": "set (masked' <<<"$BODY2" && echo 0 || echo 1)"
REVEALED2="$(call_info "$CERTS/client.crt" "$CERTS/client.key" --url "https://$HOSTNAME_IN_CERT:$PORT/info?reveal=true")"
check "reveal works once REVEAL_SECRETS is on" \
  "$(grep -q "$TOKEN" <<<"$REVEALED2" && echo 0 || echo 1)"

echo
echo "=== 8. Secrets delivered as file mounts ==="
TOKEN_FILE="$(mktemp -t api-token.XXXXXX)"
printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
start_server API_TOKEN= API_TOKEN_FILE="$TOKEN_FILE" || { red "server did not start with a mounted secret"; exit 1; }
BODY3="$(call_info "$CERTS/client.crt" "$CERTS/client.key")"
check "API_TOKEN read from API_TOKEN_FILE mount" \
  "$(grep -q '"API_TOKEN": "set (masked' <<<"$BODY3" && echo 0 || echo 1)"
check "mounted secret is still masked" \
  "$(grep -q "$TOKEN" <<<"$BODY3" && echo 1 || echo 0)"
rm -f "$TOKEN_FILE"
expect_startup_failure "unreadable API_TOKEN_FILE exits non-zero" \
  SERVICE_REGION=us-east-1 API_TOKEN_FILE="/nonexistent/token" \
  SERVER_CERT="$CERTS/server.crt" SERVER_KEY="$CERTS/server.key" CLIENT_CA="$CERTS/client-ca.crt"
start_server LOG_LEVEL=debug WEBHOOK_KEY="$WEBHOOK" REVEAL_SECRETS=true || { red "server did not restart"; exit 1; }

echo
echo "=== 9. The client component ==="
run_client() { ( cd "$ROOT/client" && env \
    SERVER_HOST=127.0.0.1 SERVER_PORT="$PORT" SERVER_NAME="$HOSTNAME_IN_CERT" \
    SERVER_CA="$CERTS/server-ca.crt" RETRY_ATTEMPTS=1 "$@" python3 main.py >>"$LOG" 2>&1 ); }

run_client CLIENT_CERT="$CERTS/client.crt" CLIENT_KEY="$CERTS/client.key"
check "valid certificates => client exits 0" "$?"
run_client CLIENT_CERT="$CERTS/rogue-client.crt" CLIENT_KEY="$CERTS/rogue-client.key"
check "untrusted certificate => client exits non-zero" "$([ $? -ne 0 ] && echo 0 || echo 1)"
run_client CLIENT_CERT="/nonexistent/client.crt" CLIENT_KEY="/nonexistent/client.key"
check "missing certificate mounts => client exits non-zero" "$([ $? -ne 0 ] && echo 0 || echo 1)"

echo
echo "=== 10. Health endpoint ==="
check "plain-HTTP /healthz returns 200 when initialised" \
  "$(curl -sf "http://127.0.0.1:$HEALTH_PORT/healthz" >/dev/null && echo 0 || echo 1)"
check "/healthz over mTLS also works for a valid client" \
  "$(call_info "$CERTS/client.crt" "$CERTS/client.key" --url "https://$HOSTNAME_IN_CERT:$PORT/healthz" | grep -q '"status": "ok"' && echo 0 || echo 1)"

cleanup
echo
if [ "$FAIL" -eq 0 ]; then
  green "All $PASS checks passed."
  echo "Server log: $LOG"
  exit 0
fi
red "$FAIL of $((PASS + FAIL)) checks failed."
echo "Server log: $LOG"
exit 1
