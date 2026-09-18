#!/usr/bin/env bash
# Generate a self-contained test certificate set for the mTLS demo.
#
#   ./scripts/gen-certs.sh [output-dir]
#
# Produces two independent CAs plus a third "rogue" CA used only to prove that
# the server rejects certificates it was not told to trust:
#
#   server-ca.crt / .key      signs the server certificate
#   server.crt / server.key   the service's own identity        (server secret)
#   client-ca.crt / .key      signs legitimate client certificates
#   client.crt / client.key   a valid client identity           (client secret)
#   rogue-ca.crt / .key       an untrusted CA
#   rogue-client.crt / .key   a well-formed cert from the wrong CA (negative test)
#
# The server is given: server.crt, server.key, client-ca.crt
# The client is given: client.crt, client.key, server-ca.crt
# Nothing is ever given rogue-ca.crt -- that is the point.

set -euo pipefail

OUT="${1:-certs}"
DAYS="${DAYS:-825}"
# Every name the server certificate should be valid for.  Add the Choreo
# service DNS name here once you know it, or set SERVER_SAN before running.
SERVER_CN="${SERVER_CN:-mtls-demo-server}"
SERVER_SAN="${SERVER_SAN:-DNS:localhost,DNS:mtls-demo-server,DNS:mtls-service,IP:127.0.0.1}"
CLIENT_CN="${CLIENT_CN:-mtls-demo-client}"
SUBJ_BASE="${SUBJ_BASE:-/C=LK/O=WSO2/OU=Choreo mTLS Demo}"

mkdir -p "$OUT"
cd "$OUT"

log() { printf '  %s\n' "$*"; }

# make_ca <name> <common-name>
make_ca() {
  local name="$1" cn="$2"
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "$DAYS" \
    -keyout "${name}.key" -out "${name}.crt" \
    -subj "${SUBJ_BASE}/CN=${cn}" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  log "CA        ${name}.crt  (CN=${cn})"
}

# make_leaf <name> <common-name> <ca-name> <server|client> [san]
make_leaf() {
  local name="$1" cn="$2" ca="$3" role="$4" san="${5:-}"
  local ext_file="${name}.ext"

  openssl req -newkey rsa:2048 -nodes -sha256 \
    -keyout "${name}.key" -out "${name}.csr" \
    -subj "${SUBJ_BASE}/CN=${cn}" 2>/dev/null

  {
    echo "basicConstraints=CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    if [ "$role" = "server" ]; then
      echo "extendedKeyUsage=serverAuth"
      echo "subjectAltName=${san}"
    else
      echo "extendedKeyUsage=clientAuth"
      [ -n "$san" ] && echo "subjectAltName=${san}"
    fi
  } > "$ext_file"

  openssl x509 -req -in "${name}.csr" -sha256 -days "$DAYS" \
    -CA "${ca}.crt" -CAkey "${ca}.key" -CAcreateserial \
    -extfile "$ext_file" -out "${name}.crt" 2>/dev/null

  rm -f "${name}.csr" "$ext_file"
  chmod 600 "${name}.key"
  log "${role}    ${name}.crt  (CN=${cn}, signed by ${ca})"
}

echo "Generating test certificates in ${OUT}/ (valid ${DAYS} days)"
make_ca server-ca "mtls-demo Server CA"
make_ca client-ca "mtls-demo Client CA"
make_ca rogue-ca  "mtls-demo Rogue CA (untrusted)"

make_leaf server       "$SERVER_CN"       server-ca server "$SERVER_SAN"
make_leaf client       "$CLIENT_CN"       client-ca client "DNS:${CLIENT_CN}"
make_leaf rogue-client "rogue-client"     rogue-ca  client "DNS:rogue-client"

rm -f ./*.srl
chmod 600 ./*.key

cat <<EOF

Done. Upload to Choreo as file mounts:

  server component            client component
  --------------------------  --------------------------
  server.crt    -> config     client.crt    -> config
  server.key    -> SECRET     client.key    -> SECRET
  client-ca.crt -> config     server-ca.crt -> config

Quick check:
  openssl verify -CAfile ${OUT}/client-ca.crt ${OUT}/client.crt
  openssl verify -CAfile ${OUT}/client-ca.crt ${OUT}/rogue-client.crt   # must FAIL
EOF
