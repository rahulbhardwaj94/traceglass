#!/usr/bin/env bash
#
# Regenerate the RFC 3161 test fixtures using OpenSSL's own TSA implementation.
#
# WHY: the parser in src/rfc3161.ts must cope with tokens produced by real TSA
# software, not just with what our own encoder emits. Round-tripping against our
# own writer would test nothing. OpenSSL's `ts` produces a genuine, fully-formed
# TimeStampResp: CMS SignedData, signed attributes, an embedded X.509 signer.
#
# The generated files are COMMITTED so the test suite runs offline with no
# OpenSSL dependency in CI. Re-run this only when the fixtures need to change:
#
#     ./packages/cli/test-fixtures/generate-tsa.sh
#
# Requires: openssl 3.x
set -euo pipefail
cd "$(dirname "$0")"

rm -rf .work && mkdir .work
trap 'rm -rf .work' EXIT

# The message the timestamp is taken over. The tests hash this file themselves,
# so the fixture stays honest: nothing hard-codes the digest.
printf 'traceglass rfc3161 fixture message\n' > message.bin

cat > .work/openssl.cnf <<'CONF'
[ ca ]
default_ca = tsa_ca

[ tsa_ca ]
new_certs_dir  = .work
database       = .work/index.txt
serial         = .work/serial
default_md     = sha256
policy         = policy_any
email_in_dn    = no
unique_subject = no

[ policy_any ]
commonName = supplied
countryName = optional
stateOrProvinceName = optional
organizationName = optional
organizationalUnitName = optional

[ req ]
distinguished_name = req_dn
prompt = no

[ req_dn ]
CN = traceglass test TSA
O  = traceglass fixtures
C  = GB

[ tsa_cert_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash

[ tsa_config ]
serial                 = .work/tsaserial
signer_cert            = tsa-cert.pem
certs                  = tsa-cert.pem
signer_key             = .work/tsa-key.pem
signer_digest          = sha256
default_policy         = 1.3.6.1.4.1.99999.1.1
other_policies         = 1.3.6.1.4.1.99999.1.2
digests                = sha256,sha384,sha512
accuracy               = secs:1,millisecs:500,microsecs:100
ordering               = yes
tsa_name               = yes
ess_cert_id_chain      = no
CONF

touch .work/index.txt
echo 01 > .work/serial
echo 01 > .work/tsaserial

# Self-signed TSA certificate carrying the critical timeStamping EKU. A real
# deployment would chain this to a CA; for fixtures a self-signed leaf exercises
# every code path we actually implement (we verify against the embedded cert and
# require an out-of-band pin for the strong claim — see rfc3161.ts).
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout .work/tsa-key.pem -out tsa-cert.pem \
  -days 36500 -sha256 -config .work/openssl.cnf \
  -extensions tsa_cert_ext >/dev/null 2>&1

# A genuine TimeStampReq (with nonce and certReq set) ...
openssl ts -query -data message.bin -sha256 -cert -out request.tsq >/dev/null 2>&1

# ... and the matching TimeStampResp.
OPENSSL_CONF=.work/openssl.cnf openssl ts -reply \
  -section tsa_config -queryfile request.tsq -out response.tsr >/dev/null 2>&1

# A second token, this one over a real traceglass ANCHOR STATEMENT for a canned
# run. This is what lets the test suite verify a complete anchor end to end
# against genuine TSA output. The statement bytes are written here independently
# of the TypeScript; the test asserts anchorStatement() reproduces them exactly,
# so any drift in the statement format fails loudly instead of silently
# invalidating every anchor ever issued.
node -e '
const fs = require("fs");
const j = JSON.stringify;
const runId = "anchored-run";
const runHash = "9f2c4a1e77b3d508e6a09c15be34fd72a8c1b05d3e9f641728ad5c0be7139f4a";
const keyId = "0123456789abcdef";
const signature = "c2lnbmF0dXJlLWZvci10aGUtY2FubmVkLWZpeHR1cmUtcnVu";
const statement = [
  "traceglass-anchor-v2",
  `runId: ${j(runId)}`,
  `runHash: ${j(runHash)}`,
  `keyId: ${j(keyId)}`,
  `signature: ${j(signature)}`,
].join("\n") + "\n";
fs.writeFileSync("anchor-statement.bin", statement);
fs.writeFileSync("anchor-run.json", j({ runId, runHash, keyId, signature }, null, 2) + "\n");
'

openssl ts -query -data anchor-statement.bin -sha256 -cert -out anchor-request.tsq >/dev/null 2>&1
OPENSSL_CONF=.work/openssl.cnf openssl ts -reply \
  -section tsa_config -queryfile anchor-request.tsq -out anchor-response.tsr >/dev/null 2>&1

# A rejection response, for the error path. OpenSSL emits a granted reply for
# anything well-formed, so build the PKIStatusInfo by hand: SEQUENCE {
#   SEQUENCE { INTEGER 2, SEQUENCE { UTF8String "..." }, BIT STRING failInfo } }
# status 2 = rejection, failInfo bit 0 = badAlg.
python3 - <<'PY'
import struct

def tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    length = len(content)
    out = b""
    while length:
        out = bytes([length & 0xFF]) + out
        length >>= 8
    return bytes([tag, 0x80 | len(out)]) + out + content

msg = "Message digest algorithm is not supported".encode()
status_string = tlv(0x30, tlv(0x0C, msg))          # PKIFreeText ::= SEQUENCE OF UTF8String
fail_info     = tlv(0x03, bytes([7, 0x80]))        # BIT STRING, 7 unused bits, bit 0 set
status_info   = tlv(0x30, tlv(0x02, bytes([2])) + status_string + fail_info)
open("response-rejected.tsr", "wb").write(tlv(0x30, status_info))
PY

echo "Regenerated fixtures:"
ls -l message.bin request.tsq response.tsr response-rejected.tsr tsa-cert.pem anchor-statement.bin anchor-response.tsr anchor-run.json
