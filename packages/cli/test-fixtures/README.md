# Anchoring test fixtures

Committed binary artefacts so the anchoring test suite runs **fully offline**.
Nothing here is generated at test time and no test reaches the network.

Two kinds of fixture, with different jobs.

## Locally generated (`generate-tsa.sh`)

Produced by OpenSSL's own TSA implementation. Regenerate with:

```sh
./packages/cli/test-fixtures/generate-tsa.sh   # requires openssl 3.x
```

| File | What it is |
|---|---|
| `message.bin` | Arbitrary bytes the basic fixture token covers. Tests hash it themselves — the digest is never hard-coded. |
| `request.tsq` | A genuine `TimeStampReq` from `openssl ts -query`, used to check our encoder against real output. |
| `response.tsr` | The matching granted `TimeStampResp`. Also serves as the "valid token over the **wrong** document" attacker fixture. |
| `response-rejected.tsr` | A hand-built `PKIStatusInfo` rejection (status 2, `badAlg`) — OpenSSL will not emit one, and the error path needs covering. |
| `tsa-cert.pem` | The self-signed test TSA leaf, with the critical `timeStamping` EKU. |
| `other-ca.pem` | An unrelated certificate, for the "pinned to a different TSA" case. |
| `anchor-statement.bin` | The exact anchor-statement bytes for a canned run, written by the generator **independently of the TypeScript**. `anchors.attack.test.ts` asserts `anchorStatement()` reproduces it, so any drift in the statement format fails loudly instead of silently invalidating every anchor ever issued. |
| `anchor-run.json` | The canned run's `runId`/`runHash`/`keyId`/`signature`, so tests can rebuild the statement. |
| `anchor-response.tsr` | A token over `anchor-statement.bin` — a complete anchor, verifiable end to end. |

## Captured from production services

These make the suite an **interoperability** test rather than a self-consistency
test. Our own encoder cannot produce these shapes, so they are the only thing
that would catch a subtly wrong Merkle computation or SET canonicalization.
Consumed by `src/interop.test.ts`.

| File | Source | Why it matters |
|---|---|---|
| `live-digicert-response.tsr` | `http://timestamp.digicert.com` | Real commercial TSA token over `anchor-statement.bin`. 3-certificate chain, bare `rsaEncryption` sigAlg, DigiCert policy OID. |
| `live-sectigo-response.tsr` | `http://timestamp.sectigo.com` | Second independent authority, different policy OID and cert layout. |
| `live-*-nonce.txt` | — | The nonce sent with each request, so the echo can be asserted. |
| `rekor-entry.json` | `https://rekor.sigstore.dev` | A real public-log entry with a 31-node inclusion path in a tree of ~2.1 billion entries. |
| `rekor-public-key.pem` | `https://rekor.sigstore.dev/api/v1/log/publicKey` | The log's real ECDSA P-256 key, used to verify the real Signed Entry Timestamp. |

### Refreshing the captured fixtures

These require network access. Timestamp tokens do not expire for verification
purposes, so there is normally no reason to refresh them.

```sh
# RFC 3161 — sends only a SHA-256 digest of anchor-statement.bin.
node -e '
const {createHash}=require("node:crypto"), {readFileSync,writeFileSync}=require("node:fs");
import("../dist/rfc3161.js").then(async (m) => {
  const st = readFileSync("anchor-statement.bin");
  const d  = createHash("sha256").update(st).digest();
  for (const [n,u] of [["digicert","http://timestamp.digicert.com"],
                       ["sectigo","http://timestamp.sectigo.com"]]) {
    const req = m.buildTimeStampRequest(d);
    const {raw} = await m.requestTimestamp(u, req, {timeoutMs:15000});
    writeFileSync(`live-${n}-response.tsr`, raw);
    writeFileSync(`live-${n}-nonce.txt`, req.nonce.toString("hex")+"\n");
  }
});'

# Rekor — READ ONLY. Do not "refresh" by submitting an entry: writes to the
# public log are permanent and cannot be retracted.
curl -s https://rekor.sigstore.dev/api/v1/log/publicKey -o rekor-public-key.pem
IDX=$(( $(curl -s https://rekor.sigstore.dev/api/v1/log | sed 's/.*"treeSize":\([0-9]*\).*/\1/') - 5000 ))
curl -s "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=$IDX" | python3 -m json.tool > rekor-entry.json
```

The Rekor fixture is public log data — it contains no traceglass run content
and belongs to whoever published it, not to us.
