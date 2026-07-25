# DRAFT — not published

**Do not treat this as a live advisory.** No GHSA requested, no CVE reserved.
See [`README.md`](README.md).

---

**Title:** `traceglass redact` reported success while the "erased" value stayed
recoverable from the database file

**Package:** `traceglass` / `@traceglass/core` (npm)
**Affected versions:** `>=0.6.0 <0.7.1`
**Patched version:** `0.7.1`
**Severity (proposed):** Moderate — CVSS 3.1 **5.5**
**Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Weaknesses:** CWE-212 (Improper Removal of Sensitive Information Before
Storage or Transfer), CWE-459 (Incomplete Cleanup)

## Summary

`traceglass redact` exists to make a specific promise: the value is destroyed,
irreversibly, while the hash chain and signature over the record remain valid.
In 0.6.0 through 0.7.0 the first half of that promise did not hold against the
file on disk.

After a `--yes` redaction that reported success, the value was gone from every
query — and still present, in plaintext, in a freed SQLite page:

```sh
strings traceglass.sqlite | grep 'chase account 4471'
# chase account 4471      <-- after a redaction that reported success
```

Two causes, both about pages rather than rows:

1. SQLite's `secure_delete` pragma defaults to **off**, so pages freed by the
   update kept their bytes rather than being zeroed.
2. The store has run in **WAL mode** since 0.3.0, and in WAL mode the superseded
   row survives in the write-ahead log until a checkpoint.

Retention pruning (`pruneOlderThan`, used by `serve --retain`) removed data
through the same path and leaked the same way.

## Impact

Data that an operator — and, more importantly, an auditor or a data subject —
was told had been erased remained readable to anyone who obtained the database
file or its WAL sidecar. That includes:

- filesystem backups and snapshots taken at any point after the redaction
- a disk image, a stolen laptop, or a copied volume
- the `traceglass.sqlite-wal` sidecar, which is a separate file and was easy to
  miss when copying "the database"

This directly undermines the compliance claim the feature was built to support:
a GDPR erasure request answered with traceglass `redact` was not actually
satisfied on disk. The severity is moderate rather than high because exploiting
it requires access to the database file itself; it is not remotely reachable.

Integrity was never affected. The hash chain, the run anchor, and the Ed25519
signature behaved correctly throughout — the bug is that removal was incomplete,
not that anything was forged.

## Proof of concept

Against a vulnerable version (0.6.0–0.7.0), with a run whose input contains an
SSN:

```sh
# Present before, as expected:
strings "$TRACEGLASS_HOME/traceglass.sqlite" | grep -c '123-45-6789'   # 1

traceglass redact pii-run --path input.ssn --reason erasure --yes
# reports success

# Still present after:
strings "$TRACEGLASS_HOME/traceglass.sqlite" | grep -c '123-45-6789'   # 1
```

Note that counting with `grep -c` on the binary counts matching *lines*, not
occurrences; use `strings f | grep -o pat | wc -l` for a true count. Check the
`-wal` sidecar separately.

## Patches

Upgrade to **0.7.1**.

The fix enables `secure_delete` on every connection, so freed pages are zeroed
rather than merely unlinked, and follows the two operations that remove data —
`replaceRedacted` and `pruneOlderThan` — with `wal_checkpoint(TRUNCATE)` and
`VACUUM` to reclaim the freed pages. Both are rare, explicit operations, so the
cost is acceptable for an erasure guarantee that survives someone running
`strings` on a stolen copy. `VACUUM` runs outside the prune transaction because
it cannot run inside one.

Two regression tests ship with the fix; both fail against the previous
`store.ts`.

Verified end to end with the real CLI: the phrase is recoverable from the file
before redaction and absent afterwards, in both the database and the WAL
sidecar, while the anchor stays byte-identical and the chain and signature still
verify.

## Remediation for existing stores

**Upgrading alone does not scrub data already leaked into freed pages by an
earlier redaction.** `secure_delete` governs pages freed from that point on.
After upgrading to 0.7.1 or later, force a rewrite of the existing file:

```sh
sqlite3 "$TRACEGLASS_HOME/traceglass.sqlite" \
  "PRAGMA secure_delete=ON; PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
```

Then confirm:

```sh
strings "$TRACEGLASS_HOME/traceglass.sqlite" | grep -o 'THE-REDACTED-VALUE' | wc -l
strings "$TRACEGLASS_HOME/traceglass.sqlite-wal" | grep -o 'THE-REDACTED-VALUE' | wc -l
```

Treat any **backup** taken while an affected version was in use as still
containing the unredacted data, and dispose of those backups according to
whatever policy sent you to `redact` in the first place. A `VACUUM` on the live
database cannot reach them.

## Workarounds

There is no configuration workaround in the affected versions. Before 0.7.1,
the only way to genuinely erase a value was to rewrite the database file
externally (`VACUUM` with `secure_delete` enabled) after every redaction.

## Credit

Found during internal review ahead of the 0.7.1 release.
