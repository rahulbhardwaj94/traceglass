# Published advisories

> **These are published.** Both advisories are live on GitHub and in the GitHub
> Advisory Database. The files here are the source text they were created from,
> kept for the record.

Both defects were **already fixed and released** before disclosure. The
advisories exist because the fixes shipped inside ordinary release commits, so
without them nothing tells a user of an older version that they are exposed —
which is exactly what an advisory is for.

| Advisory                                                         | GHSA                                                                                            | Fixed in | Affects     | Severity       |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------- | ----------- | -------------- |
| [`serve` auth bypass](2026-07-25-serve-auth-bypass.md)           | [GHSA-69r3-wwg5-x52j](https://github.com/rahulbhardwaj94/traceglass/security/advisories/GHSA-69r3-wwg5-x52j) | 0.7.2    | 0.3.0–0.7.1 | High (7.5)     |
| [`redact` erasure residue](2026-07-24-redact-erasure-residue.md) | [GHSA-gg8v-j45q-wq22](https://github.com/rahulbhardwaj94/traceglass/security/advisories/GHSA-gg8v-j45q-wq22) | 0.7.1    | 0.6.0–0.7.0 | Moderate (5.5) |

Published 2026-07-26. GitHub computed both severities from the CVSS vectors in
each file, and they matched what the drafts proposed.

**No CVE was requested for either.** A CVE can still be requested from the
advisory page if one is wanted later — it is what makes an advisory reachable to
scanners that read CVE feeds rather than the GitHub database.

## Adding another

1. Write the text as a file here, following the shape of the two existing ones:
   summary, impact, a proof of concept that actually runs, the patch, and
   workarounds for people who cannot upgrade yet.
2. Create it with the API rather than by hand, so the structured fields cannot
   drift from the prose:

   ```sh
   gh api repos/rahulbhardwaj94/traceglass/security-advisories \
     --method POST --input advisory.json
   ```

   The payload needs `summary`, `description`, `cvss_vector_string`, `cwe_ids`,
   and `vulnerabilities[]` with the affected package, version range and patched
   version. It is created as a **draft** — publishing stays a deliberate click.
3. After publishing, record the GHSA id in this table, `CHANGELOG.md`, and
   `SECURITY.md`.
