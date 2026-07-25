# Advisory drafts

> **These are DRAFTS. Nothing here has been published.**
>
> No GHSA has been requested, no CVE has been reserved, and no advisory has been
> created on GitHub. These files are prepared text only. Publishing them is a
> deliberate decision for the maintainer to make.

Both defects described here are **already fixed and released**. The drafts exist
because the fixes shipped inside ordinary release commits, so there is currently
no artifact that tells a user of an older version that they are exposed — which
is exactly what an advisory is for.

| Draft                                                        | Fixed in | Affects     | Severity (proposed) |
| ------------------------------------------------------------ | -------- | ----------- | ------------------- |
| [`serve` auth bypass](2026-07-25-serve-auth-bypass.md)        | 0.7.2    | 0.3.0–0.7.1 | High (7.5)          |
| [`redact` erasure residue](2026-07-24-redact-erasure-residue.md) | 0.7.1    | 0.6.0–0.7.0 | Moderate (5.5)      |

Severities and CVSS vectors are proposed, not authoritative. Review them before
publishing; GitHub will also compute its own severity when an advisory is
created.

## If you decide to publish

1. Repository → Security → Advisories → New draft security advisory.
2. Paste the body from the corresponding file; set the affected package
   (`traceglass` on npm), the affected version range, and the patched version.
3. Request a CVE through GitHub if you want one.
4. Publish, then add the assigned GHSA ID back into `CHANGELOG.md` and
   `SECURITY.md`.
