# Security Policy

traceglass produces tamper-evident records that people rely on as evidence. A
defect that lets a record be forged, an "erased" value be recovered, or a stored
run be read without authorization defeats the entire purpose of the tool. We
treat those as the most serious class of bug in this project, and we would much
rather hear about one early and awkwardly than late and politely.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Preferred: use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability). It creates a private thread with the
maintainers and needs no coordination over email.

Alternative: email `rhlbhrdwj3@gmail.com`. If you would rather encrypt the
report, say so in a first message with no details and we will exchange keys.

### What to include

The more of this you can provide, the faster a fix lands:

- affected version(s) of `traceglass`, `@traceglass/core`, or `@traceglass/sdk`
- the deployment shape — local CLI, `serve` on loopback, `serve --host 0.0.0.0`,
  or the Docker image (this materially changes severity)
- a minimal reproduction: commands, a request, or a short script
- what an attacker gains, and what access they need to start
- any suggested fix, if you have one

### What is in scope

- forging, altering, or replaying a record so that `verify` still passes
- recovering data that `redact` or retention pruning reported as destroyed
- reading or ingesting runs without a valid token where a token is required
- signing-key handling, or anything that lets an unsigned record appear signed
- path traversal or arbitrary file read/write via the collector or the dashboard
- dependency vulnerabilities that reach a **published** tarball

### What is out of scope

- findings in the dev-only toolchain (vite, esbuild, vitest). `@traceglass/web`
  is private and vite is a devDependency, so none of it ships. Only
  `npm audit --omit=dev` gates a release.
- running `serve` bound to a non-loopback interface without a token — the CLI
  refuses this by design; if you find a way around the refusal, that *is* in
  scope
- an attacker who already has write access to the machine holding the store and
  the private signing key. The threat model assumes the key is protected; the
  hash chain alone was never sufficient against that attacker, which is why
  0.3.0 added signing.
- volumetric denial of service against your own collector

## Supported versions

traceglass is pre-1.0 and ships from a single line. Security fixes land on the
latest minor only, and the practical advice is always to move to the newest
patch release.

| Version | Supported                              |
| ------- | -------------------------------------- |
| 0.7.x   | ✅ Yes                                 |
| 0.6.x   | ❌ No — upgrade (see advisories below) |
| 0.3–0.5 | ❌ No — upgrade (see advisories below) |
| < 0.3   | ❌ No                                  |

Every release before 0.7.2 carries at least one known, fixed security defect.
There is no supported configuration of an older release; upgrade.

## Response targets

These are targets for a small project, not a contractual SLA. They are counted
from when a report is received.

| Stage                                    | Target                           |
| ---------------------------------------- | -------------------------------- |
| Acknowledge receipt                      | 3 business days                  |
| Initial assessment (severity, in-scope?) | 7 calendar days                  |
| Fix or documented mitigation — high/crit | 14 calendar days                 |
| Fix or documented mitigation — mod/low   | 30 calendar days                 |
| Public advisory after a fix ships        | Same day as the patched release  |

If a deadline is going to slip, we will say so in the report thread rather than
go quiet.

## Coordinated disclosure

1. You report privately; we acknowledge and confirm whether it reproduces.
2. We agree on severity and a rough timeline in the same thread.
3. We prepare a fix, a regression test that fails against the vulnerable
   version, and a draft advisory.
4. We publish the patched release, then the GitHub Security Advisory, and add
   the entry to `CHANGELOG.md` under a **Security** heading.
5. You are credited by the name or handle you choose, or not at all if you
   prefer.

Default embargo is **90 days** from acknowledgement, or until a fix ships,
whichever comes first. We will not ask you to stay quiet longer than that. If a
vulnerability is being exploited, we will move immediately and publish as soon
as a fix exists.

We do not run a bug bounty and cannot pay for reports.

## Verifying what you installed

Published packages are built and published by the tagged CI workflow, which
refuses to publish when the git tag and the package versions disagree, and
publishes with npm provenance. To check a release:

```sh
npm view traceglass@<version> dist.integrity
npm audit --omit=dev
```

To check that a specific evidence file has not been altered:

```sh
traceglass verify path/to/run.tgev --json
```

This works offline, with no store and no keys — the public key travels in the
file.

## Known past vulnerabilities

Both are fixed. Drafted advisory text lives in
[`.github/advisories/`](.github/advisories/).

| ID (draft)         | Fixed in | Affects     | Summary                                                                     |
| ------------------ | -------- | ----------- | --------------------------------------------------------------------------- |
| `serve` auth bypass | 0.7.2    | 0.3.0–0.7.1 | Percent-encoded path skipped the read authorization gate on non-loopback binds |
| `redact` residue    | 0.7.1    | 0.6.0–0.7.0 | Redacted values stayed recoverable from freed SQLite pages and the WAL       |
