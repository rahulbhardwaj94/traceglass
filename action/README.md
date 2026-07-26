# `traceglass` GitHub Action

Fail the build when a recorded agent run violates its guardrails, and post the
compliance summary as a pull-request comment.

`traceglass check --policy` is a good command that nobody remembers to run. This
turns it into infrastructure: the run's evidence file is checked on every pull
request, the verdict lands as a comment that updates in place, and a violation
is a red X rather than a line in a log nobody opened.

---

## Quick start

```yaml
name: agent evidence
on: pull_request

permissions:
  contents: read
  pull-requests: write   # only needed for the comment

jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22

      - uses: rahulbhardwaj94/traceglass/action@main
        with:
          evidence: evidence/nightly-underwriting.tgev
          policy: .traceglass/policy.json
```

That is the whole integration. The action runs
`traceglass check <evidence> --policy <policy> --json`, renders the result, and
exits 1 if the record fails either integrity or policy.

> **Note.** This action is not published to the GitHub Marketplace, and
> `@main` is not a stable ref. Pin a tag once one exists, or vendor `action/`
> into your own repository — it is three dependency-free files with no build
> step.

---

## What it actually does

1. **Runs the check.** `traceglass check <evidence> --policy <policy> --json`.
   Integrity (hash chain + signature + redaction log) is checked alongside the
   rules, because a policy verdict over an inauthentic record is worthless.
2. **Optionally checks anchors.** With `anchors:` set it also runs
   `traceglass verify --anchors`, and reports the anchor strength —
   `none` / `local` / `self-attested` / `external`.
3. **Writes the job summary.** The rendered Markdown goes to
   `$GITHUB_STEP_SUMMARY`, so the verdict is on the run page whether or not a
   pull request exists.
4. **Comments on the pull request.** Keyed on `evidence` + `policy`, so a re-run
   edits its own comment instead of stacking, and two different checks in one
   workflow keep two separate comments.
5. **Sets the verdict.** Exit 1 by default; outputs are set either way.

### Zero dependencies

`main.mjs` and `report.mjs` are plain ESM run by the Node already on the runner.
No `node_modules`, no bundler, no committed `dist/`, no `@actions/*` packages.
The REST calls use Node 20's built-in `fetch`. For a product whose pitch is that
you can audit its supply chain, an action with a 200-package transitive tree
would be an odd thing to ship.

---

## What the comment looks like

Real output, rendered by this action against the run built in
[`../docs/forensic-walkthrough.md`](../docs/forensic-walkthrough.md) — a
collections agent that looped, refunded ₹18,400 with nobody's approval, and had
its subject's PII erased afterwards:

> ## ❌ traceglass — record FAILED
>
> Checked `evidence/account-4471.tgev` against `docs/examples/collections-policy.json` · run `collections-4471`.
>
> ### Integrity
>
> | | Check | Result |
> |---|---|---|
> | ✅ | Hash chain | Integrity check passed: chain intact. |
> | ✅ | Signature | Signature OK (keyId 131fe18d2d28c0e1). |
> | ⚠️ | Redaction log | 5 redaction(s) recorded, UNATTESTED: no keyholder has sealed this redaction log, so the entries are a claim by whoever last wrote the file. |
>
> Anchor `fd447e28544661c3f2ed62a4bca4e14f5d7307ed28cdba80fc82a920bd5e465b` (tgcanon/2).
>
> ### Policy — `collections guardrails`
>
> ❌ **3 violation(s).**
>
> | Rule | What happened | Steps |
> |---|---|---|
> | `maxCostPerRun` | Run cost INR 17.00 exceeds the limit of 10. |  |
> | `requireApprovalFor` | Tool "payments.*" was called without a preceding approval step (4 time(s), first at step #2). | `collections-4471:2` `collections-4471:3` `collections-4471:4` `collections-4471:5` |
> | `forbidWarnings` | Forbidden warning "loop": Tool "payments.get_status" was called 3x in a row with identical input — likely a stuck loop burning tokens/cost. | `collections-4471:2` `collections-4471:3` `collections-4471:4` |
>
> <details><summary>What this verdict does and does not prove</summary>
>
> - The chain proves the steps were not **edited, reordered, inserted or removed** after the anchor was sealed. It does not prove the record was *true* when written, and it cannot detect a step that was never recorded.
> - Verification uses the public key **embedded in the evidence file**. A valid signature therefore means *internally consistent and self-attested by that key*, not *authenticated*. An anchored record proves strictly more; only an `external` anchor is third-party evidence.
> - A redaction entry is an unauthenticated claim unless the redaction log is sealed (`attested: true`).
>
> The full calibration is in `docs/threat-model.md` in the traceglass repository.
> </details>

The collapsed section is not decoration. A green check on a pull request is
exactly where someone will over-read the guarantee, so the qualification travels
with the verdict instead of living in a document they would have to go and find.

---

## Inputs

| Input | Required | Default | Description |
|---|:---:|---|---|
| `evidence` | yes | — | Path to a `.tgev` file, or the id of a run in the runner's traceglass store. |
| `policy` | yes | — | Path to the guardrail policy JSON. |
| `comment` | no | `true` | Post/update the pull-request comment. Needs `pull-requests: write`. Ignored when the event has no PR. |
| `summary` | no | `true` | Write the summary to `$GITHUB_STEP_SUMMARY`. |
| `fail-on-violation` | no | `true` | Exit non-zero on failure. `false` reports only — gate on the `ok` output yourself. |
| `anchors` | no | `''` | Anchors JSONL file to check the run against. |
| `tsa-cert` | no | `''` | PEM of the expected RFC 3161 TSA certificate. Pins timestamp anchors. |
| `rekor-key` | no | `''` | PEM of the transparency log's public key. Pins Rekor anchors. |
| `require-external` | no | `false` | Fail unless an anchor verifies against out-of-band trust material. Requires `anchors`. |
| `version` | no | `latest` | npm version of the `traceglass` CLI to run. |
| `bin` | no | `''` | Path to an already-built entrypoint (e.g. `packages/cli/dist/bin.js`). Overrides `version`. |
| `github-token` | no | `${{ github.token }}` | Token for the comment. |
| `github-api-url` | no | `${{ github.api_url }}` | REST base URL. Override for GitHub Enterprise Server. |

## Outputs

| Output | Description |
|---|---|
| `ok` | `true` when integrity and policy both passed. |
| `violations` | Number of policy violations. |
| `run-id` | Id of the run that was checked. |
| `anchor-strength` | `none` / `local` / `self-attested` / `external`; empty unless `anchors` was set. |
| `report` | Path to the rendered Markdown. |
| `json` | Path to the raw `traceglass check --json` output. |

---

## Recipes

### Pin the CLI version

`latest` is convenient and wrong for a compliance gate — a new release should
not be able to change a verdict on a Monday morning.

```yaml
- uses: rahulbhardwaj94/traceglass/action@main
  with:
    evidence: evidence/run.tgev
    policy: .traceglass/policy.json
    version: '0.9.0'
```

### Report without blocking, then block later

Roll a policy out in warn mode, watch the comments for a week, then flip one
line.

```yaml
- id: tg
  uses: rahulbhardwaj94/traceglass/action@main
  with:
    evidence: evidence/run.tgev
    policy: .traceglass/policy.json
    fail-on-violation: 'false'

- name: block only on cost
  if: steps.tg.outputs.violations != '0'
  run: |
    jq -e '.check.policy.violations | map(select(.rule == "maxCostPerRun")) | length == 0' \
      "${{ steps.tg.outputs.json }}"
```

### Require a real external trust root

The strongest form. A `local` anchor is a note the recording machine wrote to
itself; only `external` is third-party evidence.

```yaml
- uses: rahulbhardwaj94/traceglass/action@main
  with:
    evidence: evidence/run.tgev
    policy: .traceglass/policy.json
    anchors: evidence/anchors.jsonl
    tsa-cert: .traceglass/digicert-tsa.pem
    require-external: 'true'
```

### Record in CI, then check what you recorded

```yaml
- name: run the agent under the SDK
  run: node scripts/nightly-agent.mjs        # calls startRecording()

- name: export the evidence
  run: npx traceglass export "$RUN_ID" -o evidence/run.tgev

- uses: rahulbhardwaj94/traceglass/action@main
  with:
    evidence: evidence/run.tgev
    policy: .traceglass/policy.json

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: agent-evidence
    path: evidence/run.tgev
```

Uploading the `.tgev` matters more than it looks. The record is the artefact an
auditor asks for, and `always()` means you keep it precisely on the runs that
failed.

### Check every exported record in a directory

```yaml
- id: find
  run: echo "files=$(ls evidence/*.tgev | jq -R -s -c 'split("\n")[:-1]')" >> "$GITHUB_OUTPUT"
```

…then fan out with a matrix over `fromJSON(steps.find.outputs.files)`, one job
per record. Each gets its own comment, because the marker is keyed on the
evidence path.

---

## Permissions

```yaml
permissions:
  contents: read
  pull-requests: write
```

`pull-requests: write` is only needed for `comment: true`. Without it the action
warns and carries on — a missing permission must never turn a failing policy
check into a passing job. Forks: `pull_request` from a fork gets a read-only
token, so the comment is skipped and the job summary carries the verdict
instead.

---

## Testing it

```bash
npm run build
node action/test.mjs
```

`test.mjs` records a real run with the SDK, exports a real `.tgev`, and invokes
`main.mjs` exactly as the composite step does — same `INPUT_*` variables, same
`GITHUB_OUTPUT` / `GITHUB_STEP_SUMMARY` / `GITHUB_EVENT_PATH` contract. It
covers the violating record, the clean record, `fail-on-violation: false`, a
tampered file, both anchor paths, and refusal on bad input. The pull-request
comment runs against a local stub of the REST API (`github-api-url` is a real
input, for GitHub Enterprise Server), so create-then-update, per-policy comment
keying, the no-PR case and the permission-denied case are all covered without a
network or a token.

```
58 checks passed, 0 failed
```

---

## Files

| File | What it is |
|---|---|
| `action.yml` | the composite action definition |
| `main.mjs` | reads inputs, runs the CLI, writes outputs, posts the comment |
| `report.mjs` | pure Markdown renderer — no I/O, so it is directly testable |
| `test.mjs` | the end-to-end exercise above |
