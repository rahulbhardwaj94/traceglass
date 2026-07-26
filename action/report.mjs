/**
 * Renders the compliance summary posted to the job summary and the PR comment.
 *
 * Pure: input is the parsed JSON from `traceglass check --json` (plus, when the
 * caller asked for anchors, the `anchor` block from `traceglass verify --json`).
 * No I/O, no globals — so `node action/test.mjs` can assert on it directly.
 *
 * The wording here is bound by docs/threat-model.md §6. A valid signature means
 * *self-attested*, not *authenticated*, and this comment is the surface most
 * likely to be read by someone who will not read the threat model. So the
 * qualification travels with the verdict rather than living in a footnote
 * somebody has to go and find.
 */

/** The hidden marker that lets a re-run update its own comment in place. */
export const MARKER_PREFIX = '<!-- traceglass-action:';

export function markerFor(key) {
  // Key the marker on evidence+policy so two checks in one workflow keep two
  // comments rather than overwriting each other.
  return `${MARKER_PREFIX}${key.replace(/[^A-Za-z0-9._/-]/g, '_')} -->`;
}

const YES = '✅'; // white heavy check mark
const NO = '❌'; // cross mark
const WARN = '⚠️'; // warning sign

/** Collapse anything that would break out of a Markdown table cell. */
function cell(text) {
  return String(text ?? '')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .trim();
}

/** Fence a value that came from a record, so a crafted label cannot inject Markdown. */
function code(text) {
  const s = String(text ?? '');
  return s === '' ? '' : '`' + s.replace(/`/g, 'ˋ') + '`';
}

function anchorLine(anchor) {
  if (!anchor) return null;
  if (!anchor.matched) {
    return `${WARN} **No anchor record** for this run. Absence is not detectable from the record itself.`;
  }
  const strength = anchor.strength;
  const proven = anchor.provenExistedBy
    ? ` Provably existed by \`${anchor.provenExistedBy}\`.`
    : '';
  if (strength === 'external') {
    return `${YES} **Anchor: external.** Verified against trust material supplied out of band — this is third-party evidence.${proven}`;
  }
  if (strength === 'self-attested') {
    return `${WARN} **Anchor: self-attested.** The proof is cryptographically valid, but only against trust material carried inside the proof itself. Pin the TSA certificate or the log key to upgrade it.${proven}`;
  }
  if (strength === 'local') {
    return `${WARN} **Anchor: local only.** A matching signed record exists, but it carries no external proof and cannot outrank someone who controls the recording machine.`;
  }
  return `${WARN} **Anchor: none.**`;
}

/**
 * @param {object} args
 * @param {object} args.check      parsed `traceglass check --json`
 * @param {object|null} args.anchor  the `anchor` block from `verify --json`, if requested
 * @param {string[]} args.anchorFileProblems
 * @param {string} args.evidence   what the user pointed the action at
 * @param {string} args.policyPath
 * @param {string|null} args.runUrl link back to the workflow run, if known
 */
export function renderMarkdown({
  check,
  anchor = null,
  anchorFileProblems = [],
  evidence,
  policyPath,
  runUrl = null,
}) {
  const integrity = check.integrity ?? {};
  const chain = integrity.chain ?? {};
  const signature = integrity.signature ?? {};
  const redaction = integrity.redaction ?? {};
  const policy = check.policy ?? { ok: true, violations: [] };
  const violations = policy.violations ?? [];
  const ok = check.ok === true;

  const out = [];
  out.push(`## ${ok ? YES : NO} traceglass — ${ok ? 'record passed' : 'record FAILED'}`);
  out.push('');
  out.push(
    `Checked ${code(evidence)} against ${code(policyPath)}` +
      (check.runId ? ` · run ${code(check.runId)}` : '') +
      '.',
  );
  out.push('');

  // --- integrity -----------------------------------------------------------
  out.push('### Integrity');
  out.push('');
  out.push('| | Check | Result |');
  out.push('|---|---|---|');
  out.push(`| ${chain.ok ? YES : NO} | Hash chain | ${cell(chain.message)} |`);
  out.push(
    `| ${signature.ok ? YES : signature.keyId ? NO : WARN} | Signature | ${cell(
      signature.message ?? 'No signature.',
    )} |`,
  );
  if (redaction.message) {
    out.push(
      `| ${redaction.ok ? (redaction.attested ? YES : WARN) : NO} | Redaction log | ${cell(
        redaction.message,
      )} |`,
    );
  }
  out.push('');

  if (chain.storedRunHash) {
    out.push(`Anchor \`${chain.storedRunHash}\`${chain.hashVersion ? ` (tgcanon/${chain.hashVersion})` : ''}.`);
    if (!chain.ok && chain.expectedRunHash && chain.expectedRunHash !== chain.storedRunHash) {
      out.push('');
      out.push(`Recomputed to \`${chain.expectedRunHash}\` — they disagree.`);
    }
    out.push('');
  }

  const aline = anchorLine(anchor);
  if (aline) {
    out.push(aline);
    out.push('');
  }
  for (const p of anchorFileProblems) {
    out.push(`${NO} Anchors file: ${cell(p)}`);
  }
  if (anchorFileProblems.length) out.push('');

  // --- policy --------------------------------------------------------------
  const name = policy.policyName ? ` — ${code(policy.policyName)}` : '';
  out.push(`### Policy${name}`);
  out.push('');
  if (violations.length === 0) {
    out.push(`${YES} No violations.`);
  } else {
    out.push(`${NO} **${violations.length} violation(s).**`);
    out.push('');
    out.push('| Rule | What happened | Steps |');
    out.push('|---|---|---|');
    for (const v of violations) {
      const steps = (v.stepIds ?? []).slice(0, 4).map(code).join(' ');
      const more = (v.stepIds ?? []).length > 4 ? ` +${v.stepIds.length - 4} more` : '';
      out.push(`| ${code(v.rule)} | ${cell(v.message)} | ${steps}${more} |`);
    }
  }
  out.push('');

  // --- the honest footer ---------------------------------------------------
  out.push('<details><summary>What this verdict does and does not prove</summary>');
  out.push('');
  out.push(
    '- The chain proves the steps were not **edited, reordered, inserted or removed** after the anchor was sealed. It does not prove the record was *true* when written, and it cannot detect a step that was never recorded.',
  );
  out.push(
    '- Verification uses the public key **embedded in the evidence file**. A valid signature therefore means *internally consistent and self-attested by that key*, not *authenticated*. An anchored record proves strictly more; only an `external` anchor is third-party evidence.',
  );
  out.push(
    '- A redaction entry is an unauthenticated claim unless the redaction log is sealed (`attested: true`).',
  );
  out.push('');
  // Deliberately not a link: a relative path does not resolve from a PR comment
  // on a consumer's repository, and hard-coding an absolute URL here would rot.
  out.push('The full calibration is in `docs/threat-model.md` in the traceglass repository.');
  out.push('</details>');
  if (runUrl) {
    out.push('');
    out.push(`<sub>[workflow run](${runUrl})</sub>`);
  }
  out.push('');
  return out.join('\n');
}
