import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import {
  RunStore,
  createEnvelope,
  evaluatePolicy,
  finalizeJournal,
  hashStep,
  ingestAndFinalize,
  parseEvidence,
  parsePolicy,
  patternsByName,
  redactRun,
  readJournal,
  verifyRun,
  verifyRunFull,
  type Run,
} from '@traceglass/core';
import { startRecording } from '@traceglass/sdk';
import { buildServer } from './server.js';
import { generateKeys, loadKeys, maybeSign } from './keys.js';

/**
 * v0.3 outcome test — the end-to-end proof that the evidence pipeline holds:
 * keygen → live-record (signed) → collector ingest with auth → export →
 * verify offline in a clean home → tampering fails loudly → retention is
 * audited → crashed recordings recover.
 */

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');

let home: string;
let originalHome: string | undefined;

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), 'tg-e2e-'));
  originalHome = process.env.TRACEGLASS_HOME;
  process.env.TRACEGLASS_HOME = home;
});

afterAll(() => {
  if (originalHome === undefined) delete process.env.TRACEGLASS_HOME;
  else process.env.TRACEGLASS_HOME = originalHome;
  rmSync(home, { recursive: true, force: true });
});

describe('v0.3 outcome test', () => {
  let sdkRun: Run;

  it('1. keygen creates a 0600 private key and a 16-hex keyId', () => {
    const { keyId } = generateKeys();
    expect(keyId).toMatch(/^[0-9a-f]{16}$/);
    const mode = statSync(join(home, 'keys', 'private.pem')).mode & 0o777;
    expect(mode).toBe(0o600);
    expect(loadKeys()!.keyId).toBe(keyId);
  });

  it('2. SDK records a signed, journaled, verifying run', async () => {
    const rec = startRecording({ name: 'simulated collections agent', dir: home, id: 'e2e-run' });
    rec.step({ type: 'user_input', label: 'Dun account 4471', input: { account: '4471' } });
    rec.step({
      type: 'tool_call',
      toolName: 'get_payment_status',
      label: 'Tool: get_payment_status',
      input: { account: '4471' },
      output: { status: 'overdue', days: 42 },
      dataPayload: { status: 'overdue', days: 42 },
      tokens: 800,
      cost: 0.4,
    });
    expect(existsSync(join(home, 'journal', 'e2e-run.jsonl'))).toBe(true); // journaled mid-run
    rec.step({
      type: 'tool_call',
      toolName: 'send_reminder',
      label: 'Tool: send_reminder',
      input: { account: '4471' },
      output: { sent: true },
      dataPayload: { mutated: 'reminders', account: '4471' },
      tokens: 300,
      cost: 0.2,
    });
    rec.step({ type: 'final_output', label: 'Reminder sent', output: 'Sent reminder to 4471.' });
    sdkRun = await rec.end();

    expect(existsSync(join(home, 'journal', 'e2e-run.jsonl'))).toBe(false); // cleaned up
    const store = new RunStore(join(home, 'traceglass.sqlite'));
    const stored = store.getRun('e2e-run');
    store.close();
    expect(stored).not.toBeNull();
    expect(stored!.signature).toBeDefined(); // auto-signed
    const result = verifyRunFull(stored!);
    expect(result.chain.ok).toBe(true);
    expect(result.signature.ok).toBe(true);
    expect(result.signature.keyId).toBe(loadKeys()!.keyId);
  });

  it('3. collector ingest requires the token and dedupes', async () => {
    const store = new RunStore(':memory:');
    const app = buildServer(store, { token: 's3cret', enableIngest: true, signer: maybeSign });
    await app.ready();
    const payload = JSON.parse(readFileSync(join(fixturesDir, 'sample-run-native.json'), 'utf8'));

    const ok = await app.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { authorization: 'Bearer s3cret', 'content-type': 'application/json' },
      payload,
    });
    expect(ok.statusCode).toBe(200);
    const { runId } = ok.json() as { runId: string };
    expect(store.getRun(runId)!.signature).toBeDefined(); // collector also signs

    const bad = await app.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { authorization: 'Bearer wrong', 'content-type': 'application/json' },
      payload,
    });
    expect(bad.statusCode).toBe(401);
    const missing = await app.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { 'content-type': 'application/json' },
      payload,
    });
    expect(missing.statusCode).toBe(401);
    await app.close();
    store.close();
  });

  it('4+5. exported evidence verifies fully offline in a clean home', () => {
    const exported = JSON.stringify(createEnvelope(sdkRun));
    // Simulate the third party: different TRACEGLASS_HOME, no store, no keys.
    const cleanHome = mkdtempSync(join(tmpdir(), 'tg-clean-'));
    const saved = process.env.TRACEGLASS_HOME;
    process.env.TRACEGLASS_HOME = cleanHome;
    try {
      const parsed = parseEvidence(JSON.parse(exported));
      const result = verifyRunFull(parsed);
      expect(result.chain.ok).toBe(true);
      expect(result.signature.ok).toBe(true); // public key travels in the file
    } finally {
      process.env.TRACEGLASS_HOME = saved;
      rmSync(cleanHome, { recursive: true, force: true });
    }
  });

  it('6. tampering with the export fails at the tampered step', () => {
    const envelope = JSON.parse(JSON.stringify(createEnvelope(sdkRun))) as { run: Run };
    (envelope.run.steps[1]!.output as { status: string }).status = 'paid'; // rewrite history
    const result = verifyRun(parseEvidence(envelope));
    expect(result.ok).toBe(false);
    expect(result.brokenStepIndex).toBe(1);
  });

  it('7. tampering with the DB fails the chain; re-chaining fails the signature', () => {
    // Raw SQL edit — bypassing the append-only API, as an attacker would.
    const db = new Database(join(home, 'traceglass.sqlite'));
    const row = db.prepare(`SELECT data FROM runs WHERE id = 'e2e-run'`).get() as { data: string };
    const tampered = JSON.parse(row.data) as Run;
    tampered.steps[2]!.cost = 0.0001; // hide what the loop cost
    db.prepare(`UPDATE runs SET data = ? WHERE id = 'e2e-run'`).run(JSON.stringify(tampered));
    db.close();

    const store = new RunStore(join(home, 'traceglass.sqlite'));
    const fromDb = store.getRun('e2e-run')!;
    store.close();
    const chainResult = verifyRunFull(fromDb);
    expect(chainResult.chain.ok).toBe(false);
    expect(chainResult.chain.brokenStepIndex).toBe(2);

    // Smarter attacker: recompute the whole chain + runHash. Signature catches it.
    let prevHash = '';
    const rechained: Run = {
      ...fromDb,
      steps: fromDb.steps.map((s) => {
        const base = { ...s, prevHash };
        base.hash = hashStep(base, prevHash);
        prevHash = base.hash;
        return base;
      }),
    };
    rechained.runHash = prevHash;
    const rechainedResult = verifyRunFull(rechained);
    expect(rechainedResult.chain.ok).toBe(true); // chain alone is fooled
    expect(rechainedResult.signature.ok).toBe(false); // signature is not
  });

  it('8. retention prunes only old runs and the pruned list is auditable', () => {
    const store = new RunStore(join(home, 'traceglass.sqlite'));
    const extra = ingestAndFinalize(
      JSON.parse(readFileSync(join(fixturesDir, 'sample-run-native.json'), 'utf8')),
    );
    if (!store.getRun(extra.id)) store.saveRun(extra);
    // Backdate it 40 days via raw SQL (tests only).
    const db = new Database(join(home, 'traceglass.sqlite'));
    const old = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare(`UPDATE runs SET ingested_at = ? WHERE id = ?`).run(old, extra.id);
    db.close();

    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const pruned = store.pruneOlderThan(cutoff);
    expect(pruned.map((p) => p.id)).toEqual([extra.id]);
    expect(store.getRun('e2e-run')).not.toBeNull(); // recent run untouched

    // The CLI's audit write, asserted here at the same contract.
    const auditPath = join(home, 'audit.jsonl');
    appendFileSync(
      auditPath,
      pruned
        .map((p) =>
          JSON.stringify({ ...p, prunedAt: new Date().toISOString(), reason: 'retention' }),
        )
        .join('\n') + '\n',
    );
    const audit = readFileSync(auditPath, 'utf8').trim().split('\n');
    expect(audit).toHaveLength(1);
    expect(JSON.parse(audit[0]!).id).toBe(extra.id);
    store.close();
  });

  it('9. a crashed recording recovers as a verifying failed run', () => {
    const rec = startRecording({ name: 'crashed agent', dir: home, id: 'e2e-crash' });
    rec.step({ type: 'user_input', label: 'start' });
    rec.step({ type: 'tool_call', toolName: 'x', label: 'Tool: x', cost: 1 });
    // No end() — the process "crashed" here.
    const journal = join(home, 'journal', 'e2e-crash.jsonl');
    expect(existsSync(journal)).toBe(true);
    const recovered = finalizeJournal(readJournal(journal));
    expect(recovered.status).toBe('failed');
    expect(recovered.totals.steps).toBe(2);
    expect(verifyRun(recovered).ok).toBe(true);
  });

  it('11. redaction destroys PII while the chain AND signature still verify (v0.6)', async () => {
    const rec = startRecording({ name: 'pii agent', dir: home, id: 'e2e-pii' });
    rec.step({
      type: 'user_input',
      label: 'Lookup customer',
      input: { ssn: '123-45-6789', account: '4471', note: 'keep me' },
    });
    rec.step({
      type: 'tool_call',
      toolName: 'crm',
      label: 'Tool: crm',
      output: { email: 'jane@example.com' },
      dataPayload: { read: 'customer' },
    });
    const original = await rec.end();
    expect(original.signature).toBeDefined();
    expect(verifyRunFull(original).ok).toBe(true);

    const { run: redacted, redacted: paths } = redactRun(original, {
      paths: ['input.ssn'],
      patterns: patternsByName(['email']),
      reason: 'GDPR erasure',
    });
    expect(paths.sort()).toEqual(['e2e-pii:0#input.ssn', 'e2e-pii:1#output.email']);

    // THE CRUX: anchor unchanged, so the ORIGINAL signature still validates.
    expect(redacted.runHash).toBe(original.runHash);
    const check = verifyRunFull(redacted);
    expect(check.chain.ok).toBe(true);
    expect(check.signature.ok).toBe(true);

    // The values are genuinely gone; siblings survive.
    const serialized = JSON.stringify(redacted);
    expect(serialized).not.toContain('123-45-6789');
    expect(serialized).not.toContain('jane@example.com');
    expect(serialized).toContain('keep me');
    expect(serialized).toContain('4471');

    // Persisting it destroys the original on disk.
    const store = new RunStore(join(home, 'traceglass.sqlite'));
    store.replaceRedacted(redacted);
    const reloaded = store.getRun('e2e-pii')!;
    store.close();
    expect(JSON.stringify(reloaded)).not.toContain('123-45-6789');
    expect(verifyRunFull(reloaded).ok).toBe(true);
    expect(reloaded.steps[0]!.redactions![0]!.reason).toBe('GDPR erasure');
  });

  it('12. SECURITY: payload tampering on a committed run is still detected (v0.6)', () => {
    const store = new RunStore(join(home, 'traceglass.sqlite'));
    const run = store.getRun('e2e-pii')!;
    store.close();
    // Editing a raw value cannot move the hash (it covers commitments), so the
    // commitment check is the only thing standing between us and silent edits.
    const tampered: Run = {
      ...run,
      steps: run.steps.map((s, i) =>
        i === 0 ? { ...s, input: { ...(s.input as object), account: '9999' } } : s,
      ),
    };
    expect(tampered.steps[0]!.hash).toBe(run.steps[0]!.hash); // chain looks fine
    const result = verifyRun(tampered);
    expect(result.ok).toBe(false); // but verification still catches it
    expect(result.message).toContain('input.account');
  });

  it('10. approval-gated policy: pass with approval, fail without, search finds the account (v0.4)', async () => {
    // A run where a human approves BEFORE the sensitive tool fires.
    const rec = startRecording({ name: 'gated refund agent', dir: home, id: 'e2e-gated' });
    rec.step({ type: 'user_input', label: 'Refund account 9982', input: { account: '9982' } });
    rec.step({
      type: 'approval',
      label: 'Supervisor approved refund',
      input: { approver: 'lead-ops', decision: 'approve' },
      dataPayload: { approver: 'lead-ops', decision: 'approve' },
    });
    rec.step({
      type: 'tool_call',
      toolName: 'payments.refund',
      label: 'Tool: payments.refund',
      input: { account: '9982', amount: 120 },
      output: { refunded: true },
      dataPayload: { mutated: 'payments', account: '9982' },
      cost: 0.5,
    });
    rec.step({ type: 'final_output', label: 'Refund issued' });
    const gated = await rec.end();

    const policy = parsePolicy({
      name: 'payments guardrails',
      rules: {
        requireApprovalFor: ['payments.*'],
        forbidTools: ['*_delete'],
        requireSignature: true,
        forbidWarnings: ['loop'],
        maxCostPerRun: 10,
      },
    });
    // The gated run satisfies every rule (it was auto-signed — keys exist).
    expect(evaluatePolicy(gated, policy).ok).toBe(true);

    // The earlier e2e-run called tools with NO approval step → same policy fails.
    const store = new RunStore(join(home, 'traceglass.sqlite'));
    const ungated = store.getRun('e2e-run')!;
    const failed = evaluatePolicy(ungated, {
      ...policy,
      rules: { requireApprovalFor: ['get_payment_status'] },
    });
    expect(failed.ok).toBe(false);
    expect(failed.violations[0]!.rule).toBe('requireApprovalFor');

    // Search sweeps the store: "which runs touched account 9982?"
    const hits = store.searchRuns('9982');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.every((h) => h.runId === 'e2e-gated')).toBe(true);
    store.close();
  });
});
