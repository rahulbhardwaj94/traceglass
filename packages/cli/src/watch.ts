import { appendFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  RunStore,
  discoverSessions,
  evaluatePolicy,
  ingestClaudeCodeAndFinalize,
  readSessionRecords,
  sessionRunId,
  type Policy,
  type PolicyResult,
  type Run,
} from '@traceglass/core';
import { dataDir } from './paths.js';
import { maybeSign } from './keys.js';
import { FileAnchorSink, anchorRecordForRun, defaultAnchorsPath } from './anchors.js';

/**
 * Watch-mode sweep (v0.5): turn every finished Claude Code session into
 * signed, policy-checked, optionally anchored evidence — automatically.
 *
 * A session is ingested when (a) it has settled — no file modification for
 * `settleMs` — and (b) its predicted run id is not already stored. Sessions
 * that keep growing after ingestion are NOT re-ingested (the store is
 * append-only); the record is the session as it stood when it settled.
 */

export interface SweepOptions {
  /** Claude Code projects dir; defaults to ~/.claude/projects. */
  dir?: string;
  /** Ingest only sessions unchanged for this long (ms). */
  settleMs: number;
  /** Check each new run against this policy. */
  policy?: Policy;
  /** Append each new run's anchor to the anchors file. */
  anchor?: boolean;
  /** Called once per human-readable progress line. */
  log?: (line: string) => void;
}

export interface SweepIngested {
  runId: string;
  sessionId: string;
  steps: number;
  signed: boolean;
  policy: PolicyResult | null;
}

export interface SweepResult {
  ingested: SweepIngested[];
  skipped: number;
  /** Total policy violations across everything ingested this sweep. */
  violations: number;
}

export async function sweepSessions(store: RunStore, opts: SweepOptions): Promise<SweepResult> {
  const log = opts.log ?? (() => {});
  const result: SweepResult = { ingested: [], skipped: 0, violations: 0 };
  const anchors = opts.anchor ? new FileAnchorSink(defaultAnchorsPath()) : null;
  const now = Date.now();

  for (const session of discoverSessions(opts.dir)) {
    let mtimeMs: number;
    try {
      mtimeMs = statSync(session.file).mtimeMs;
    } catch {
      continue; // Session file vanished between discovery and stat.
    }
    if (now - mtimeMs < opts.settleMs) {
      result.skipped += 1;
      continue; // Still being written — let it settle.
    }
    const predictedId = sessionRunId(session.file);
    if (store.getRun(predictedId)) {
      result.skipped += 1;
      continue; // Already evidence.
    }

    let run: Run;
    try {
      run = maybeSign(
        ingestClaudeCodeAndFinalize(readSessionRecords(session.file), {
          name: session.firstPrompt,
        }),
      );
      store.saveRun(run);
    } catch (e) {
      log(`✗ session ${session.id}: ${e instanceof Error ? e.message.split('\n')[0] : String(e)}`);
      continue;
    }

    let policyResult: PolicyResult | null = null;
    if (opts.policy) {
      policyResult = evaluatePolicy(run, opts.policy);
      if (!policyResult.ok) {
        result.violations += policyResult.violations.length;
        // Violations are evidence too: audit-log them next to retention prunes.
        appendFileSync(
          join(dataDir(), 'audit.jsonl'),
          JSON.stringify({
            reason: 'policy-violation',
            runId: run.id,
            sessionId: session.id,
            policy: policyResult.policyName,
            violations: policyResult.violations,
            at: new Date().toISOString(),
          }) + '\n',
        );
      }
    }

    if (anchors) await anchors.append([anchorRecordForRun(run)]);

    result.ingested.push({
      runId: run.id,
      sessionId: session.id,
      steps: run.totals.steps,
      signed: run.signature !== undefined,
      policy: policyResult,
    });
    const verdict = policyResult
      ? policyResult.ok
        ? ' · policy PASS'
        : ` · policy FAIL (${policyResult.violations.length})`
      : '';
    log(
      `Recorded session ${session.id} → ${run.id} (${run.totals.steps} steps${run.signature ? ', signed' : ''}${verdict})`,
    );
  }
  return result;
}
