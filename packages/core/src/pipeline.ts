import type { Run } from './model.js';
import { ingestAuto } from './ingest/index.js';
import {
  ingestClaudeCodeSession,
  type ClaudeCodeIngestOptions,
} from './ingest/claude-code.js';
import { analyzeRun } from './analyze/index.js';
import { applyHashChain } from './integrity/hash.js';

/**
 * Turn a structurally-ingested run into a finalized audit record:
 *   1. analyze  → recompute totals, attach warnings (loops, high-cost, errors)
 *   2. hash     → compute the tamper-evidence chain + runHash (§6)
 *
 * Hashes cover only step content (not warnings), so this order is safe.
 */
export function finalizeRun(run: Run): Run {
  return applyHashChain(analyzeRun(run));
}

/** Detect format, ingest, and finalize in one step — the `open` pipeline. */
export function ingestAndFinalize(value: unknown): Run {
  return finalizeRun(ingestAuto(value));
}

/** Ingest Claude Code session records and finalize — the `--session` pipeline. */
export function ingestClaudeCodeAndFinalize(
  records: unknown[],
  opts?: ClaudeCodeIngestOptions,
): Run {
  return finalizeRun(ingestClaudeCodeSession(records, opts));
}
