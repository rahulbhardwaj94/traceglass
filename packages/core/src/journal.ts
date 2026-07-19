import { readFileSync } from 'node:fs';
import { RunStatusSchema, StepSchema, type Run, type RunStatus, type Step } from './model.js';
import { analyzeRun } from './analyze/index.js';
import { verifyRun } from './integrity/verify.js';
import { z } from 'zod';

/**
 * Crash-safe recording journal (v0.3 live capture).
 *
 * While an agent run is being recorded, each step is appended as one JSONL
 * line the moment it happens — already hash-chained, so the chain is fixed at
 * capture time. On a clean end() the journal is finalized into the append-only
 * store and deleted. If the process dies mid-run, the orphaned journal can be
 * finalized later (`traceglass recover`) into a `failed` run whose chain still
 * verifies up to the crash point.
 */

export const JOURNAL_FORMAT_VERSION = 1;

const MetaLineSchema = z.object({
  kind: z.literal('meta'),
  formatVersion: z.literal(JOURNAL_FORMAT_VERSION),
  id: z.string().min(1),
  name: z.string(),
  currency: z.string(),
  startedAt: z.string(),
});
export type JournalMeta = z.infer<typeof MetaLineSchema>;

const StepLineSchema = z.object({ kind: z.literal('step'), step: StepSchema });
const EndLineSchema = z.object({ kind: z.literal('end'), status: RunStatusSchema });

const JournalLineSchema = z.discriminatedUnion('kind', [
  MetaLineSchema,
  StepLineSchema,
  EndLineSchema,
]);
export type JournalLine = z.infer<typeof JournalLineSchema>;

export interface JournalContents {
  meta: JournalMeta;
  steps: Step[];
  /** Status from the `end` record, or null if the recording never ended cleanly. */
  endedStatus: RunStatus | null;
}

/** Parse a journal file. Throws if the meta line is missing or malformed. */
export function readJournal(file: string): JournalContents {
  const lines = readFileSync(file, 'utf8').split('\n');
  let meta: JournalMeta | null = null;
  const steps: Step[] = [];
  let endedStatus: RunStatus | null = null;
  for (const line of lines) {
    if (!line.trim()) continue;
    const parsed = JournalLineSchema.parse(JSON.parse(line));
    if (parsed.kind === 'meta') meta = parsed;
    else if (parsed.kind === 'step') steps.push(parsed.step);
    else endedStatus = parsed.status;
  }
  if (!meta) throw new Error(`Journal ${file} has no meta line.`);
  return { meta, steps, endedStatus };
}

/** Serialize one journal line (used by the SDK recorder). */
export function journalLine(line: JournalLine): string {
  return JSON.stringify(line) + '\n';
}

/**
 * Assemble journal contents into a finalized Run. Steps are used exactly as
 * recorded (order + hashes fixed at capture); only totals/warnings/anchor are
 * derived here. A journal with no `end` record finalizes as `failed`.
 */
export function finalizeJournal(contents: JournalContents): Run {
  const { meta, steps, endedStatus } = contents;
  if (steps.length === 0) {
    throw new Error(`Journal for run "${meta.id}" has no steps; nothing to recover.`);
  }
  const last = steps[steps.length - 1]!;
  const totals = steps.reduce(
    (acc, s) => ({
      tokens: acc.tokens + s.tokens,
      cost: acc.cost + s.cost,
      durationMs: acc.durationMs + s.durationMs,
      steps: acc.steps + 1,
    }),
    { tokens: 0, cost: 0, durationMs: 0, steps: 0 },
  );
  const run: Run = analyzeRun({
    id: meta.id,
    name: meta.name,
    startedAt: meta.startedAt,
    endedAt: new Date(Date.parse(last.startedAt) + last.durationMs).toISOString(),
    status: endedStatus ?? 'failed',
    currency: meta.currency,
    totals,
    warnings: [],
    steps,
    runHash: last.hash,
  });
  const check = verifyRun(run);
  if (!check.ok) {
    throw new Error(`Journal for run "${meta.id}" fails integrity: ${check.message}`);
  }
  return run;
}
