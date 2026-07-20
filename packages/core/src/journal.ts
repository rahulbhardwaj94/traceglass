import { readFileSync, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
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
/** An `end` record settles the run, so `running` is not a legal value here. */
const EndLineSchema = z.object({
  kind: z.literal('end'),
  status: z.enum(['completed', 'failed']),
});

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
  endedStatus: Exclude<RunStatus, 'running'> | null;
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

/** Default journal directory: <TRACEGLASS_HOME ?? ~/.traceglass>/journal. */
export function defaultJournalDir(): string {
  return join(process.env.TRACEGLASS_HOME ?? join(homedir(), '.traceglass'), 'journal');
}

/** An in-progress recording, discovered from its journal file (v0.7 tail mode). */
export interface LiveRecording {
  runId: string;
  name: string;
  startedAt: string;
  /** Steps recorded so far. */
  steps: number;
  /** Journal file mtime — how fresh this recording is. */
  updatedAt: string;
  file: string;
  /** True once an `end` record was written but the run has not been stored yet. */
  ended: boolean;
}

/**
 * List recordings currently in progress. The SDK appends one JSONL line per
 * step the moment it happens, so a journal that still exists IS a live run —
 * no extra streaming infrastructure, and it survives a crash.
 */
export function listLiveRecordings(dir: string = defaultJournalDir()): LiveRecording[] {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const out: LiveRecording[] = [];
  for (const name of names) {
    if (!name.endsWith('.jsonl')) continue;
    const file = join(dir, name);
    try {
      const contents = readJournal(file);
      out.push({
        runId: contents.meta.id,
        name: contents.meta.name,
        startedAt: contents.meta.startedAt,
        steps: contents.steps.length,
        updatedAt: statSync(file).mtime.toISOString(),
        file,
        ended: contents.endedStatus !== null,
      });
    } catch {
      // A half-written line mid-append is normal; skip until it settles.
    }
  }
  return out.sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1));
}

/** Find a live recording by run id. */
export function findLiveRecording(
  runId: string,
  dir: string = defaultJournalDir(),
): LiveRecording | null {
  return listLiveRecordings(dir).find((r) => r.runId === runId) ?? null;
}

/**
 * Build a provisional Run from a partial journal so the dashboard and CLI can
 * render an in-flight recording with the existing components. Status is
 * `running` and `runHash` is empty: the chain is real up to the latest step,
 * but the record is not yet anchored or signed.
 */
export function liveRunFromJournal(contents: JournalContents): Run {
  const { meta, steps } = contents;
  const totals = steps.reduce(
    (acc, s) => ({
      tokens: acc.tokens + s.tokens,
      cost: acc.cost + s.cost,
      durationMs: acc.durationMs + s.durationMs,
      steps: acc.steps + 1,
    }),
    { tokens: 0, cost: 0, durationMs: 0, steps: 0 },
  );
  const last = steps[steps.length - 1];
  return analyzeRun({
    id: meta.id,
    name: meta.name,
    startedAt: meta.startedAt,
    endedAt: last
      ? new Date(Date.parse(last.startedAt) + last.durationMs).toISOString()
      : meta.startedAt,
    status: 'running',
    currency: meta.currency,
    totals,
    warnings: [],
    steps,
    runHash: '', // not yet anchored
  });
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
