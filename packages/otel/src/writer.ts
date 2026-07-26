import { appendFileSync, existsSync, mkdirSync, readFileSync, unlinkSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  DEFAULT_HASH_VERSION,
  JOURNAL_FORMAT_VERSION,
  RunStore,
  buildCommitments,
  finalizeJournal,
  hashStep,
  journalLine,
  patternsByName,
  scrubStepPayload,
  signRun,
  type JournalMeta,
  type RedactionPattern,
  type Run,
  type Step,
  type StepType,
} from '@traceglass/core';

/**
 * Capture-time chain writer for span-shaped input.
 *
 * This is deliberately NOT `@traceglass/sdk`'s `startRecording`. That recorder
 * synthesizes a random `spanId` per step and has no way to accept a parent, so
 * routing OTel through it would throw away the two identifiers that let an
 * auditor tie a traceglass record back to the trace it came from. Everything
 * else is the same contract, and the parts that matter are core's, not a second
 * implementation of them:
 *
 *   - steps are hashed the moment they arrive (index = arrival order,
 *     hash = hashStep(step, prevHash)), so the chain is fixed at capture time
 *     and cannot be re-ordered afterwards;
 *   - each step is appended to the same JSONL journal format the SDK writes, so
 *     `traceglass live`, `traceglass recover` and the dashboard read an
 *     in-flight OTel recording with no new machinery;
 *   - finalization goes through core's `finalizeJournal`, which is the exact
 *     code path `traceglass recover` uses — totals, anchor and the verify
 *     self-check are computed once, in one place. A recovered journal and a
 *     cleanly ended run are therefore byte-identical records.
 */

/** One step to append. Unlike the SDK recorder, span ids are caller-supplied. */
export interface WriterStepInput {
  type: StepType;
  label: string;
  startedAt: string;
  durationMs: number;
  tokens: number;
  cost: number;
  toolName?: string;
  input?: unknown;
  output?: unknown;
  dataPayload?: unknown;
  spanId: string;
  parentSpanId?: string;
}

export interface RunWriterOptions {
  id: string;
  name: string;
  currency?: string;
  /**
   * traceglass data dir (journal + SQLite store). Defaults to
   * TRACEGLASS_HOME ?? ~/.traceglass. `null` keeps the run in memory only.
   */
  dir?: string | null;
  /** Per-leaf commitments, so payloads can be redacted later (default on). */
  redactable?: boolean;
  /** Built-in pattern names scrubbed at capture time, before anything is hashed. */
  redactPatterns?: string[];
  /** Run start; defaults to now. */
  startedAt?: string;
}

function defaultDir(): string {
  return process.env.TRACEGLASS_HOME ?? join(homedir(), '.traceglass');
}

/**
 * Load signing keys from <dir>/keys if present. Mirrors the CLI's key layout
 * (packages/cli/src/keys.ts) and the SDK recorder's loader — the file paths are
 * the contract between packages; the ~10 lines are duplicated to avoid pulling
 * the CLI into a library dependency.
 */
function loadKeys(dir: string): { privateKeyPem: string; publicKeyPem: string } | null {
  const priv = join(dir, 'keys', 'private.pem');
  const pub = join(dir, 'keys', 'public.pem');
  if (!existsSync(priv) || !existsSync(pub)) return null;
  return { privateKeyPem: readFileSync(priv, 'utf8'), publicKeyPem: readFileSync(pub, 'utf8') };
}

export class RunWriter {
  readonly runId: string;
  readonly startedAt: string;

  private readonly dir: string | null;
  private readonly meta: JournalMeta;
  private readonly journalFile: string | null;
  private readonly redactable: boolean;
  private readonly patterns: RedactionPattern[];
  private readonly steps: Step[] = [];
  private prevHash = '';
  private ended = false;

  constructor(opts: RunWriterOptions) {
    this.runId = opts.id;
    this.startedAt = opts.startedAt ?? new Date().toISOString();
    this.dir = opts.dir === null ? null : (opts.dir ?? defaultDir());
    this.redactable = opts.redactable !== false;
    this.patterns = opts.redactPatterns ? patternsByName(opts.redactPatterns) : [];
    this.meta = {
      kind: 'meta',
      formatVersion: JOURNAL_FORMAT_VERSION,
      id: this.runId,
      name: opts.name,
      currency: opts.currency ?? 'USD',
      startedAt: this.startedAt,
      hashVersion: DEFAULT_HASH_VERSION,
    };
    this.journalFile = this.dir ? join(this.dir, 'journal', `${this.runId}.jsonl`) : null;
    if (this.journalFile && this.dir) {
      mkdirSync(join(this.dir, 'journal'), { recursive: true });
      appendFileSync(this.journalFile, journalLine(this.meta));
    }
  }

  get stepCount(): number {
    return this.steps.length;
  }

  get isEnded(): boolean {
    return this.ended;
  }

  /** Append one step: scrubbed, committed, hashed and journaled before returning. */
  step(input: WriterStepInput): Step {
    if (this.ended) throw new Error(`Recording "${this.runId}" has already ended.`);
    const index = this.steps.length;
    const hashVersion = DEFAULT_HASH_VERSION;

    // Capture-time scrubbing runs BEFORE commitments/hashing, so a matched
    // value is never committed to and never written anywhere.
    let payload: { input?: unknown; output?: unknown; dataPayload?: unknown } = {
      ...(input.input !== undefined ? { input: input.input } : {}),
      ...(input.output !== undefined ? { output: input.output } : {}),
      ...(input.dataPayload !== undefined ? { dataPayload: input.dataPayload } : {}),
    };
    let redactions: Step['redactions'];
    if (this.patterns.length > 0) {
      const scrubbed = scrubStepPayload(payload, this.patterns, hashVersion);
      payload = scrubbed.payload;
      if (scrubbed.redactions.length > 0) redactions = scrubbed.redactions;
    }

    const step: Step = {
      id: `${this.runId}:${index}`,
      runId: this.runId,
      index,
      type: input.type,
      label: input.label,
      startedAt: input.startedAt,
      durationMs: input.durationMs,
      tokens: input.tokens,
      cost: input.cost,
      ...(input.toolName !== undefined ? { toolName: input.toolName } : {}),
      ...payload,
      spanId: input.spanId,
      ...(input.parentSpanId !== undefined ? { parentSpanId: input.parentSpanId } : {}),
      hash: '',
      prevHash: this.prevHash,
      ...(this.redactable ? buildCommitments(payload, hashVersion) : {}),
      ...(redactions !== undefined ? { redactions } : {}),
    };
    step.hash = hashStep(step, this.prevHash, hashVersion);
    this.prevHash = step.hash;
    this.steps.push(step);
    if (this.journalFile) appendFileSync(this.journalFile, journalLine({ kind: 'step', step }));
    return step;
  }

  /**
   * Finalize: totals + warnings + anchor via core's journal finalizer, sign if
   * keys exist, save, delete the journal. Synchronous — every write involved is
   * (the SDK recorder's `end` is async only because its signature is).
   */
  end(opts: { status?: 'completed' | 'failed' } = {}): Run {
    if (this.ended) throw new Error(`Recording "${this.runId}" has already ended.`);
    this.ended = true;
    if (this.steps.length === 0) {
      throw new Error(`Recording "${this.runId}" has no steps; nothing to finalize.`);
    }
    const status =
      opts.status ?? (this.steps.some((s) => s.type === 'error') ? 'failed' : 'completed');
    if (this.journalFile) appendFileSync(this.journalFile, journalLine({ kind: 'end', status }));

    // finalizeJournal verifies the assembled record and throws if the chain
    // does not hold, so a broken run is never stored.
    let run = finalizeJournal({ meta: this.meta, steps: this.steps, endedStatus: status });

    if (this.dir) {
      const keys = loadKeys(this.dir);
      if (keys) run = signRun(run, keys.privateKeyPem, keys.publicKeyPem);
      const store = new RunStore(join(this.dir, 'traceglass.sqlite'));
      try {
        store.saveRun(run);
      } finally {
        store.close();
      }
      if (this.journalFile) unlinkSync(this.journalFile);
    }
    return run;
  }
}
