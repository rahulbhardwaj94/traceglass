import { appendFileSync, existsSync, mkdirSync, readFileSync, unlinkSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  JOURNAL_FORMAT_VERSION,
  RunStore,
  analyzeRun,
  buildCommitments,
  hashStep,
  journalLine,
  patternsByName,
  scrubStepPayload,
  signRun,
  verifyRun,
  type Run,
  type RunStatus,
  type Step,
  type StepType,
} from '@traceglass/core';

/**
 * Live-capture recorder. Unlike post-hoc ingestion (which sorts and re-indexes
 * before chaining), the recorder hashes each step the moment it is recorded:
 * index = arrival order, hash = hashStep(step, prevHash). The chain is
 * therefore fixed at capture time — recorded history cannot be silently
 * reordered or edited later, which is the whole point of a flight recorder.
 *
 * Crash safety: every step is synchronously appended to a JSONL journal in
 * <dir>/journal/ before step() returns (appendFileSync without fsync — a
 * process crash loses nothing; a power failure may lose the final line).
 * end() saves the finalized run into the append-only store and deletes the
 * journal. Orphaned journals are finalized by `traceglass recover`.
 */

export interface StartRecordingOptions {
  name: string;
  currency?: string;
  /** Explicit run id; defaults to sdk-<timestamp>-<hex>. */
  id?: string;
  /**
   * traceglass data dir (journal + SQLite store live here). Defaults to
   * TRACEGLASS_HOME ?? ~/.traceglass. Pass null for a memory-only recording
   * (no journal, no store — end() just returns the finalized Run).
   */
  dir?: string | null;
  /**
   * Record per-leaf commitments so payload values can be redacted later
   * WITHOUT breaking the hash chain (v0.6). On by default — it is what makes
   * `traceglass redact` possible. Set false for the pre-0.6 hashing behaviour.
   */
  redactable?: boolean;
  /**
   * Names of built-in patterns (email, credit-card, ssn, aadhaar,
   * private-key, bearer-token) to scrub at CAPTURE time. Matching values are
   * replaced before anything is hashed or written, so the original never
   * reaches disk.
   */
  redactPatterns?: string[];
}

export interface RecordStepInput {
  type: StepType;
  label: string;
  input?: unknown;
  output?: unknown;
  dataPayload?: unknown;
  tokens?: number;
  cost?: number;
  toolName?: string;
  durationMs?: number;
  startedAt?: string;
}

export interface Recorder {
  readonly runId: string;
  /** Record one step: hashed into the chain and journaled before returning. */
  step(input: RecordStepInput): Step;
  /** Finalize: totals + warnings + anchor, sign if keys exist, save, clean up. */
  end(opts?: { status?: RunStatus }): Promise<Run>;
}

function defaultDir(): string {
  return process.env.TRACEGLASS_HOME ?? join(homedir(), '.traceglass');
}

/**
 * Load signing keys from <dir>/keys if present. Mirrors the CLI's key layout
 * (packages/cli/src/keys.ts) — the file paths are the contract between the
 * two packages; the ~10 lines are duplicated to avoid a cli→sdk dependency.
 */
function loadKeys(dir: string): { privateKeyPem: string; publicKeyPem: string } | null {
  const priv = join(dir, 'keys', 'private.pem');
  const pub = join(dir, 'keys', 'public.pem');
  if (!existsSync(priv) || !existsSync(pub)) return null;
  return { privateKeyPem: readFileSync(priv, 'utf8'), publicKeyPem: readFileSync(pub, 'utf8') };
}

export function startRecording(opts: StartRecordingOptions): Recorder {
  const runId =
    opts.id ?? `sdk-${new Date().toISOString().slice(0, 10)}-${randomBytes(3).toString('hex')}`;
  const currency = opts.currency ?? 'USD';
  const dir = opts.dir === null ? null : (opts.dir ?? defaultDir());
  const startedAt = new Date().toISOString();
  const steps: Step[] = [];
  let prevHash = '';
  let ended = false;
  const redactable = opts.redactable !== false; // on by default (v0.6)
  const patterns = opts.redactPatterns ? patternsByName(opts.redactPatterns) : [];

  const journalFile = dir ? join(dir, 'journal', `${runId}.jsonl`) : null;
  if (journalFile) {
    mkdirSync(join(dir!, 'journal'), { recursive: true });
    appendFileSync(
      journalFile,
      journalLine({
        kind: 'meta',
        formatVersion: JOURNAL_FORMAT_VERSION,
        id: runId,
        name: opts.name,
        currency,
        startedAt,
      }),
    );
  }

  return {
    runId,

    step(input: RecordStepInput): Step {
      if (ended) throw new Error(`Recording "${runId}" has already ended.`);
      const index = steps.length;

      // Capture-time pattern scrubbing runs BEFORE commitments/hashing, so a
      // matched value is never committed to and never written anywhere.
      let payload: { input?: unknown; output?: unknown; dataPayload?: unknown } = {
        ...(input.input !== undefined ? { input: input.input } : {}),
        ...(input.output !== undefined ? { output: input.output } : {}),
        ...(input.dataPayload !== undefined ? { dataPayload: input.dataPayload } : {}),
      };
      let redactions: Step['redactions'];
      if (patterns.length > 0) {
        const scrubbed = scrubStepPayload(payload, patterns);
        payload = scrubbed.payload;
        if (scrubbed.redactions.length > 0) redactions = scrubbed.redactions;
      }

      const step: Step = {
        id: `${runId}:${index}`,
        runId,
        index,
        type: input.type,
        label: input.label,
        startedAt: input.startedAt ?? new Date().toISOString(),
        durationMs: input.durationMs ?? 0,
        tokens: input.tokens ?? 0,
        cost: input.cost ?? 0,
        ...(input.toolName !== undefined ? { toolName: input.toolName } : {}),
        ...payload,
        spanId: randomBytes(8).toString('hex'),
        hash: '',
        prevHash,
        ...(redactable ? buildCommitments(payload) : {}),
        ...(redactions !== undefined ? { redactions } : {}),
      };
      step.hash = hashStep(step, prevHash);
      prevHash = step.hash;
      steps.push(step);
      if (journalFile) appendFileSync(journalFile, journalLine({ kind: 'step', step }));
      return step;
    },

    async end(endOpts: { status?: RunStatus } = {}): Promise<Run> {
      if (ended) throw new Error(`Recording "${runId}" has already ended.`);
      ended = true;
      if (steps.length === 0) throw new Error('Cannot end a recording with no steps.');
      const status =
        endOpts.status ?? (steps.some((s) => s.type === 'error') ? 'failed' : 'completed');
      if (journalFile) appendFileSync(journalFile, journalLine({ kind: 'end', status }));

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
      // Warnings/totals live outside the hashed fields, so analyzing after
      // chaining cannot break the chain.
      let run: Run = analyzeRun({
        id: runId,
        name: opts.name,
        startedAt,
        endedAt: new Date().toISOString(),
        status,
        currency,
        totals,
        warnings: [],
        steps,
        runHash: last.hash,
      });

      const check = verifyRun(run);
      if (!check.ok) throw new Error(`Recorder self-check failed: ${check.message}`);

      if (dir) {
        const keys = loadKeys(dir);
        if (keys) run = signRun(run, keys.privateKeyPem, keys.publicKeyPem);
        const store = new RunStore(join(dir, 'traceglass.sqlite'));
        try {
          store.saveRun(run);
        } finally {
          store.close();
        }
        if (journalFile) unlinkSync(journalFile);
      }
      return run;
    },
  };
}
