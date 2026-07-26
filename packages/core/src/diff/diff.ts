import type { Run, RunStatus, Step, StepType, Warning } from '../model.js';
import {
  COMMITTED_FIELDS,
  canonicalize,
  hashVersionOf,
  isSupportedHashVersion,
  type CommittedField,
} from '../integrity/hash.js';
import { REDACTED_MARKER, escapePathSegment } from '../redact/commit.js';
import { alignSteps, type AlignOptions } from './align.js';

/**
 * Trace diffing (roadmap #14): what changed between two recorded runs.
 *
 * Two audiences shape every decision here:
 *
 *   - forensics — "this run went wrong and yesterday's didn't; what differed?"
 *   - regression testing — "did this prompt change make the agent worse?",
 *     which is `traceglass diff` in CI next to `traceglass check --policy`.
 *
 * A diff of two evidence records is itself evidence, so the hard rule is that
 * it must be HONEST ABOUT WHAT IT CANNOT COMPARE. Two cases matter:
 *
 *   1. Redacted leaves. The value is destroyed by design and only the salted
 *      commitment survives (SPEC §8.3). Comparing the surviving marker against
 *      a live value would report a CHANGE on a pair of perfectly intact
 *      records. That is the same class of false alarm as SPEC §12.5, the worst
 *      bug this product has shipped, so a redacted leaf is reported as
 *      `redacted` — not comparable — and never as changed.
 *
 *   2. Records written under different hashing rules. `tgcanon/1` builds
 *      commitment paths by bare concatenation, `tgcanon/2` escapes them. The
 *      diff therefore addresses leaves by a single unambiguous encoding of its
 *      own (v2 syntax) and translates to each record's own path syntax only to
 *      look up that record's commitments — and says so in a caveat.
 *
 * Pure: no I/O, no clock, no mutation of the inputs.
 */

/* ── result types ──────────────────────────────────────────────────────────── */

export type DiffCaveatKind =
  | 'hash-version-mismatch'
  | 'unsupported-hash-version'
  | 'currency-mismatch'
  | 'redacted-leaves'
  | 'alignment-degraded';

export interface DiffCaveat {
  kind: DiffCaveatKind;
  message: string;
}

export interface NumericDelta {
  a: number;
  b: number;
  delta: number;
}

/** Cost, which is only subtractable when both runs are in the same currency. */
export interface CostDelta {
  a: number;
  b: number;
  /** null when the two runs are denominated differently — never a fake zero. */
  delta: number | null;
}

export type LeafStatus = 'changed' | 'added' | 'removed' | 'redacted';

export interface LeafDiff {
  /** Escape-aware leaf path (`tgcanon/2` syntax), e.g. `input.rows[0].user\.id`. */
  path: string;
  status: LeafStatus;
  /** Present unless the leaf is absent on A or was redacted there. */
  a?: unknown;
  /** Present unless the leaf is absent on B or was redacted there. */
  b?: unknown;
  /** Which side's value was destroyed. Set whenever redaction touched the leaf. */
  redactedOn?: 'a' | 'b' | 'both';
}

export interface FieldChange {
  field: 'label' | 'type' | 'toolName';
  a: string | null;
  b: string | null;
}

export type StepDiffKind = 'same' | 'changed' | 'added' | 'removed';

export interface StepDiff {
  kind: StepDiffKind;
  /** True when the step is the same step, at a different position in the run. */
  moved: boolean;
  aIndex: number | null;
  bIndex: number | null;
  aStepId: string | null;
  bStepId: string | null;
  /** Best label for display: B's when the step survives, otherwise A's. */
  label: string;
  type: StepType;
  toolName: string | null;
  fields: FieldChange[];
  tokens: NumericDelta;
  cost: CostDelta;
  durationMs: NumericDelta;
  /** Only differing leaves; unchanged leaves are omitted. */
  leaves: LeafDiff[];
  /** How many leaves could not be compared because a value was redacted. */
  incomparableLeaves: number;
}

export interface ToolDelta {
  toolName: string;
  a: number;
  b: number;
  delta: number;
}

export interface WarningDiff {
  appeared: Warning[];
  cleared: Warning[];
  persisted: Warning[];
}

export interface RunSide {
  id: string;
  name: string;
  status: RunStatus;
  currency: string;
  hashVersion: number;
  runHash: string;
  signed: boolean;
  steps: number;
}

export interface DiffSummary {
  same: number;
  changed: number;
  added: number;
  removed: number;
  moved: number;
  incomparableLeaves: number;
}

export interface RunDiff {
  a: RunSide;
  b: RunSide;
  /** True when nothing observable differs. Says nothing about redacted leaves. */
  equivalent: boolean;
  /** True when every leaf was actually comparable and the rules matched. */
  fullyComparable: boolean;
  caveats: DiffCaveat[];
  currency: { a: string; b: string; same: boolean };
  totals: {
    steps: NumericDelta;
    tokens: NumericDelta;
    cost: CostDelta;
    durationMs: NumericDelta;
  };
  steps: StepDiff[];
  summary: DiffSummary;
  tools: ToolDelta[];
  warnings: WarningDiff;
}

export type DiffOptions = AlignOptions;

/* ── leaf walking ──────────────────────────────────────────────────────────── */

interface DualLeaf {
  /** Unambiguous path used for MATCHING leaves across the two records. */
  path: string;
  /** The same leaf under `tgcanon/1`'s unescaped concatenation. */
  legacyPath: string;
  value: unknown;
}

/**
 * Walk one payload field to its JSON leaves, emitting both path encodings.
 *
 * `redact/commit.ts#walkLeaves` produces one encoding per call and is the
 * PRODUCER side, where the record's own version is authoritative. Diffing is a
 * consumer of two records that may disagree, so it needs both at once: match on
 * the escaped form (which is injective), look commitments up under whichever
 * form that record was written with.
 */
function walkDualLeaves(field: CommittedField, value: unknown): DualLeaf[] {
  const out: DualLeaf[] = [];
  const walk = (node: unknown, path: string, legacyPath: string): void => {
    if (Array.isArray(node)) {
      if (node.length === 0) {
        out.push({ path, legacyPath, value: node });
        return;
      }
      node.forEach((item, i) => walk(item, `${path}[${i}]`, `${legacyPath}[${i}]`));
      return;
    }
    if (node !== null && typeof node === 'object') {
      const keys = Object.keys(node as Record<string, unknown>);
      if (keys.length === 0) {
        out.push({ path, legacyPath, value: node });
        return;
      }
      for (const key of keys) {
        walk(
          (node as Record<string, unknown>)[key],
          `${path}.${escapePathSegment(key)}`,
          `${legacyPath}.${key}`,
        );
      }
      return;
    }
    out.push({ path, legacyPath, value: node });
  };
  walk(value, field, field);
  return out;
}

/**
 * Commitment paths on this step whose value is gone.
 *
 * Three independent signals, unioned deliberately — a diff must err toward
 * "cannot compare" rather than toward inventing a change:
 *   - a committed path whose salt was destroyed (the v0.6 mechanism);
 *   - a path named in the step's redaction log (capture-time scrubbing and
 *     legacy re-chained redaction both record here);
 *   - the redaction marker sitting in the value (a pre-0.6 record redacted
 *     through the legacy path carries no commitments at all).
 */
function redactedPathsOf(step: Step): Set<string> {
  const paths = new Set<string>();
  const salts = step.salts ?? {};
  for (const path of Object.keys(step.commitments ?? {})) {
    if (salts[path] === undefined) paths.add(path);
  }
  for (const record of step.redactions ?? []) paths.add(record.path);
  return paths;
}

/**
 * Encode a leaf for equality testing.
 *
 * `canonicalize(undefined)` returns `undefined`, not a string (SPEC §12.4), so
 * it needs a form of its own. A control character is safe as the sentinel:
 * `tgcanon` escapes every code unit below U+0020 (SPEC §4.3), so no real value
 * can canonicalize to something starting with one.
 */
function encodeLeaf(value: unknown): string {
  return value === undefined ? '\u0000undefined' : canonicalize(value);
}

/* ── step comparison ───────────────────────────────────────────────────────── */

interface SideContext {
  version: number;
  redacted: Set<string>;
}

function isRedactedLeaf(leaf: DualLeaf, ctx: SideContext): boolean {
  if (leaf.value === REDACTED_MARKER) return true;
  return ctx.redacted.has(ctx.version === 2 ? leaf.path : leaf.legacyPath);
}

/** Diff the committed payload fields of two aligned steps. */
function diffPayload(a: Step, ctxA: SideContext, b: Step, ctxB: SideContext): LeafDiff[] {
  const diffs: LeafDiff[] = [];

  for (const field of COMMITTED_FIELDS) {
    const hasA = a[field] !== undefined;
    const hasB = b[field] !== undefined;
    if (!hasA && !hasB) continue;

    const leavesA = hasA ? walkDualLeaves(field, a[field]) : [];
    const leavesB = hasB ? walkDualLeaves(field, b[field]) : [];
    const byPathB = new Map(leavesB.map((leaf) => [leaf.path, leaf]));
    const seen = new Set<string>();

    for (const leafA of leavesA) {
      seen.add(leafA.path);
      const leafB = byPathB.get(leafA.path);
      const redA = isRedactedLeaf(leafA, ctxA);

      if (!leafB) {
        diffs.push({
          path: leafA.path,
          status: 'removed',
          ...(redA ? { redactedOn: 'a' as const } : { a: leafA.value }),
        });
        continue;
      }

      const redB = isRedactedLeaf(leafB, ctxB);
      if (redA || redB) {
        // The defining rule: a destroyed value is NOT evidence of a change.
        diffs.push({
          path: leafA.path,
          status: 'redacted',
          redactedOn: redA && redB ? 'both' : redA ? 'a' : 'b',
          ...(redA ? {} : { a: leafA.value }),
          ...(redB ? {} : { b: leafB.value }),
        });
        continue;
      }
      if (encodeLeaf(leafA.value) !== encodeLeaf(leafB.value)) {
        diffs.push({ path: leafA.path, status: 'changed', a: leafA.value, b: leafB.value });
      }
    }

    for (const leafB of leavesB) {
      if (seen.has(leafB.path)) continue;
      const redB = isRedactedLeaf(leafB, ctxB);
      diffs.push({
        path: leafB.path,
        status: 'added',
        ...(redB ? { redactedOn: 'b' as const } : { b: leafB.value }),
      });
    }
  }

  return diffs;
}

/** Count leaves on one side whose value has been destroyed. */
function countRedactedLeaves(step: Step, ctx: SideContext): number {
  let count = 0;
  for (const field of COMMITTED_FIELDS) {
    if (step[field] === undefined) continue;
    for (const leaf of walkDualLeaves(field, step[field])) {
      if (isRedactedLeaf(leaf, ctx)) count++;
    }
  }
  return count;
}

function delta(a: number, b: number): NumericDelta {
  return { a, b, delta: b - a };
}

function costDelta(a: number, b: number, sameCurrency: boolean): CostDelta {
  return { a, b, delta: sameCurrency ? b - a : null };
}

function sideOf(run: Run): RunSide {
  return {
    id: run.id,
    name: run.name,
    status: run.status,
    currency: run.currency,
    hashVersion: hashVersionOf(run),
    runHash: run.runHash,
    signed: run.signature !== undefined,
    steps: run.steps.length,
  };
}

/* ── the diff ──────────────────────────────────────────────────────────────── */

/**
 * Compare two recorded runs. `a` is the baseline, `b` the candidate; every
 * delta reads "A → B", so a positive cost delta means B got more expensive.
 */
export function diffRuns(a: Run, b: Run, opts: DiffOptions = {}): RunDiff {
  const versionA = hashVersionOf(a);
  const versionB = hashVersionOf(b);
  const ctxA = (step: Step): SideContext => ({
    version: versionA,
    redacted: redactedPathsOf(step),
  });
  const ctxB = (step: Step): SideContext => ({
    version: versionB,
    redacted: redactedPathsOf(step),
  });

  const sameCurrency = a.currency === b.currency;
  const alignment = alignSteps(a.steps, b.steps, opts);

  const steps: StepDiff[] = [];
  const summary: DiffSummary = {
    same: 0,
    changed: 0,
    added: 0,
    removed: 0,
    moved: 0,
    incomparableLeaves: 0,
  };
  /** A-step id -> B-step id, for translating warning step references. */
  const aToB = new Map<string, string>();

  for (const entry of alignment.entries) {
    const stepA = entry.a !== null ? a.steps[entry.a] : undefined;
    const stepB = entry.b !== null ? b.steps[entry.b] : undefined;

    if (stepA && stepB) {
      const sa = ctxA(stepA);
      const sb = ctxB(stepB);
      aToB.set(stepA.id, stepB.id);

      const fields: FieldChange[] = [];
      if (stepA.label !== stepB.label) {
        fields.push({ field: 'label', a: stepA.label, b: stepB.label });
      }
      if (stepA.type !== stepB.type) {
        fields.push({ field: 'type', a: stepA.type, b: stepB.type });
      }
      if ((stepA.toolName ?? null) !== (stepB.toolName ?? null)) {
        fields.push({
          field: 'toolName',
          a: stepA.toolName ?? null,
          b: stepB.toolName ?? null,
        });
      }

      const leaves = diffPayload(stepA, sa, stepB, sb);
      const incomparable = leaves.filter((l) => l.status === 'redacted').length;
      const realLeafChanges = leaves.length - incomparable;
      const tokens = delta(stepA.tokens, stepB.tokens);
      const cost = costDelta(stepA.cost, stepB.cost, sameCurrency);
      const durationMs = delta(stepA.durationMs, stepB.durationMs);

      // Duration is recorded wall-clock and is never stable between two runs of
      // the same agent, so it is reported but does NOT make a step "changed" —
      // otherwise every diff would be 100% changed and the signal would be nil.
      const costMoved = cost.delta === null ? cost.a !== cost.b : cost.delta !== 0;
      const changed = fields.length > 0 || realLeafChanges > 0 || tokens.delta !== 0 || costMoved;

      steps.push({
        kind: changed ? 'changed' : 'same',
        moved: entry.moved,
        aIndex: stepA.index,
        bIndex: stepB.index,
        aStepId: stepA.id,
        bStepId: stepB.id,
        label: stepB.label,
        type: stepB.type,
        toolName: stepB.toolName ?? null,
        fields,
        tokens,
        cost,
        durationMs,
        leaves,
        incomparableLeaves: incomparable,
      });
      if (changed) summary.changed++;
      else summary.same++;
      if (entry.moved) summary.moved++;
      summary.incomparableLeaves += incomparable;
      continue;
    }

    if (stepA) {
      const sa = ctxA(stepA);
      const incomparable = countRedactedLeaves(stepA, sa);
      steps.push({
        kind: 'removed',
        moved: false,
        aIndex: stepA.index,
        bIndex: null,
        aStepId: stepA.id,
        bStepId: null,
        label: stepA.label,
        type: stepA.type,
        toolName: stepA.toolName ?? null,
        fields: [],
        tokens: delta(stepA.tokens, 0),
        cost: costDelta(stepA.cost, 0, sameCurrency),
        durationMs: delta(stepA.durationMs, 0),
        leaves: [],
        incomparableLeaves: incomparable,
      });
      summary.removed++;
      summary.incomparableLeaves += incomparable;
      continue;
    }

    if (stepB) {
      const sb = ctxB(stepB);
      const incomparable = countRedactedLeaves(stepB, sb);
      steps.push({
        kind: 'added',
        moved: false,
        aIndex: null,
        bIndex: stepB.index,
        aStepId: null,
        bStepId: stepB.id,
        label: stepB.label,
        type: stepB.type,
        toolName: stepB.toolName ?? null,
        fields: [],
        tokens: delta(0, stepB.tokens),
        cost: costDelta(0, stepB.cost, sameCurrency),
        durationMs: delta(0, stepB.durationMs),
        leaves: [],
        incomparableLeaves: incomparable,
      });
      summary.added++;
      summary.incomparableLeaves += incomparable;
    }
  }

  /* Tool usage. */
  const toolCounts = (run: Run): Map<string, number> => {
    const counts = new Map<string, number>();
    for (const step of run.steps) {
      if (step.type !== 'tool_call' || step.toolName === undefined) continue;
      counts.set(step.toolName, (counts.get(step.toolName) ?? 0) + 1);
    }
    return counts;
  };
  const countsA = toolCounts(a);
  const countsB = toolCounts(b);
  const tools: ToolDelta[] = [...new Set([...countsA.keys(), ...countsB.keys()])]
    .map((toolName) => {
      const ca = countsA.get(toolName) ?? 0;
      const cb = countsB.get(toolName) ?? 0;
      return { toolName, a: ca, b: cb, delta: cb - ca };
    })
    .sort(
      (x, y) => Math.abs(y.delta) - Math.abs(x.delta) || x.toolName.localeCompare(y.toolName, 'en'),
    );

  /* Warnings, matched through the alignment so shifted indices don't lie. */
  const signature = (warning: Warning, translate: boolean): string => {
    const ids = warning.stepIds.map((id) => (translate ? (aToB.get(id) ?? `?${id}`) : id));
    return `${warning.kind}\u0000${[...ids].sort().join(',')}`;
  };
  const sigB = new Map<string, Warning>();
  for (const w of b.warnings) sigB.set(signature(w, false), w);
  const appeared: Warning[] = [];
  const cleared: Warning[] = [];
  const persisted: Warning[] = [];
  const matchedB = new Set<string>();
  for (const w of a.warnings) {
    const sig = signature(w, true);
    if (sigB.has(sig)) {
      persisted.push(w);
      matchedB.add(sig);
    } else {
      cleared.push(w);
    }
  }
  for (const [sig, w] of sigB) {
    if (!matchedB.has(sig)) appeared.push(w);
  }

  /* Caveats — every reason this comparison is less than complete. */
  const caveats: DiffCaveat[] = [];
  if (versionA !== versionB) {
    caveats.push({
      kind: 'hash-version-mismatch',
      message:
        `These records use different hashing rules (tgcanon/${versionA} vs tgcanon/${versionB}). ` +
        'Leaves are matched under one unambiguous encoding, but tgcanon/1 commitment paths are ' +
        'ambiguous for keys containing "." or "[" (SPEC §12.5), so redaction status for such keys ' +
        'may not resolve on the version-1 side.',
    });
  }
  for (const [label, version] of [
    ['A', versionA],
    ['B', versionB],
  ] as const) {
    if (!isSupportedHashVersion(version)) {
      caveats.push({
        kind: 'unsupported-hash-version',
        message: `Run ${label} declares hashVersion ${version}, which this build does not understand. Its commitment paths were read under version-1 rules; upgrade traceglass rather than trusting this diff.`,
      });
    }
  }
  if (!sameCurrency) {
    caveats.push({
      kind: 'currency-mismatch',
      message: `Run A is denominated in ${a.currency} and run B in ${b.currency}. Cost deltas are withheld rather than computed across currencies.`,
    });
  }
  if (summary.incomparableLeaves > 0) {
    caveats.push({
      kind: 'redacted-leaves',
      message: `${summary.incomparableLeaves} leaf value(s) could not be compared because they were redacted. The commitment survives; the value is gone by design, so no change can be asserted either way.`,
    });
  }
  if (alignment.degraded) {
    caveats.push({
      kind: 'alignment-degraded',
      message:
        'These runs are too long to align by subsequence search; steps were matched by position instead. Insertions may be over-reported as changes.',
    });
  }

  const totals = {
    steps: delta(a.steps.length, b.steps.length),
    tokens: delta(a.totals.tokens, b.totals.tokens),
    cost: costDelta(a.totals.cost, b.totals.cost, sameCurrency),
    durationMs: delta(a.totals.durationMs, b.totals.durationMs),
  };

  const equivalent =
    summary.changed === 0 &&
    summary.added === 0 &&
    summary.removed === 0 &&
    summary.moved === 0 &&
    appeared.length === 0 &&
    cleared.length === 0 &&
    sameCurrency;

  return {
    a: sideOf(a),
    b: sideOf(b),
    equivalent,
    fullyComparable: summary.incomparableLeaves === 0 && versionA === versionB,
    caveats,
    currency: { a: a.currency, b: b.currency, same: sameCurrency },
    totals,
    steps,
    summary,
    tools,
    warnings: { appeared, cleared, persisted },
  };
}
