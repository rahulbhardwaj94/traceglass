import type { Step } from '../model.js';

/**
 * Step alignment for `diffRuns` (roadmap #14).
 *
 * Index-by-index comparison is useless here: one step inserted at the top of a
 * run reports every later step as "changed", which is exactly the false-alarm
 * failure mode this product cannot afford. So alignment is a diff proper —
 * longest common subsequence over step IDENTITY, with two refinements.
 *
 *   Pass 1  LCS over `type ‖ toolName`. Identity deliberately EXCLUDES the
 *           label and the payload: a step whose arguments changed must align so
 *           the change can be located inside it, and labels carry content (the
 *           Claude Code ingester labels a `user_input` step with the prompt),
 *           so folding them in would make an edited prompt look structural.
 *
 *   Pass 2  Reorder detection. Anything still unpaired but carrying an identity
 *           that also exists unpaired on the other side is a MOVE, not a
 *           delete+insert. Runs before pass 3 so a genuine swap is not reported
 *           as two unrelated edits.
 *
 *   Pass 3  Gap refinement. Inside each region between two pass-1 anchors, a
 *           second LCS over `type` alone pairs up what is left. This is what
 *           turns "removed Tool: search_docs / added Tool: search_web" into
 *           "step 3 changed its tool", while a `plan` opposite a `tool_call`
 *           stays an honest deletion plus insertion.
 *
 * Everything here is pure and index-based; the caller owns interpretation.
 */

/** One aligned position. `a`/`b` are indices into the respective step arrays. */
export interface AlignmentEntry {
  /** Index in run A, or null when the step exists only in B (an insertion). */
  a: number | null;
  /** Index in run B, or null when the step exists only in A (a deletion). */
  b: number | null;
  /** True when the pair is out of sequence — the same step, at a new position. */
  moved: boolean;
}

export interface Alignment {
  entries: AlignmentEntry[];
  /**
   * True when a subsequence search was skipped because the matrix would have
   * been too large and a positional approximation was used instead. Surfaced as
   * a caveat rather than hidden: a degraded alignment can over-report changes.
   */
  degraded: boolean;
}

export interface AlignOptions {
  /**
   * Cap on LCS matrix cells before falling back to positional pairing.
   * Exposed for tests; the default holds ~2000x2000 steps in 16 MiB.
   */
  maxMatrixCells?: number;
}

const DEFAULT_MAX_CELLS = 4_000_000;

/**
 * What makes two steps "the same step" for alignment purposes.
 *
 * U+0000 as the separator, because it cannot occur in a step type and would
 * have to be smuggled into a tool name to forge a collision — and even then the
 * worst outcome is a mis-alignment, never a wrong verdict about integrity.
 */
export function stepIdentity(step: Step): string {
  return `${step.type}\u0000${step.toolName ?? ''}`;
}

interface LcsResult {
  /** Pairs of indices into the two input arrays, increasing in both. */
  pairs: Array<[number, number]>;
  degraded: boolean;
}

/**
 * Longest common subsequence over two key arrays.
 *
 * Common prefix and suffix are stripped first — the overwhelmingly common shape
 * for two runs of the same agent is "identical except in the middle", and that
 * reduces the matrix to nothing. Only the remaining window is searched.
 */
function lcsPairs(a: readonly string[], b: readonly string[], maxCells: number): LcsResult {
  const n = a.length;
  const m = b.length;
  const pairs: Array<[number, number]> = [];

  let lo = 0;
  while (lo < n && lo < m && a[lo] === b[lo]) {
    pairs.push([lo, lo]);
    lo++;
  }
  let hiA = n - 1;
  let hiB = m - 1;
  while (hiA >= lo && hiB >= lo && a[hiA] === b[hiB]) {
    hiA--;
    hiB--;
  }
  const suffix: Array<[number, number]> = [];
  for (let k = 1; k <= n - 1 - hiA; k++) suffix.push([hiA + k, hiB + k]);

  const na = hiA + 1 - lo;
  const nb = hiB + 1 - lo;
  let degraded = false;

  if (na > 0 && nb > 0) {
    if (na * nb > maxCells) {
      // Too big to search honestly. Pair only positions that already agree, so
      // the fallback never invents a match it cannot justify.
      degraded = true;
      const k = Math.min(na, nb);
      for (let i = 0; i < k; i++) {
        if (a[lo + i] === b[lo + i]) pairs.push([lo + i, lo + i]);
      }
    } else {
      const w = nb + 1;
      const dp = new Int32Array((na + 1) * w);
      for (let i = na - 1; i >= 0; i--) {
        for (let j = nb - 1; j >= 0; j--) {
          dp[i * w + j] =
            a[lo + i] === b[lo + j]
              ? (dp[(i + 1) * w + j + 1] ?? 0) + 1
              : Math.max(dp[(i + 1) * w + j] ?? 0, dp[i * w + j + 1] ?? 0);
        }
      }
      let i = 0;
      let j = 0;
      while (i < na && j < nb) {
        if (a[lo + i] === b[lo + j]) {
          pairs.push([lo + i, lo + j]);
          i++;
          j++;
        } else if ((dp[(i + 1) * w + j] ?? 0) >= (dp[i * w + j + 1] ?? 0)) {
          i++;
        } else {
          j++;
        }
      }
    }
  }

  pairs.push(...suffix);
  return { pairs, degraded };
}

/** Align two step sequences. Pure; returns index pairs in reading order. */
export function alignSteps(
  aSteps: readonly Step[],
  bSteps: readonly Step[],
  opts: AlignOptions = {},
): Alignment {
  const maxCells = opts.maxMatrixCells ?? DEFAULT_MAX_CELLS;
  const n = aSteps.length;
  const m = bSteps.length;

  const pairOfA: Array<number | null> = new Array<number | null>(n).fill(null);
  const pairOfB: Array<number | null> = new Array<number | null>(m).fill(null);
  const movedA: boolean[] = new Array<boolean>(n).fill(false);

  const idA = aSteps.map(stepIdentity);
  const idB = bSteps.map(stepIdentity);

  /* Pass 1 — anchors. */
  const anchors = lcsPairs(idA, idB, maxCells);
  let degraded = anchors.degraded;
  for (const [i, j] of anchors.pairs) {
    pairOfA[i] = j;
    pairOfB[j] = i;
  }

  /* Pass 2 — reordered steps. */
  const freeB = new Map<string, number[]>();
  for (let j = 0; j < m; j++) {
    if (pairOfB[j] !== null) continue;
    const key = idB[j] ?? '';
    const bucket = freeB.get(key);
    if (bucket) bucket.push(j);
    else freeB.set(key, [j]);
  }
  for (let i = 0; i < n; i++) {
    if (pairOfA[i] !== null) continue;
    const bucket = freeB.get(idA[i] ?? '');
    if (!bucket || bucket.length === 0) continue;
    const j = bucket.shift()!;
    pairOfA[i] = j;
    pairOfB[j] = i;
    movedA[i] = true;
  }

  /* Pass 3 — gap refinement on step type alone. */
  let prevA = -1;
  let prevB = -1;
  const gaps: Array<{ a0: number; a1: number; b0: number; b1: number }> = [];
  for (const [i, j] of anchors.pairs) {
    gaps.push({ a0: prevA + 1, a1: i, b0: prevB + 1, b1: j });
    prevA = i;
    prevB = j;
  }
  gaps.push({ a0: prevA + 1, a1: n, b0: prevB + 1, b1: m });

  for (const gap of gaps) {
    const ai: number[] = [];
    for (let i = gap.a0; i < gap.a1; i++) if (pairOfA[i] === null) ai.push(i);
    const bj: number[] = [];
    for (let j = gap.b0; j < gap.b1; j++) if (pairOfB[j] === null) bj.push(j);
    if (ai.length === 0 || bj.length === 0) continue;

    const refined = lcsPairs(
      ai.map((i) => aSteps[i]!.type),
      bj.map((j) => bSteps[j]!.type),
      maxCells,
    );
    if (refined.degraded) degraded = true;
    for (const [x, y] of refined.pairs) {
      const i = ai[x]!;
      const j = bj[y]!;
      pairOfA[i] = j;
      pairOfB[j] = i;
    }
  }

  /* Emission — anchored on A's order, with B-only steps slotted in place. */
  const entries: AlignmentEntry[] = [];
  const doneA = new Set<number>();
  const doneB = new Set<number>();
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && doneA.has(i)) {
      i++;
      continue;
    }
    if (j < m && doneB.has(j)) {
      j++;
      continue;
    }
    if (i >= n) {
      entries.push({ a: null, b: j, moved: false });
      doneB.add(j);
      j++;
      continue;
    }
    const pa = pairOfA[i] ?? null;
    if (j >= m) {
      entries.push({ a: i, b: pa, moved: pa !== null });
      doneA.add(i);
      if (pa !== null) doneB.add(pa);
      i++;
      continue;
    }
    if (pa === j) {
      entries.push({ a: i, b: j, moved: movedA[i] === true });
      doneA.add(i);
      doneB.add(j);
      i++;
      j++;
      continue;
    }
    if (pa === null) {
      entries.push({ a: i, b: null, moved: false });
      doneA.add(i);
      i++;
      continue;
    }
    if (pairOfB[j] === null) {
      entries.push({ a: null, b: j, moved: false });
      doneB.add(j);
      j++;
      continue;
    }
    // Both cursors point at paired steps that are not each other's partner:
    // a reorder. Emit A's pair here and consume its counterpart.
    entries.push({ a: i, b: pa, moved: true });
    doneA.add(i);
    doneB.add(pa);
    i++;
  }

  return { entries, degraded };
}
