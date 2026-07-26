// Fleet triage logic (v0.10) — kept pure and separate from the component so
// "which of these went wrong?" is testable without a DOM. Everything here is a
// view over what /api/fleet and /api/live already returned; nothing is guessed.

import type { FleetRun, LiveRecording } from '../types.js';

/**
 * A row in the fleet list: a sealed run from the store, or an in-progress
 * recording still being written to its journal. Both belong here — a fleet
 * view that only shows finished runs hides the ones you can still stop.
 */
export interface FleetRow extends FleetRun {
  /** True for a recording still in progress (reconstructed from /api/live). */
  live: boolean;
}

/** The things that make a run worth looking at first. */
export type IssueKey =
  | 'loop'
  | 'high_cost'
  | 'error'
  | 'policy'
  | 'outlier'
  | 'unsigned'
  | 'tampered';

export type StatusKey = 'all' | 'running' | 'completed' | 'failed';
export type SortKey = 'recent' | 'cost' | 'steps' | 'duration' | 'warnings' | 'name';
export type WindowKey = 'all' | '1h' | '24h' | '7d' | '30d';

export interface FleetFilters {
  /** Free text over run name + id. */
  text: string;
  status: StatusKey;
  /** Any-of: a run matches when it carries at least one selected issue. */
  issues: IssueKey[];
  window: WindowKey;
  sort: SortKey;
  /** Restrict to these run ids (a cross-run content search); null = no restriction. */
  runIds: Set<string> | null;
}

export const DEFAULT_FILTERS: FleetFilters = {
  text: '',
  status: 'all',
  issues: [],
  window: 'all',
  sort: 'recent',
  runIds: null,
};

const WINDOW_MS: Record<Exclude<WindowKey, 'all'>, number> = {
  '1h': 3_600_000,
  '24h': 86_400_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
};

/**
 * Lift an in-progress recording into a fleet row.
 *
 * Its integrity fields are deliberately optimistic-but-empty rather than
 * alarming: a live run has no runHash, no signature and no policy verdict yet
 * because it has not been sealed — that is not the same as failing, and
 * flagging it as unsigned would cry wolf on every running agent.
 */
export function rowFromLive(rec: LiveRecording): FleetRow {
  return {
    id: rec.runId,
    name: rec.name,
    startedAt: rec.startedAt,
    endedAt: rec.updatedAt,
    ingestedAt: rec.updatedAt,
    status: 'running',
    currency: '',
    steps: rec.steps,
    tokens: 0,
    cost: 0,
    durationMs: 0,
    runHash: '',
    warnings: { loop: 0, high_cost_step: 0, error: 0, total: 0 },
    warningMessages: [],
    signed: false,
    keyId: null,
    chainOk: true,
    signatureOk: true,
    integrityMessage: 'Recording in progress — not yet sealed.',
    policyOk: null,
    policyViolations: [],
    live: true,
  };
}

/**
 * Merge stored runs with in-progress recordings, stored wins.
 *
 * A recording that finalized between the two fetches appears in both lists;
 * the sealed record is the authoritative one, so the live entry is dropped
 * rather than shown as a duplicate ghost still "recording".
 */
export function mergeFleet(stored: FleetRun[], live: LiveRecording[]): FleetRow[] {
  const rows: FleetRow[] = stored.map((r) => ({ ...r, live: false }));
  const known = new Set(stored.map((r) => r.id));
  for (const rec of live) {
    if (known.has(rec.runId) || rec.ended) continue;
    rows.push(rowFromLive(rec));
  }
  return rows;
}

/**
 * Cost above which a run counts as an outlier: 3× the median nonzero run cost.
 * Mirrors the per-step high-cost rule the single-run view already uses, so the
 * two screens agree about what "expensive" means. Returns Infinity when there
 * is nothing to compare against — better no flag than a meaningless one.
 */
export function costOutlierThreshold(rows: FleetRow[]): number {
  const costs = rows
    .filter((r) => !r.live)
    .map((r) => r.cost)
    .filter((c) => c > 0)
    .sort((a, b) => a - b);
  if (costs.length < 3) return Number.POSITIVE_INFINITY;
  const mid = Math.floor(costs.length / 2);
  const median = costs.length % 2 ? costs[mid]! : (costs[mid - 1]! + costs[mid]!) / 2;
  return median > 0 ? median * 3 : Number.POSITIVE_INFINITY;
}

/** Every issue this row carries, in severity order. */
export function issuesOf(row: FleetRow, outlierAt: number): IssueKey[] {
  const issues: IssueKey[] = [];
  // A broken chain outranks everything: the record itself cannot be trusted.
  if (!row.chainOk || !row.signatureOk) issues.push('tampered');
  if (row.policyOk === false) issues.push('policy');
  if (row.warnings.error > 0 || row.status === 'failed') issues.push('error');
  if (row.warnings.loop > 0) issues.push('loop');
  if (row.warnings.high_cost_step > 0) issues.push('high_cost');
  if (row.cost > outlierAt) issues.push('outlier');
  // Only a sealed run can be meaningfully unsigned.
  if (!row.live && !row.signed) issues.push('unsigned');
  return issues;
}

/** Highest-severity issue on the row, or null for a clean run. */
export function worstIssue(issues: IssueKey[]): IssueKey | null {
  return issues[0] ?? null;
}

function matchesText(row: FleetRow, text: string): boolean {
  const q = text.trim().toLowerCase();
  if (!q) return true;
  return row.name.toLowerCase().includes(q) || row.id.toLowerCase().includes(q);
}

function withinWindow(row: FleetRow, window: WindowKey, now: number): boolean {
  if (window === 'all') return true;
  const at = Date.parse(row.startedAt);
  if (!Number.isFinite(at)) return true; // never hide a run over an unparsable date
  return now - at <= WINDOW_MS[window];
}

const SORTERS: Record<SortKey, (a: FleetRow, b: FleetRow) => number> = {
  recent: (a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt),
  cost: (a, b) => b.cost - a.cost,
  steps: (a, b) => b.steps - a.steps,
  duration: (a, b) => b.durationMs - a.durationMs,
  warnings: (a, b) => b.warnings.total - a.warnings.total,
  name: (a, b) => a.name.localeCompare(b.name),
};

/**
 * Apply the filter bar. Facets are ANDed with each other; the issue chips are
 * ORed among themselves, because triage asks "show me anything bad", not
 * "show me runs that are simultaneously looping and unsigned".
 */
export function applyFilters(
  rows: FleetRow[],
  filters: FleetFilters,
  now: number = Date.now(),
): FleetRow[] {
  const outlierAt = costOutlierThreshold(rows);
  const wanted = new Set(filters.issues);
  const kept = rows.filter((row) => {
    if (filters.status !== 'all' && row.status !== filters.status) return false;
    if (!matchesText(row, filters.text)) return false;
    if (!withinWindow(row, filters.window, now)) return false;
    if (filters.runIds && !filters.runIds.has(row.id)) return false;
    if (wanted.size > 0) {
      const issues = issuesOf(row, outlierAt);
      if (!issues.some((i) => wanted.has(i))) return false;
    }
    return true;
  });
  // Live rows first regardless of sort — they are the only ones you can still
  // intervene in, and burying them under a cost sort defeats the purpose.
  return kept.sort((a, b) => {
    if (a.live !== b.live) return a.live ? -1 : 1;
    return SORTERS[filters.sort](a, b);
  });
}

/** Headline counters for the summary strip. */
export interface FleetSummary {
  total: number;
  live: number;
  failed: number;
  withWarnings: number;
  policyFailed: number;
  unsigned: number;
  tampered: number;
  cost: number;
  /** Currency of the totalled cost, or '' when runs disagree (then cost is 0). */
  currency: string;
}

export function summarize(rows: FleetRow[]): FleetSummary {
  const outlierAt = costOutlierThreshold(rows);
  const currencies = new Set(rows.filter((r) => !r.live && r.currency).map((r) => r.currency));
  const mixed = currencies.size > 1;
  let summary: FleetSummary = {
    total: rows.length,
    live: 0,
    failed: 0,
    withWarnings: 0,
    policyFailed: 0,
    unsigned: 0,
    tampered: 0,
    cost: 0,
    currency: mixed ? '' : ([...currencies][0] ?? ''),
  };
  for (const row of rows) {
    const issues = new Set(issuesOf(row, outlierAt));
    summary = {
      ...summary,
      live: summary.live + (row.live ? 1 : 0),
      failed: summary.failed + (row.status === 'failed' ? 1 : 0),
      withWarnings: summary.withWarnings + (row.warnings.total > 0 ? 1 : 0),
      policyFailed: summary.policyFailed + (issues.has('policy') ? 1 : 0),
      unsigned: summary.unsigned + (issues.has('unsigned') ? 1 : 0),
      tampered: summary.tampered + (issues.has('tampered') ? 1 : 0),
      cost: mixed ? 0 : summary.cost + row.cost,
    };
  }
  return summary;
}
