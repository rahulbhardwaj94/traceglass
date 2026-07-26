import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { FleetPolicyInfo, SearchHit } from '../types.js';
import { api } from '../api.js';
import { commas, ms, relTime } from '../format.js';
import {
  DEFAULT_FILTERS,
  applyFilters,
  costOutlierThreshold,
  issuesOf,
  mergeFleet,
  summarize,
  type FleetFilters,
  type FleetRow,
  type IssueKey,
  type SortKey,
  type StatusKey,
  type WindowKey,
} from '../lib/fleet.js';
import { Icon, type IconName } from './Icon.js';

/**
 * How often the fleet re-reads the store and the live journals.
 *
 * Slower than the single-run tail (LIVE_POLL_MS): a list is scanned, not
 * watched frame by frame, and /api/fleet re-verifies hash chains. The server
 * memoizes each row by its run hash, so a steady poll costs a listing query.
 */
const FLEET_POLL_MS = 4000;

const ISSUE_META: Record<IssueKey, { label: string; icon: IconName; title: string }> = {
  tampered: {
    label: 'Tampered',
    icon: 'alert',
    title: 'The stored record does not match its own hash chain or signature.',
  },
  policy: { label: 'Policy', icon: 'policy', title: 'Violates the configured guardrail policy.' },
  error: { label: 'Error', icon: 'alert', title: 'The run failed or recorded an error step.' },
  loop: { label: 'Loop', icon: 'loop', title: 'The agent repeated the same action.' },
  high_cost: { label: 'High-cost step', icon: 'cost', title: 'A single step cost far above median.' },
  outlier: { label: 'Cost outlier', icon: 'cost', title: 'Run cost is over 3x the fleet median.' },
  unsigned: { label: 'Unsigned', icon: 'unsigned', title: 'No Ed25519 signature over the anchor.' },
};

/** Chip order in the filter bar — most severe first, same as issuesOf(). */
const ISSUE_ORDER: IssueKey[] = [
  'tampered',
  'policy',
  'error',
  'loop',
  'high_cost',
  'outlier',
  'unsigned',
];

const STATUS_OPTIONS: Array<{ value: StatusKey; label: string }> = [
  { value: 'all', label: 'Any status' },
  { value: 'running', label: 'Recording' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
];

const WINDOW_OPTIONS: Array<{ value: WindowKey; label: string }> = [
  { value: 'all', label: 'All time' },
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24h' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
];

const SORT_OPTIONS: Array<{ value: SortKey; label: string }> = [
  { value: 'recent', label: 'Most recent' },
  { value: 'cost', label: 'Highest cost' },
  { value: 'warnings', label: 'Most warnings' },
  { value: 'steps', label: 'Most steps' },
  { value: 'duration', label: 'Longest' },
  { value: 'name', label: 'Name' },
];

/** Where a row leads: the sealed replay, or the live tail. */
function hrefFor(row: FleetRow): string {
  return row.live
    ? `?live=${encodeURIComponent(row.id)}`
    : `?run=${encodeURIComponent(row.id)}`;
}

function money(currency: string, n: number): string {
  return currency ? `${currency} ${n.toFixed(2)}` : n.toFixed(2);
}

export function FleetView() {
  const [rows, setRows] = useState<FleetRow[] | null>(null);
  const [policy, setPolicy] = useState<FleetPolicyInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<FleetFilters>(DEFAULT_FILTERS);
  const [deep, setDeep] = useState(false);
  const [hits, setHits] = useState<SearchHit[] | null>(null);
  const [searching, setSearching] = useState(false);
  const textRef = useRef('');
  textRef.current = filters.text;

  const load = useCallback(async (): Promise<void> => {
    // The two reads are independent: a store with no live journals and a
    // journal directory with no store are both normal.
    const [fleet, live] = await Promise.all([api.fleet(), api.liveRuns().catch(() => [])]);
    setRows(mergeFleet(fleet.runs, live));
    setPolicy(fleet.policy);
    setError(null);
  }, []);

  /*
   * Poll while the tab is visible. A backgrounded dashboard has no reader to
   * serve and re-verifying every hash chain for nobody is pure waste — but the
   * FIRST load must happen regardless of visibility, because a tab opened in
   * the background (or restored from a session) starts hidden and would
   * otherwise sit on "Loading fleet…" until someone clicked it.
   */
  useEffect(() => {
    let cancelled = false;
    let loadedOnce = false;
    let timer = 0;
    const refresh = async () => {
      try {
        await load();
        loadedOnce = true;
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    };
    const tick = async () => {
      if (!document.hidden || !loadedOnce) await refresh();
      if (!cancelled) timer = window.setTimeout(() => void tick(), FLEET_POLL_MS);
    };
    // Coming back to a stale tab should show current data now, not in 4s.
    const onVisible = () => {
      if (!document.hidden && !cancelled) void refresh();
    };
    document.addEventListener('visibilitychange', onVisible);
    void tick();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [load]);

  const matchedIds = useMemo(
    () => (hits ? new Set(hits.map((h) => h.runId)) : null),
    [hits],
  );

  const effective = useMemo<FleetFilters>(
    () => ({ ...filters, runIds: matchedIds }),
    [filters, matchedIds],
  );

  const all = useMemo(() => rows ?? [], [rows]);
  const visible = useMemo(() => applyFilters(all, effective), [all, effective]);
  const summary = useMemo(() => summarize(all), [all]);
  const outlierAt = useMemo(() => costOutlierThreshold(all), [all]);

  const setFilter = useCallback(<K extends keyof FleetFilters>(key: K, value: FleetFilters[K]) => {
    setFilters((f) => ({ ...f, [key]: value }));
  }, []);

  const toggleIssue = useCallback((issue: IssueKey) => {
    setFilters((f) => ({
      ...f,
      issues: f.issues.includes(issue)
        ? f.issues.filter((i) => i !== issue)
        : [...f.issues, issue],
    }));
  }, []);

  const runDeepSearch = useCallback(async () => {
    const q = textRef.current.trim();
    if (!q) {
      setHits(null);
      return;
    }
    setSearching(true);
    try {
      setHits(await api.search(q));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSearching(false);
    }
  }, []);

  const clearAll = useCallback(() => {
    setFilters(DEFAULT_FILTERS);
    setHits(null);
    setDeep(false);
  }, []);

  const filtered = visible.length !== all.length;

  return (
    <div className="fleet">
      <header className="fleet-head">
        <div className="brand">
          <span className="wordmark">traceglass</span>
          <span className="tag">fleet</span>
        </div>
        <div className="fleet-headright">
          {policy && <PolicyChip policy={policy} />}
          <a className="fleet-link" href="?picker=1">
            Ingest a session <Icon name="fwd" size={14} />
          </a>
        </div>
      </header>

      <p className="fleet-sub">
        Every run this collector holds, scored for triage. Warnings, guardrail
        violations, cost outliers and unsigned records are on the row — nothing
        that matters is a click away.
      </p>

      {error && <p className="msg-error fleet-err">{error}</p>}
      {policy?.error && <p className="msg-error fleet-err">Policy not loaded: {policy.error}</p>}

      <Summary summary={summary} />

      <div className="fleet-controls">
        <div className="fl-searchbox">
          <span className="fl-searchico">
            <Icon name="search" size={15} />
          </span>
          <input
            className="fl-search"
            type="search"
            value={filters.text}
            placeholder={deep ? 'Search step contents, then press Enter…' : 'Filter by run name or id…'}
            aria-label="Filter runs"
            onChange={(e) => {
              setFilter('text', e.target.value);
              // A stale hit set would silently contradict the box.
              if (hits) setHits(null);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && deep) void runDeepSearch();
            }}
          />
          <button
            className={'fl-deep' + (deep ? ' on' : '')}
            type="button"
            aria-pressed={deep}
            title="Search inside step inputs, outputs and data payloads across every run"
            onClick={() => {
              const next = !deep;
              setDeep(next);
              if (!next) setHits(null);
              else void runDeepSearch();
            }}
          >
            {searching ? 'searching…' : 'step contents'}
          </button>
        </div>

        <select
          className="fl-select"
          aria-label="Status"
          value={filters.status}
          onChange={(e) => setFilter('status', e.target.value as StatusKey)}
        >
          {STATUS_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>

        <select
          className="fl-select"
          aria-label="Time range"
          value={filters.window}
          onChange={(e) => setFilter('window', e.target.value as WindowKey)}
        >
          {WINDOW_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>

        <select
          className="fl-select"
          aria-label="Sort by"
          value={filters.sort}
          onChange={(e) => setFilter('sort', e.target.value as SortKey)}
        >
          {SORT_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>

      <div className="fleet-chips">
        {ISSUE_ORDER.map((issue) => {
          const on = filters.issues.includes(issue);
          const meta = ISSUE_META[issue];
          return (
            <button
              key={issue}
              type="button"
              aria-pressed={on}
              title={meta.title}
              className={'fl-chip ' + issue + (on ? ' on' : '')}
              onClick={() => toggleIssue(issue)}
            >
              <Icon name={meta.icon} size={13} />
              {meta.label}
            </button>
          );
        })}
      </div>

      <div className="fleet-band">
        <span className="fl-count mono">
          {visible.length} of {all.length} run{all.length === 1 ? '' : 's'}
        </span>
        {hits && (
          <span className="fl-hits mono">
            {hits.length} step match{hits.length === 1 ? '' : 'es'} in {matchedIds?.size ?? 0} run
            {matchedIds?.size === 1 ? '' : 's'}
          </span>
        )}
        {(filtered || hits) && (
          <button className="fl-clear" type="button" onClick={clearAll}>
            Clear filters
          </button>
        )}
      </div>

      {rows === null && !error && <p className="msg-muted">Loading fleet…</p>}
      {rows !== null && all.length === 0 && (
        <p className="msg-muted">
          No runs recorded yet. Record one with the SDK, POST a trace to{' '}
          <span className="mono">/api/ingest</span>, or{' '}
          <a className="fleet-inline" href="?picker=1">
            ingest a Claude Code session
          </a>
          .
        </p>
      )}
      {rows !== null && all.length > 0 && visible.length === 0 && (
        <p className="msg-muted">No run matches these filters.</p>
      )}

      <ul className="fleet-list">
        {visible.map((row) => (
          <FleetRowItem key={row.id} row={row} outlierAt={outlierAt} />
        ))}
      </ul>
    </div>
  );
}

function PolicyChip({ policy }: { policy: FleetPolicyInfo }) {
  if (!policy.configured) {
    return (
      <span
        className="fl-policychip off"
        title="No guardrail policy configured. Set TRACEGLASS_POLICY, or drop a policy.json in your traceglass home, to score every run against it."
      >
        <Icon name="policy" size={13} /> No policy
      </span>
    );
  }
  return (
    <span
      className={'fl-policychip' + (policy.error ? ' bad' : ' on')}
      title={policy.error ?? `Runs are scored against this policy (${policy.source}).`}
    >
      <Icon name="policy" size={13} /> {policy.name ?? 'Policy'}
    </span>
  );
}

function Summary({ summary }: { summary: ReturnType<typeof summarize> }) {
  const tiles: Array<{ label: string; value: string; tone?: string }> = [
    { label: 'Runs', value: commas(summary.total) },
    ...(summary.live > 0
      ? [{ label: 'Recording', value: commas(summary.live), tone: 'live' }]
      : []),
    { label: 'With warnings', value: commas(summary.withWarnings), tone: summary.withWarnings ? 'warn' : '' },
    { label: 'Failed', value: commas(summary.failed), tone: summary.failed ? 'err' : '' },
    {
      label: 'Policy violations',
      value: commas(summary.policyFailed),
      tone: summary.policyFailed ? 'err' : '',
    },
    { label: 'Unsigned', value: commas(summary.unsigned), tone: summary.unsigned ? 'warn' : '' },
    ...(summary.tampered > 0
      ? [{ label: 'Tampered', value: commas(summary.tampered), tone: 'err' }]
      : []),
    { label: 'Total cost', value: summary.currency ? money(summary.currency, summary.cost) : '—' },
  ];
  return (
    <div className="fleet-summary">
      {tiles.map((t) => (
        <div key={t.label} className={'fl-tile ' + (t.tone ?? '')}>
          <span className="fl-tile-v mono">{t.value}</span>
          <span className="fl-tile-l">{t.label}</span>
        </div>
      ))}
    </div>
  );
}

function FleetRowItem({ row, outlierAt }: { row: FleetRow; outlierAt: number }) {
  const issues = issuesOf(row, outlierAt);
  const subtitle = row.live
    ? 'Recording in progress'
    : row.policyViolations[0]?.message ?? row.warningMessages[0] ?? row.integrityMessage;

  return (
    <li>
      <a className={'fl-row' + (issues.length ? ' flagged' : '')} href={hrefFor(row)}>
        <span className={'fl-led ' + row.status} />

        <span className="fl-main">
          <span className="fl-title">{row.name || row.id}</span>
          <span className="fl-sub">{subtitle}</span>
          <span className="fl-flags">
            {issues.map((issue) => (
              <span key={issue} className={'fl-flag ' + issue} title={ISSUE_META[issue].title}>
                <Icon name={ISSUE_META[issue].icon} size={12} />
                {ISSUE_META[issue].label}
                {issue === 'loop' && row.warnings.loop > 1 ? ` ×${row.warnings.loop}` : ''}
                {issue === 'high_cost' && row.warnings.high_cost_step > 1
                  ? ` ×${row.warnings.high_cost_step}`
                  : ''}
              </span>
            ))}
            {issues.length === 0 && !row.live && (
              <span className="fl-flag clean" title={row.integrityMessage}>
                <Icon name="shield" size={12} /> Verified
              </span>
            )}
          </span>
        </span>

        <span className="fl-stats mono">
          <span className="fl-stat">
            <b>{commas(row.steps)}</b> steps
          </span>
          <span className="fl-stat">
            <b>{row.live ? '—' : money(row.currency, row.cost)}</b>
          </span>
          <span className="fl-stat">{row.live ? 'live' : ms(row.durationMs)}</span>
        </span>

        <span className="fl-when">
          <span className="fl-age mono">{relTime(row.live ? row.endedAt : row.startedAt)}</span>
          <span className="fl-id mono">{row.id}</span>
        </span>

        <span className="fl-go">
          <Icon name="fwd" size={16} />
        </span>
      </a>
    </li>
  );
}
