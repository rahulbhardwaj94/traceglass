import { describe, expect, it } from 'vitest';
import type { FleetRun, LiveRecording } from '../types.js';
import {
  DEFAULT_FILTERS,
  applyFilters,
  costOutlierThreshold,
  issuesOf,
  mergeFleet,
  summarize,
  type FleetRow,
} from './fleet.js';

const NOW = Date.parse('2026-07-26T12:00:00.000Z');

function run(over: Partial<FleetRun> = {}): FleetRun {
  return {
    id: 'r1',
    name: 'agent run',
    startedAt: '2026-07-26T11:00:00.000Z',
    endedAt: '2026-07-26T11:01:00.000Z',
    ingestedAt: '2026-07-26T11:01:00.000Z',
    status: 'completed',
    currency: 'USD',
    steps: 5,
    tokens: 100,
    cost: 1,
    durationMs: 1000,
    runHash: 'a'.repeat(64),
    warnings: { loop: 0, high_cost_step: 0, error: 0, total: 0 },
    warningMessages: [],
    signed: true,
    keyId: '0123456789abcdef',
    chainOk: true,
    signatureOk: true,
    integrityMessage: 'ok',
    policyOk: null,
    policyViolations: [],
    ...over,
  };
}

const row = (over: Partial<FleetRun> = {}): FleetRow => ({ ...run(over), live: false });

describe('mergeFleet', () => {
  const live: LiveRecording = {
    runId: 'live-1',
    name: 'slow agent',
    startedAt: '2026-07-26T11:59:00.000Z',
    steps: 3,
    updatedAt: '2026-07-26T11:59:30.000Z',
    ended: false,
  };

  it('adds in-progress recordings alongside sealed runs', () => {
    const rows = mergeFleet([run({ id: 'stored' })], [live]);
    expect(rows.map((r) => r.id)).toEqual(['stored', 'live-1']);
    expect(rows[1]!.live).toBe(true);
    expect(rows[1]!.status).toBe('running');
  });

  it('drops a live entry once the sealed record exists (no ghost duplicate)', () => {
    const rows = mergeFleet([run({ id: 'live-1' })], [live]);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.live).toBe(false);
  });

  it('drops a recording whose journal already ended', () => {
    expect(mergeFleet([], [{ ...live, ended: true }])).toHaveLength(0);
  });

  it('never flags a live recording as unsigned — it has not been sealed yet', () => {
    const [liveRow] = mergeFleet([], [live]);
    expect(issuesOf(liveRow!, Number.POSITIVE_INFINITY)).toEqual([]);
  });
});

describe('costOutlierThreshold', () => {
  it('is 3x the median nonzero run cost', () => {
    const rows = [1, 1, 1, 2, 10].map((cost, i) => row({ id: `r${i}`, cost }));
    expect(costOutlierThreshold(rows)).toBe(3);
  });

  it('refuses to guess from too few data points', () => {
    expect(costOutlierThreshold([row({ cost: 5 })])).toBe(Number.POSITIVE_INFINITY);
    expect(costOutlierThreshold([])).toBe(Number.POSITIVE_INFINITY);
  });

  it('ignores zero-cost runs so a fleet of free runs has no outliers', () => {
    const rows = [0, 0, 0, 0].map((cost, i) => row({ id: `r${i}`, cost }));
    expect(costOutlierThreshold(rows)).toBe(Number.POSITIVE_INFINITY);
  });
});

describe('issuesOf', () => {
  it('reports a broken chain first — the record itself cannot be trusted', () => {
    const issues = issuesOf(row({ chainOk: false, warnings: warn({ loop: 1 }) }), Infinity);
    expect(issues[0]).toBe('tampered');
    expect(issues).toContain('loop');
  });

  it('treats an invalid signature as tampering, not as unsigned', () => {
    const issues = issuesOf(row({ signed: true, signatureOk: false }), Infinity);
    expect(issues).toContain('tampered');
    expect(issues).not.toContain('unsigned');
  });

  it('flags an unsigned sealed run', () => {
    expect(issuesOf(row({ signed: false }), Infinity)).toContain('unsigned');
  });

  it('flags a policy failure and a cost outlier', () => {
    const issues = issuesOf(row({ policyOk: false, cost: 40 }), 10);
    expect(issues).toContain('policy');
    expect(issues).toContain('outlier');
  });

  it('says nothing about policy when no policy is configured', () => {
    expect(issuesOf(row({ policyOk: null }), Infinity)).not.toContain('policy');
  });

  it('treats a failed run as an error even with no warning attached', () => {
    expect(issuesOf(row({ status: 'failed' }), Infinity)).toContain('error');
  });

  it('finds nothing on a clean signed run', () => {
    expect(issuesOf(row(), Infinity)).toEqual([]);
  });
});

function warn(over: Partial<FleetRun['warnings']>): FleetRun['warnings'] {
  const w = { loop: 0, high_cost_step: 0, error: 0, ...over };
  return { ...w, total: w.loop + w.high_cost_step + w.error };
}

describe('applyFilters', () => {
  const rows: FleetRow[] = [
    row({ id: 'clean', name: 'nightly sweep', cost: 1 }),
    row({ id: 'looper', name: 'stuck agent', cost: 1, warnings: warn({ loop: 2 }) }),
    row({ id: 'broke', name: 'failed agent', cost: 1, status: 'failed' }),
    row({ id: 'pricey', name: 'expensive agent', cost: 90 }),
    row({ id: 'raw', name: 'unsigned agent', cost: 1, signed: false }),
  ];

  it('ORs the issue chips so triage sees everything bad at once', () => {
    const got = applyFilters(rows, { ...DEFAULT_FILTERS, issues: ['loop', 'unsigned'] }, NOW);
    expect(got.map((r) => r.id).sort()).toEqual(['looper', 'raw']);
  });

  it('ANDs a status filter with the issue chips', () => {
    const got = applyFilters(
      rows,
      { ...DEFAULT_FILTERS, issues: ['loop', 'error'], status: 'failed' },
      NOW,
    );
    expect(got.map((r) => r.id)).toEqual(['broke']);
  });

  it('finds the cost outlier without being told a threshold', () => {
    const got = applyFilters(rows, { ...DEFAULT_FILTERS, issues: ['outlier'] }, NOW);
    expect(got.map((r) => r.id)).toEqual(['pricey']);
  });

  it('matches text against name and id', () => {
    expect(applyFilters(rows, { ...DEFAULT_FILTERS, text: 'STUCK' }, NOW).map((r) => r.id)).toEqual([
      'looper',
    ]);
    expect(applyFilters(rows, { ...DEFAULT_FILTERS, text: 'pric' }, NOW).map((r) => r.id)).toEqual([
      'pricey',
    ]);
  });

  it('restricts to the run ids a content search returned', () => {
    const got = applyFilters(
      rows,
      { ...DEFAULT_FILTERS, runIds: new Set(['broke', 'raw']) },
      NOW,
    );
    expect(got.map((r) => r.id).sort()).toEqual(['broke', 'raw']);
  });

  it('honours the time window against startedAt', () => {
    const old = row({ id: 'ancient', startedAt: '2026-01-01T00:00:00.000Z' });
    const got = applyFilters([...rows, old], { ...DEFAULT_FILTERS, window: '24h' }, NOW);
    expect(got.map((r) => r.id)).not.toContain('ancient');
    expect(applyFilters([...rows, old], { ...DEFAULT_FILTERS, window: 'all' }, NOW)).toHaveLength(6);
  });

  it('sorts by cost descending when asked', () => {
    const got = applyFilters(rows, { ...DEFAULT_FILTERS, sort: 'cost' }, NOW);
    expect(got[0]!.id).toBe('pricey');
  });

  it('keeps in-progress recordings pinned above any sort order', () => {
    const live: FleetRow = { ...row({ id: 'now', cost: 0, status: 'running' }), live: true };
    const got = applyFilters([...rows, live], { ...DEFAULT_FILTERS, sort: 'cost' }, NOW);
    expect(got[0]!.id).toBe('now');
  });

  it('does not mutate the input array', () => {
    const input = [...rows];
    applyFilters(input, { ...DEFAULT_FILTERS, sort: 'cost' }, NOW);
    expect(input.map((r) => r.id)).toEqual(rows.map((r) => r.id));
  });
});

describe('summarize', () => {
  it('counts the things an incident responder scans for', () => {
    const s = summarize([
      row({ id: 'a', cost: 1 }),
      row({ id: 'b', cost: 2, warnings: warn({ loop: 1 }) }),
      row({ id: 'c', cost: 3, status: 'failed', signed: false }),
      row({ id: 'd', cost: 4, chainOk: false }),
      row({ id: 'e', cost: 5, policyOk: false }),
    ]);
    expect(s.total).toBe(5);
    expect(s.withWarnings).toBe(1);
    expect(s.failed).toBe(1);
    expect(s.unsigned).toBe(1);
    expect(s.tampered).toBe(1);
    expect(s.policyFailed).toBe(1);
    expect(s.cost).toBe(15);
    expect(s.currency).toBe('USD');
  });

  it('refuses to add up mixed currencies', () => {
    const s = summarize([row({ id: 'a', cost: 1 }), row({ id: 'b', cost: 2, currency: 'INR' })]);
    expect(s.currency).toBe('');
    expect(s.cost).toBe(0);
  });
});
