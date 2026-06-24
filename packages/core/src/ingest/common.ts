import type { Run, RunStatus, RunTotals, Step, StepType } from '../model.js';

/**
 * A step as produced by an ingester, before the integrity hash chain and
 * analysis warnings are attached. Carries everything except hash/prevHash,
 * which the integrity pipeline computes (PRD §6), and runId/index, which
 * assembly assigns from ordering.
 */
export interface DraftStep {
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

export interface DraftRunMeta {
  id: string;
  name: string;
  currency: string;
  /** Optional explicit status; otherwise derived from presence of error steps. */
  status?: RunStatus;
}

function computeTotals(steps: Step[]): RunTotals {
  return steps.reduce<RunTotals>(
    (acc, s) => ({
      tokens: acc.tokens + s.tokens,
      cost: acc.cost + s.cost,
      durationMs: acc.durationMs + s.durationMs,
      steps: acc.steps + 1,
    }),
    { tokens: 0, cost: 0, durationMs: 0, steps: 0 },
  );
}

/**
 * Assemble draft steps + metadata into a structurally-complete Run.
 *
 * Steps are ordered by `startedAt` (stable), then assigned index/runId.
 * Hash fields are left empty here — the integrity pipeline (§6) fills them.
 * Warnings are left empty — the analysis pipeline attaches them.
 */
export function assembleRun(meta: DraftRunMeta, drafts: DraftStep[]): Run {
  const ordered = [...drafts].sort((a, b) => {
    const t = Date.parse(a.startedAt) - Date.parse(b.startedAt);
    return t !== 0 ? t : 0;
  });

  const steps: Step[] = ordered.map((d, index) => ({
    id: `${meta.id}:${index}`,
    runId: meta.id,
    index,
    type: d.type,
    label: d.label,
    startedAt: d.startedAt,
    durationMs: d.durationMs,
    tokens: d.tokens,
    cost: d.cost,
    ...(d.toolName !== undefined ? { toolName: d.toolName } : {}),
    ...(d.input !== undefined ? { input: d.input } : {}),
    ...(d.output !== undefined ? { output: d.output } : {}),
    ...(d.dataPayload !== undefined ? { dataPayload: d.dataPayload } : {}),
    spanId: d.spanId,
    ...(d.parentSpanId !== undefined ? { parentSpanId: d.parentSpanId } : {}),
    hash: '',
    prevHash: '',
  }));

  const startedAt = steps.length > 0 ? steps[0]!.startedAt : new Date(0).toISOString();
  const lastStep = steps.length > 0 ? steps[steps.length - 1]! : undefined;
  const endedAt = lastStep
    ? new Date(Date.parse(lastStep.startedAt) + lastStep.durationMs).toISOString()
    : startedAt;

  const hasError = steps.some((s) => s.type === 'error');
  const status: RunStatus = meta.status ?? (hasError ? 'failed' : 'completed');

  return {
    id: meta.id,
    name: meta.name,
    startedAt,
    endedAt,
    status,
    currency: meta.currency,
    totals: computeTotals(steps),
    warnings: [],
    steps,
    runHash: '',
  };
}
