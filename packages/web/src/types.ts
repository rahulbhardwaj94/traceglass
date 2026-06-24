// Browser-side mirror of the @traceglass/core data model (PRD §3). Kept as a
// standalone copy so the web bundle never imports the Node-only core engine
// (which pulls in better-sqlite3). The shapes must match the API responses.

export type StepType =
  | 'user_input'
  | 'plan'
  | 'tool_call'
  | 'llm_reasoning'
  | 'branch'
  | 'final_output'
  | 'error';

export interface Step {
  id: string;
  runId: string;
  index: number;
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
  hash: string;
  prevHash: string;
}

export interface RunTotals {
  tokens: number;
  cost: number;
  durationMs: number;
  steps: number;
}

export type WarningKind = 'loop' | 'high_cost_step' | 'error';

export interface Warning {
  kind: WarningKind;
  message: string;
  stepIds: string[];
}

export interface Run {
  id: string;
  name: string;
  startedAt: string;
  endedAt: string;
  status: 'completed' | 'failed';
  currency: string;
  totals: RunTotals;
  warnings: Warning[];
  steps: Step[];
  runHash: string;
}

export interface VerifyResult {
  ok: boolean;
  brokenStepIndex: number | null;
  brokenStepId: string | null;
  message: string;
  expectedRunHash: string;
  storedRunHash: string;
}

export interface RunSummary {
  id: string;
  name: string;
  startedAt: string;
  status: Run['status'];
  steps: number;
  cost: number;
  currency: string;
  runHash: string;
}

/** A discovered Claude Code session (mirror of @traceglass/core SessionInfo). */
export interface SessionInfo {
  id: string;
  file: string;
  project: string;
  startedAt: string;
  endedAt: string;
  messageCount: number;
  firstPrompt: string;
}
