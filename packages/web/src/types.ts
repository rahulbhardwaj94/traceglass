// Browser-side mirror of the @traceglass/core data model (PRD §3). Kept as a
// standalone copy so the web bundle never imports the Node-only core engine
// (which pulls in better-sqlite3). The shapes must match the API responses.

export type StepType =
  | 'user_input'
  | 'plan'
  | 'tool_call'
  | 'llm_reasoning'
  | 'branch'
  | 'approval'
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
  status: 'completed' | 'failed' | 'running';
  /** Present on live (in-progress) runs served from /api/live. */
  live?: boolean;
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

/* ---- fleet view (v0.10) — mirrors the /api/fleet response in the CLI ---- */

export interface FleetWarnings {
  loop: number;
  high_cost_step: number;
  error: number;
  total: number;
}

/** One triage row: enough to spot a bad run without loading it. */
export interface FleetRun {
  id: string;
  name: string;
  startedAt: string;
  endedAt: string;
  ingestedAt: string;
  status: Run['status'];
  currency: string;
  steps: number;
  tokens: number;
  cost: number;
  durationMs: number;
  runHash: string;
  warnings: FleetWarnings;
  warningMessages: string[];
  signed: boolean;
  keyId: string | null;
  chainOk: boolean;
  signatureOk: boolean;
  integrityMessage: string;
  /** null when the server has no guardrail policy configured. */
  policyOk: boolean | null;
  policyViolations: Array<{ rule: string; message: string }>;
}

export interface FleetPolicyInfo {
  configured: boolean;
  name: string | null;
  source: 'inline' | 'env' | 'home' | null;
  error: string | null;
}

export interface FleetResponse {
  runs: FleetRun[];
  policy: FleetPolicyInfo;
  generatedAt: string;
}

/** An in-progress recording (mirror of @traceglass/core LiveRecording). */
export interface LiveRecording {
  runId: string;
  name: string;
  startedAt: string;
  steps: number;
  updatedAt: string;
  ended: boolean;
}

/** One step-level hit from /api/search (mirror of core's SearchHit). */
export interface SearchHit {
  runId: string;
  runName: string;
  stepId: string;
  stepIndex: number;
  stepType: StepType;
  label: string;
  snippet: string;
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
