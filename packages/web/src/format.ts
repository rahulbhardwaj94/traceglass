import type { Step, StepType } from './types.js';

export function money(currency: string, n: number): string {
  return `${currency} ${n.toFixed(2)}`;
}

export function durationLabel(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function timeLabel(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

export function stepTypeLabel(type: StepType): string {
  return type.replace(/_/g, ' ');
}

/** Integer with thousands separators. */
export function commas(n: number): string {
  return Math.round(n).toLocaleString('en-US');
}

/** Compact duration with a thin space (ms under 1s, otherwise seconds). */
export function ms(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(2)} s`;
  return `${commas(n)} ms`;
}

const pad = (n: number, l = 2): string => String(n).padStart(l, '0');

/** UTC wall-clock for an ISO timestamp — deterministic for an audit recorder. */
export function clockOf(iso: string): string {
  const d = new Date(iso);
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(
    d.getUTCMilliseconds(),
    3,
  )}`;
}

const TYPE_LABEL: Record<StepType, string> = {
  user_input: 'User input',
  plan: 'Plan',
  tool_call: 'Tool call',
  llm_reasoning: 'LLM reasoning',
  branch: 'Branch',
  final_output: 'Final output',
  error: 'Error',
};

/** Title-cased display label for a step type (design copy). */
export function typeLabel(type: StepType): string {
  return TYPE_LABEL[type] ?? type;
}

/** Pretty-print an arbitrary payload value for display in a <pre>. */
export function pretty(value: unknown): string {
  if (value === undefined) return '';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

/** Accumulate totals across steps[0..index] inclusive. */
export function accumulate(steps: Step[], index: number) {
  let tokens = 0;
  let cost = 0;
  let durationMs = 0;
  for (let i = 0; i <= index && i < steps.length; i++) {
    tokens += steps[i]!.tokens;
    cost += steps[i]!.cost;
    durationMs += steps[i]!.durationMs;
  }
  return { tokens, cost, durationMs, steps: Math.min(index + 1, steps.length) };
}
