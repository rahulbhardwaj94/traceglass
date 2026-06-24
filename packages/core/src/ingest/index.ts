import type { Run } from '../model.js';
import { ingestNative, isNativeFormat } from './native.js';
import { ingestOtel, isOtelFormat } from './otel.js';

export { ingestNative, isNativeFormat } from './native.js';
export { ingestOtel, isOtelFormat } from './otel.js';
export {
  ingestClaudeCodeSession,
  parseClaudeCodeJsonl,
  isClaudeCodeFormat,
  type ClaudeCodeIngestOptions,
} from './claude-code.js';
export {
  discoverSessions,
  findSession,
  readSessionRecords,
  defaultSessionsDir,
  type SessionInfo,
} from './claude-code-sessions.js';
export {
  DEFAULT_MODEL_PRICES,
  type ModelPrice,
  type ModelPriceTable,
} from './model-prices.js';
export type { DraftStep, DraftRunMeta } from './common.js';

export type TraceFormat = 'otel' | 'native';

export function detectFormat(value: unknown): TraceFormat | null {
  if (isOtelFormat(value)) return 'otel';
  if (isNativeFormat(value)) return 'native';
  return null;
}

/** Detect the trace format and ingest accordingly. Throws if unrecognized. */
export function ingestAuto(value: unknown): Run {
  const fmt = detectFormat(value);
  if (fmt === 'otel') return ingestOtel(value);
  if (fmt === 'native') return ingestNative(value);
  throw new Error(
    'Unrecognized trace format: expected OTLP/JSON (resourceSpans) or native traceglass JSON (id + steps).',
  );
}
