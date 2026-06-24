/**
 * Model price table for deriving cost from token usage (USD per 1M tokens).
 *
 * Cache rates follow Anthropic's published multipliers relative to the input
 * rate: cache *write* is 1.25x (5-minute TTL) or 2x (1-hour TTL); cache *read*
 * is 0.1x. Prices change over time and vary by provider — this table is a
 * sensible default and is fully overridable via `ingestClaudeCodeSession`.
 */

export interface ModelPrice {
  /** USD per 1M input tokens. */
  input: number;
  /** USD per 1M output tokens. */
  output: number;
}

export type ModelPriceTable = Record<string, ModelPrice>;

/** Cache-write/read multipliers applied to a model's input rate. */
export const CACHE_WRITE_5M_MULTIPLIER = 1.25;
export const CACHE_WRITE_1H_MULTIPLIER = 2;
export const CACHE_READ_MULTIPLIER = 0.1;

/** Default per-model prices (USD / 1M tokens). */
export const DEFAULT_MODEL_PRICES: ModelPriceTable = {
  'claude-fable-5': { input: 10, output: 50 },
  'claude-mythos-5': { input: 10, output: 50 },
  'claude-opus-4-8': { input: 5, output: 25 },
  'claude-opus-4-7': { input: 5, output: 25 },
  'claude-opus-4-6': { input: 5, output: 25 },
  'claude-opus-4-5': { input: 5, output: 25 },
  'claude-sonnet-4-6': { input: 3, output: 15 },
  'claude-sonnet-4-5': { input: 3, output: 15 },
  'claude-haiku-4-5': { input: 1, output: 5 },
};

/** Currency the default price table is denominated in. */
export const DEFAULT_CURRENCY = 'USD';

/**
 * Resolve a price for a model id. Falls back to a prefix match (so dated
 * snapshots like `claude-haiku-4-5-20251001` resolve), then to Opus pricing as
 * a conservative default for unknown current-gen models.
 */
export function priceForModel(model: string | undefined, table: ModelPriceTable): ModelPrice {
  if (model) {
    if (table[model]) return table[model]!;
    const prefixHit = Object.keys(table).find((id) => model.startsWith(id));
    if (prefixHit) return table[prefixHit]!;
  }
  return table['claude-opus-4-8'] ?? { input: 0, output: 0 };
}

/** Token-usage shape carried by each Claude Code assistant message. */
export interface TokenUsage {
  input_tokens?: number;
  output_tokens?: number;
  cache_read_input_tokens?: number;
  cache_creation_input_tokens?: number;
  cache_creation?: {
    ephemeral_5m_input_tokens?: number;
    ephemeral_1h_input_tokens?: number;
  };
}

/** Total tokens processed for a message (input + output + both cache tiers). */
export function totalTokens(usage: TokenUsage | undefined): number {
  if (!usage) return 0;
  return (
    (usage.input_tokens ?? 0) +
    (usage.output_tokens ?? 0) +
    (usage.cache_read_input_tokens ?? 0) +
    (usage.cache_creation_input_tokens ?? 0)
  );
}

/** Cost in the table's currency for a message's usage under a model's price. */
export function costForUsage(usage: TokenUsage | undefined, price: ModelPrice): number {
  if (!usage) return 0;
  const input = usage.input_tokens ?? 0;
  const output = usage.output_tokens ?? 0;
  const cacheRead = usage.cache_read_input_tokens ?? 0;

  // Prefer the explicit 5m/1h breakdown; otherwise treat all cache-creation as 5m.
  const write5m = usage.cache_creation?.ephemeral_5m_input_tokens;
  const write1h = usage.cache_creation?.ephemeral_1h_input_tokens;
  const hasBreakdown = write5m !== undefined || write1h !== undefined;
  const cacheWrite5m = hasBreakdown ? (write5m ?? 0) : (usage.cache_creation_input_tokens ?? 0);
  const cacheWrite1h = hasBreakdown ? (write1h ?? 0) : 0;

  const perToken = price.input / 1_000_000;
  return (
    (input * price.input) / 1_000_000 +
    (output * price.output) / 1_000_000 +
    cacheRead * perToken * CACHE_READ_MULTIPLIER +
    cacheWrite5m * perToken * CACHE_WRITE_5M_MULTIPLIER +
    cacheWrite1h * perToken * CACHE_WRITE_1H_MULTIPLIER
  );
}
