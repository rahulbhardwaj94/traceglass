import type { Run } from '../model.js';
import { assembleRun, type DraftRunMeta, type DraftStep } from './common.js';
import {
  DEFAULT_CURRENCY,
  DEFAULT_MODEL_PRICES,
  costForUsage,
  priceForModel,
  totalTokens,
  type ModelPriceTable,
  type TokenUsage,
} from './model-prices.js';

/**
 * Claude Code session-JSONL ingester.
 *
 * Claude Code persists each session as newline-delimited JSON under
 * `~/.claude/projects/**`. This maps that log onto the existing traceglass
 * Run/Step model — no model changes. We port the minimal parse here rather than
 * depending on the `inspecto` package (3k+ downloads), which is the reference
 * implementation for reading these logs; this avoids version coupling.
 *
 * Mapping (PRD v0.2):
 *   user (string)        -> user_input
 *   assistant thinking   -> llm_reasoning
 *   assistant text       -> llm_reasoning (final assistant text -> final_output)
 *   assistant tool_use   -> tool_call (+ toolName, input)
 *   user  tool_result    -> attached to the matching tool_call as output;
 *                           the structured toolUseResult becomes dataPayload
 * Token usage per assistant message -> Step.tokens; cost from a price table.
 */

interface ContentBlock {
  type?: string;
  text?: string;
  thinking?: string;
  // tool_use
  id?: string;
  name?: string;
  input?: unknown;
  // tool_result
  tool_use_id?: string;
  content?: unknown;
  is_error?: boolean;
}

interface CCMessage {
  role?: string;
  model?: string;
  content?: string | ContentBlock[];
  usage?: TokenUsage;
}

interface CCEntry {
  type?: string;
  uuid?: string;
  parentUuid?: string | null;
  timestamp?: string;
  isSidechain?: boolean;
  isMeta?: boolean;
  message?: CCMessage;
  toolUseResult?: unknown;
  cwd?: string;
  sessionId?: string;
}

export interface ClaudeCodeIngestOptions {
  /** Run id; defaults to the session id (or "claude-code-run"). */
  runId?: string;
  /** Human run name; defaults to the first user prompt. */
  name?: string;
  /** Override the model-price table used to derive cost. */
  prices?: ModelPriceTable;
  /** Currency label; defaults to USD (the default price table's currency). */
  currency?: string;
}

/** Parse Claude Code session JSONL text into an array of entries. */
export function parseClaudeCodeJsonl(text: string): unknown[] {
  const out: unknown[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed));
    } catch {
      // Tolerate the occasional malformed line rather than failing the import.
    }
  }
  return out;
}

/** Returns true if the records look like a Claude Code session log. */
export function isClaudeCodeFormat(records: unknown[]): boolean {
  return records.some((r) => {
    if (typeof r !== 'object' || r === null) return false;
    const e = r as CCEntry;
    return (
      (e.type === 'user' || e.type === 'assistant') &&
      typeof e.message === 'object' &&
      e.message !== null &&
      typeof e.uuid === 'string'
    );
  });
}

function asBlocks(content: string | ContentBlock[] | undefined): ContentBlock[] {
  if (Array.isArray(content)) return content;
  if (typeof content === 'string') return [{ type: 'text', text: content }];
  return [];
}

/**
 * Concatenated text of a user message — handles both plain-string content and
 * the content-array form (where the prompt is a `text` block alongside images).
 * tool_result blocks are excluded (they're correlated to their tool_call).
 */
export function extractUserText(content: string | ContentBlock[] | undefined): string {
  if (typeof content === 'string') return content.trim();
  if (Array.isArray(content)) {
    return content
      .filter((b) => b.type === 'text' && typeof b.text === 'string')
      .map((b) => b.text!.trim())
      .filter(Boolean)
      .join('\n')
      .trim();
  }
  return '';
}

/** True for Claude Code's injected plumbing envelopes (not real agent input). */
export function isPlumbing(text: string): boolean {
  return (
    text.startsWith('<command-') ||
    text.startsWith('<local-command') ||
    text.startsWith('<bash-') ||
    text.startsWith('<task-notification')
  );
}

/** Collapse whitespace/newlines to a single line — for compact labels. */
export function oneLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/** True if `text` reads as a human prompt worth using as a run/session label. */
export function isLabelWorthy(text: string): boolean {
  if (!text || isPlumbing(text)) return false;
  if (text.startsWith('<')) return false; // system-reminder / other XML envelopes
  if (text.startsWith('Caveat:')) return false;
  if (text.startsWith('This session is being continued')) return false;
  return true;
}

/** Render a tool_result block's content into a readable string/structure. */
function toolResultOutput(content: unknown): unknown {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    const texts = content
      .map((b) => (typeof b === 'object' && b && 'text' in b ? (b as { text?: string }).text : undefined))
      .filter((t): t is string => typeof t === 'string');
    if (texts.length > 0) return texts.join('\n');
    return content;
  }
  return content;
}

function firstUserPrompt(records: CCEntry[]): string {
  for (const e of records) {
    if (e.type !== 'user') continue;
    const t = extractUserText(e.message?.content);
    if (isLabelWorthy(t)) return oneLine(t);
  }
  return 'Claude Code session';
}

/**
 * Ingest Claude Code session records into a structural Run (hashes/warnings are
 * filled by the downstream pipeline via `finalizeRun`).
 */
export function ingestClaudeCodeSession(records: unknown[], opts: ClaudeCodeIngestOptions = {}): Run {
  const entries = records.filter(
    (r): r is CCEntry => typeof r === 'object' && r !== null,
  );

  const prices = opts.prices ?? DEFAULT_MODEL_PRICES;
  const currency = opts.currency ?? DEFAULT_CURRENCY;

  // 1) Correlate tool results back to their tool_use id.
  const resultByToolUseId = new Map<string, { output: unknown; data: unknown }>();
  for (const e of entries) {
    if (e.type !== 'user') continue;
    for (const block of asBlocks(e.message?.content)) {
      if (block.type === 'tool_result' && typeof block.tool_use_id === 'string') {
        resultByToolUseId.set(block.tool_use_id, {
          output: toolResultOutput(block.content),
          data: e.toolUseResult,
        });
      }
    }
  }

  // 2) Walk entries in order, emitting draft steps.
  const sessionId =
    entries.find((e) => typeof e.sessionId === 'string')?.sessionId ?? 'claude-code';
  const runId = opts.runId ?? `cc-${sessionId}`;

  const drafts: DraftStep[] = [];
  const indexOfLastAssistantText: { value: number } = { value: -1 };

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]!;
    if (e.type !== 'user' && e.type !== 'assistant') continue;

    const startedAt = e.timestamp ?? new Date(0).toISOString();
    // Per-step duration = gap to the next message entry; attributed to this
    // entry's first emitted step so wall-clock totals stay honest.
    const next = entries.slice(i + 1).find((n) => n.type === 'user' || n.type === 'assistant');
    const gapMs =
      next?.timestamp && e.timestamp
        ? Math.max(0, Date.parse(next.timestamp) - Date.parse(e.timestamp))
        : 0;

    const usage = e.type === 'assistant' ? e.message?.usage : undefined;
    const tokens = totalTokens(usage);
    const cost = usage ? costForUsage(usage, priceForModel(e.message?.model, prices)) : 0;
    let firstStepOfEntry = true;

    const push = (draft: Omit<DraftStep, 'startedAt' | 'durationMs' | 'tokens' | 'cost' | 'spanId'> & {
      spanId: string;
    }) => {
      drafts.push({
        ...draft,
        startedAt,
        durationMs: firstStepOfEntry ? gapMs : 0,
        // Attribute the message's tokens/cost to its first step only, so a
        // multi-block assistant turn isn't counted several times over.
        tokens: firstStepOfEntry ? tokens : 0,
        cost: firstStepOfEntry ? cost : 0,
      });
      firstStepOfEntry = false;
    };

    if (e.type === 'user') {
      const text = extractUserText(e.message?.content);
      // Skip empty / tool_result-only turns (folded into their tool_call) and
      // Claude Code's command plumbing — neither is real agent input.
      if (text && !isPlumbing(text)) {
        const label = oneLine(text);
        push({
          type: 'user_input',
          label: label.length > 60 ? `${label.slice(0, 57)}…` : label,
          input: text,
          spanId: e.uuid ?? `${runId}-span-${drafts.length}`,
          ...(e.parentUuid ? { parentSpanId: e.parentUuid } : {}),
        });
      }
      continue;
    }

    // assistant
    const blocks = asBlocks(e.message?.content);
    for (const block of blocks) {
      const spanId = `${e.uuid ?? runId}:${block.id ?? block.type ?? drafts.length}`;
      if (block.type === 'thinking' && block.thinking) {
        push({
          type: 'llm_reasoning',
          label: 'Reasoning',
          output: block.thinking,
          spanId,
          ...(e.parentUuid ? { parentSpanId: e.parentUuid } : {}),
        });
      } else if (block.type === 'text' && block.text?.trim()) {
        indexOfLastAssistantText.value = drafts.length;
        push({
          type: 'llm_reasoning',
          label: 'Assistant',
          output: block.text,
          spanId,
          ...(e.parentUuid ? { parentSpanId: e.parentUuid } : {}),
        });
      } else if (block.type === 'tool_use') {
        const result = block.id ? resultByToolUseId.get(block.id) : undefined;
        push({
          type: 'tool_call',
          label: block.name ? `Tool: ${block.name}` : 'Tool call',
          ...(block.name ? { toolName: block.name } : {}),
          ...(block.input !== undefined ? { input: block.input } : {}),
          ...(result?.output !== undefined ? { output: result.output } : {}),
          ...(result?.data !== undefined ? { dataPayload: result.data } : {}),
          spanId,
          ...(e.parentUuid ? { parentSpanId: e.parentUuid } : {}),
        });
      }
    }
  }

  // 3) Promote the session's final assistant text to final_output.
  if (indexOfLastAssistantText.value >= 0) {
    const last = drafts[indexOfLastAssistantText.value]!;
    last.type = 'final_output';
    last.label = 'Final output';
  }

  const meta: DraftRunMeta = {
    id: runId,
    name: opts.name ?? firstUserPrompt(entries),
    currency,
  };

  return assembleRun(meta, drafts);
}
