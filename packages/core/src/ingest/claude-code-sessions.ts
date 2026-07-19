import { readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import {
  claudeCodeRunId,
  extractUserText,
  isLabelWorthy,
  oneLine,
  parseClaudeCodeJsonl,
} from './claude-code.js';

/**
 * Discovery for Claude Code session logs. Claude Code stores one JSONL file per
 * session under `~/.claude/projects/<encoded-cwd>/<session-uuid>.jsonl`.
 */

export interface SessionInfo {
  /** Session id = the JSONL filename without extension (the session uuid). */
  id: string;
  /** Absolute path to the session JSONL file. */
  file: string;
  /** Human project label — the session's cwd, or the decoded directory name. */
  project: string;
  /** First timestamp seen in the session (ISO 8601), or '' if none. */
  startedAt: string;
  /** Last timestamp seen in the session (ISO 8601), or '' if none. */
  endedAt: string;
  /** Count of user/assistant message entries. */
  messageCount: number;
  /** First user prompt, used as a human label. */
  firstPrompt: string;
}

/** Default Claude Code sessions directory: `~/.claude/projects`. */
export function defaultSessionsDir(): string {
  return process.env.CLAUDE_PROJECTS_DIR ?? join(homedir(), '.claude', 'projects');
}

interface CCEntryLite {
  type?: string;
  timestamp?: string;
  cwd?: string;
  message?: { role?: string; content?: string | { type?: string; text?: string }[] };
}

function listJsonlFiles(dir: string): string[] {
  const out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) out.push(...listJsonlFiles(full));
    else if (st.isFile() && name.endsWith('.jsonl')) out.push(full);
  }
  return out;
}

function summarize(file: string): SessionInfo {
  let records: CCEntryLite[] = [];
  try {
    records = parseClaudeCodeJsonl(readFileSync(file, 'utf8')) as CCEntryLite[];
  } catch {
    records = [];
  }

  let startedAt = '';
  let endedAt = '';
  let messageCount = 0;
  let project = '';
  let firstPrompt = '';

  for (const e of records) {
    if (e.type !== 'user' && e.type !== 'assistant') continue;
    messageCount++;
    if (typeof e.timestamp === 'string') {
      if (!startedAt) startedAt = e.timestamp;
      endedAt = e.timestamp;
    }
    if (!project && typeof e.cwd === 'string') project = e.cwd;
    if (!firstPrompt && e.type === 'user') {
      const t = oneLine(extractUserText(e.message?.content));
      if (isLabelWorthy(t)) {
        firstPrompt = t.length > 100 ? `${t.slice(0, 97)}…` : t;
      }
    }
  }

  return {
    id: basename(file).replace(/\.jsonl$/, ''),
    file,
    project: project || decodeDirName(file),
    startedAt,
    endedAt,
    messageCount,
    firstPrompt: firstPrompt || '(no prompt)',
  };
}

/** Best-effort decode of Claude Code's path-encoded directory name. */
function decodeDirName(file: string): string {
  // e.g. ".../projects/-Users-me-Documents-foo/<uuid>.jsonl" -> "/Users/me/Documents/foo"
  const parts = file.split(/[/\\]/);
  const dir = parts[parts.length - 2] ?? '';
  return dir.startsWith('-') ? dir.replace(/-/g, '/') : dir;
}

/**
 * Discover Claude Code sessions under `dir` (default `~/.claude/projects`),
 * most recently active first. Reads each file to derive metadata.
 */
export function discoverSessions(dir: string = defaultSessionsDir()): SessionInfo[] {
  const files = listJsonlFiles(dir);
  const sessions = files.map(summarize).filter((s) => s.messageCount > 0);
  sessions.sort((a, b) => (a.endedAt < b.endedAt ? 1 : a.endedAt > b.endedAt ? -1 : 0));
  return sessions;
}

/** Find a session by id under `dir`, or null. */
export function findSession(id: string, dir: string = defaultSessionsDir()): SessionInfo | null {
  return discoverSessions(dir).find((s) => s.id === id) ?? null;
}

/** Read and parse a session's JSONL records from disk. */
export function readSessionRecords(file: string): unknown[] {
  return parseClaudeCodeJsonl(readFileSync(file, 'utf8'));
}

/**
 * Predict the run id a session file would ingest under, by scanning for the
 * first `sessionId` in the log — cheap enough to call on every watch sweep,
 * with no hashing or model assembly.
 */
export function sessionRunId(file: string): string {
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as { sessionId?: unknown };
      if (typeof parsed.sessionId === 'string') return claudeCodeRunId(parsed.sessionId);
    } catch {
      // Skip malformed lines, same as ingestion does.
    }
  }
  return claudeCodeRunId(undefined);
}
