import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import { RunSchema, type Run } from '../model.js';

/** Lightweight run metadata for listings (no full step payloads). */
export interface RunSummary {
  id: string;
  name: string;
  startedAt: string;
  endedAt: string;
  status: Run['status'];
  steps: number;
  cost: number;
  currency: string;
  runHash: string;
  ingestedAt: string;
}

/**
 * Append-only run store (PRD §6). A run, once ingested, is never updated:
 * there is intentionally NO update path in this class. That immutability is
 * what lets the hash chain stand as an audit record rather than a debug log.
 * Deletion exists ONLY through pruneOlderThan (retention policy) — an explicit
 * whole-run path whose results the caller must write to an audit log.
 */
export class RunStore {
  private readonly db: Database.Database;

  constructor(path: string) {
    if (path !== ':memory:') {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS runs (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        started_at  TEXT NOT NULL,
        ended_at    TEXT NOT NULL,
        status      TEXT NOT NULL,
        steps       INTEGER NOT NULL,
        cost        REAL NOT NULL,
        currency    TEXT NOT NULL,
        run_hash    TEXT NOT NULL,
        ingested_at TEXT NOT NULL,
        data        TEXT NOT NULL
      );
    `);
  }

  /**
   * Persist a run. INSERT-only: re-ingesting an existing id throws rather than
   * overwriting, preserving the append-only guarantee.
   */
  saveRun(run: Run): void {
    const validated = RunSchema.parse(run);
    if (this.getRun(validated.id)) {
      throw new Error(
        `Run "${validated.id}" already exists. Runs are append-only and cannot be overwritten.`,
      );
    }
    this.db
      .prepare(
        `INSERT INTO runs
          (id, name, started_at, ended_at, status, steps, cost, currency, run_hash, ingested_at, data)
         VALUES
          (@id, @name, @startedAt, @endedAt, @status, @steps, @cost, @currency, @runHash, @ingestedAt, @data)`,
      )
      .run({
        id: validated.id,
        name: validated.name,
        startedAt: validated.startedAt,
        endedAt: validated.endedAt,
        status: validated.status,
        steps: validated.totals.steps,
        cost: validated.totals.cost,
        currency: validated.currency,
        runHash: validated.runHash,
        ingestedAt: new Date().toISOString(),
        data: JSON.stringify(validated),
      });
  }

  /** Load a full run by id, or null if absent. Validates on the way out. */
  getRun(id: string): Run | null {
    const row = this.db.prepare(`SELECT data FROM runs WHERE id = ?`).get(id) as
      | { data: string }
      | undefined;
    if (!row) return null;
    return RunSchema.parse(JSON.parse(row.data));
  }

  /** List run summaries, most recently ingested first. */
  listRuns(): RunSummary[] {
    const rows = this.db
      .prepare(
        `SELECT id, name, started_at, ended_at, status, steps, cost, currency, run_hash, ingested_at
         FROM runs ORDER BY ingested_at DESC`,
      )
      .all() as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: String(r.id),
      name: String(r.name),
      startedAt: String(r.started_at),
      endedAt: String(r.ended_at),
      status: r.status as Run['status'],
      steps: Number(r.steps),
      cost: Number(r.cost),
      currency: String(r.currency),
      runHash: String(r.run_hash),
      ingestedAt: String(r.ingested_at),
    }));
  }

  /**
   * Cross-run search (v0.4): find steps whose label, tool name, or payloads
   * contain the query text (case-insensitive). SQL narrows to candidate rows;
   * the precise match runs over the parsed steps so hits carry step context.
   * Answers questions like "which runs ever touched account 4471?" — the shape
   * of a GDPR data-subject request or an incident sweep.
   */
  searchRuns(query: string, opts: { limit?: number } = {}): SearchHit[] {
    const limit = opts.limit ?? 50;
    const needle = query.toLowerCase();
    const rows = this.db
      .prepare(
        `SELECT id, name, data FROM runs WHERE data LIKE ? ESCAPE '\\' ORDER BY ingested_at DESC`,
      )
      .all(`%${escapeLike(query)}%`) as Array<{ id: string; name: string; data: string }>;

    const hits: SearchHit[] = [];
    for (const row of rows) {
      const run = RunSchema.parse(JSON.parse(row.data));
      for (const step of run.steps) {
        const haystacks = [
          step.label,
          step.toolName ?? '',
          step.input !== undefined ? JSON.stringify(step.input) : '',
          step.output !== undefined ? JSON.stringify(step.output) : '',
          step.dataPayload !== undefined ? JSON.stringify(step.dataPayload) : '',
        ];
        const matched = haystacks.find((h) => h.toLowerCase().includes(needle));
        if (matched === undefined) continue;
        hits.push({
          runId: run.id,
          runName: run.name,
          stepId: step.id,
          stepIndex: step.index,
          stepType: step.type,
          label: step.label,
          snippet: makeSnippet(matched, needle),
        });
        if (hits.length >= limit) return hits;
      }
    }
    return hits;
  }

  /**
   * Redaction: overwrite a stored run with a redacted version of ITSELF.
   *
   * This is the only update path in the store, and it exists because erasure
   * requests require destroying data in place — leaving the original on disk
   * would defeat the purpose. It is deliberately narrow: the id must match an
   * existing run, and the caller must audit-log the result. Everything else
   * about the store stays append-only.
   */
  replaceRedacted(run: Run): void {
    const validated = RunSchema.parse(run);
    const existing = this.getRun(validated.id);
    if (!existing) {
      throw new Error(`Cannot redact "${validated.id}": no such run.`);
    }
    this.db
      .prepare(`UPDATE runs SET data = @data, run_hash = @runHash, cost = @cost WHERE id = @id`)
      .run({
        id: validated.id,
        data: JSON.stringify(validated),
        runHash: validated.runHash,
        cost: validated.totals.cost,
      });
  }

  /**
   * Retention: delete whole runs ingested before the cutoff and return what
   * was removed so the caller can audit-log it. This is the only delete path.
   */
  pruneOlderThan(cutoffIso: string): PrunedRun[] {
    const prune = this.db.transaction((cutoff: string): PrunedRun[] => {
      const rows = this.db
        .prepare(`SELECT id, name, ingested_at, run_hash FROM runs WHERE ingested_at < ?`)
        .all(cutoff) as Array<Record<string, unknown>>;
      this.db.prepare(`DELETE FROM runs WHERE ingested_at < ?`).run(cutoff);
      return rows.map((r) => ({
        id: String(r.id),
        name: String(r.name),
        ingestedAt: String(r.ingested_at),
        runHash: String(r.run_hash),
      }));
    });
    return prune(cutoffIso);
  }

  close(): void {
    this.db.close();
  }
}

/** What pruneOlderThan removed — enough to audit-log the deletion. */
export interface PrunedRun {
  id: string;
  name: string;
  ingestedAt: string;
  runHash: string;
}

/** One step-level match from searchRuns. */
export interface SearchHit {
  runId: string;
  runName: string;
  stepId: string;
  stepIndex: number;
  stepType: Run['steps'][number]['type'];
  label: string;
  /** Short excerpt of the matched text around the query. */
  snippet: string;
}

/** Escape SQL LIKE metacharacters in user input. */
function escapeLike(text: string): string {
  return text.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/** Excerpt ~80 chars of matched text centred on the first occurrence. */
function makeSnippet(haystack: string, lowerNeedle: string): string {
  const at = haystack.toLowerCase().indexOf(lowerNeedle);
  const start = Math.max(0, at - 30);
  const end = Math.min(haystack.length, at + lowerNeedle.length + 50);
  return `${start > 0 ? '…' : ''}${haystack.slice(start, end)}${end < haystack.length ? '…' : ''}`;
}
