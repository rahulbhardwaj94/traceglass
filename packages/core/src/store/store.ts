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
