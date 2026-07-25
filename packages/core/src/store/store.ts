import { mkdirSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import { RunSchema, type Run } from '../model.js';

/**
 * Current on-disk schema version, recorded in `PRAGMA user_version`.
 *
 * 0 — pre-versioning (traceglass ≤ 0.7.2). Shape is identical to v1, but these
 *     files were written before secure_delete was enabled, so a redacted or
 *     pruned value may still be readable in a freed page. Migrating to 1 purges
 *     that residue once.
 * 1 — same table shape, and the file is known to have been purged at least once
 *     under secure_delete.
 */
export const SCHEMA_VERSION = 1;

/**
 * One forward migration step. Steps run in order, each bumping user_version by
 * itself, so a database three versions behind catches up one step at a time and
 * a crash mid-upgrade leaves a coherent version on disk rather than a lie.
 *
 * Adding a migration: append a step with the next `to`, bump SCHEMA_VERSION to
 * match, and keep the append-only invariant — a migration may reshape storage
 * but must never silently drop a run.
 */
interface Migration {
  readonly to: number;
  readonly description: string;
  readonly apply: (db: Database.Database) => void;
}

const MIGRATIONS: readonly Migration[] = [
  {
    to: 1,
    description: 'purge freed pages left readable by pre-0.7.1 redaction and pruning',
    // Databases written by 0.6.0–0.7.2 kept redacted plaintext in freed pages;
    // the 0.7.1 fix only purges on the NEXT redact or prune, so an untouched
    // file still holds values whose owners were told they were erased. One
    // VACUUM under secure_delete settles it, and user_version keeps it to once.
    apply: (db) => purgeFreedPages(db),
  },
];

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
 * the ONLY update path is replaceRedacted (erasure, in place) and the ONLY
 * delete path is pruneOlderThan (retention). That immutability is what lets the
 * hash chain stand as an audit record rather than a debug log; both exceptions
 * are explicit, narrow, and their results must be written to an audit log by
 * the caller. `vacuum` is not a third path: it rewrites the file without
 * changing a single logical row.
 */
export class RunStore {
  private readonly db: Database.Database;
  private readonly path: string;
  /** Schema version found on disk at open, after any migrations were applied. */
  readonly schemaVersion: number;

  constructor(path: string) {
    if (path !== ':memory:') {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.path = path;
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    // Zero out freed content instead of leaving it readable in the page file.
    // Without this, a redacted value survives in a freed page and `strings` on
    // the .sqlite recovers it verbatim — an erasure claim that does not hold.
    this.db.pragma('secure_delete = ON');

    const found = readUserVersion(this.db);
    if (found > SCHEMA_VERSION) {
      this.db.close();
      throw new Error(
        `Database at ${path} uses schema version ${found}, but this traceglass understands ` +
          `at most ${SCHEMA_VERSION}. A newer traceglass wrote it — upgrade rather than risk ` +
          `corrupting the record (nothing was modified).`,
      );
    }

    // A file with no runs table is new, whatever its user_version says: it gets
    // the current schema and no migration (a VACUUM on every open would be a
    // brutal regression on a large store, so the version stamp is the gate).
    const fresh = !tableExists(this.db, 'runs');
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

    if (fresh) {
      setUserVersion(this.db, SCHEMA_VERSION);
      this.schemaVersion = SCHEMA_VERSION;
    } else {
      this.schemaVersion = migrate(this.db, found);
    }
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
    purgeFreedPages(this.db);
  }

  /**
   * Reclaim freed pages on demand, so a value removed earlier cannot be read
   * back out of the file. Changes no logical row; safe to run repeatedly.
   *
   * This exists because the 0.7.1 fix only purges on the NEXT redaction or
   * prune. Any database written by 0.6.0–0.7.2 that has not been touched since
   * still holds recoverable plaintext for values whose owners were told they
   * were erased; opening it now migrates it (once), and this method is the
   * manual lever for anyone who wants to force the sweep — after restoring a
   * backup, say, or before handing a copy of the file to someone else.
   */
  vacuum(): VacuumResult {
    const bytesBefore = this.fileBytes();
    purgeFreedPages(this.db);
    const bytesAfter = this.fileBytes();
    return {
      path: this.path,
      bytesBefore,
      bytesAfter,
      reclaimed: Math.max(0, bytesBefore - bytesAfter),
    };
  }

  /**
   * Durable bytes: the database plus its write-ahead log (0 for :memory:).
   * The -shm sidecar is deliberately excluded — it is a fixed-size shared-memory
   * index that exists only while the file is open, and counting it would report
   * 44 KiB for a 12 KiB store.
   */
  private fileBytes(): number {
    if (this.path === ':memory:') return 0;
    let total = 0;
    for (const suffix of ['', '-wal']) {
      try {
        total += statSync(this.path + suffix).size;
      } catch {
        // WAL absent (checkpointed away, or never created) — counts as 0.
      }
    }
    return total;
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
    const pruned = prune(cutoffIso);
    // Outside the transaction: VACUUM cannot run inside one.
    if (pruned.length > 0) purgeFreedPages(this.db);
    return pruned;
  }

  close(): void {
    this.db.close();
  }
}

/**
 * Reclaim freed pages so removed content cannot be read back out of the file.
 *
 * secure_delete only governs pages freed from here on; an UPDATE also leaves
 * the superseded row in the WAL until it is checkpointed. So: checkpoint to
 * fold the WAL into the main file, VACUUM to rebuild it from live rows only,
 * then checkpoint again because VACUUM itself wrote every page through the WAL.
 * Skipping that last step leaves the rewritten pages — and whatever the WAL had
 * already accumulated — sitting in the sidecar an attacker would also read.
 */
function purgeFreedPages(db: Database.Database): void {
  db.pragma('wal_checkpoint(TRUNCATE)');
  db.exec('VACUUM');
  db.pragma('wal_checkpoint(TRUNCATE)');
}

/** True when a table of this name exists (used to tell a new file from an old one). */
function tableExists(db: Database.Database, name: string): boolean {
  const row = db
    .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`)
    .get(name);
  return row !== undefined;
}

function readUserVersion(db: Database.Database): number {
  const rows = db.pragma('user_version') as Array<{ user_version: number }>;
  return Number(rows[0]?.user_version ?? 0);
}

function setUserVersion(db: Database.Database, version: number): void {
  // PRAGMA user_version takes no bound parameters; version is our own integer.
  db.pragma(`user_version = ${Math.trunc(version)}`);
}

/**
 * Bring a database forward to SCHEMA_VERSION, one recorded step at a time, and
 * return the version now on disk. Each step commits its own version bump, so an
 * interrupted upgrade resumes rather than re-running work already done.
 */
function migrate(db: Database.Database, from: number): number {
  let current = from;
  for (const step of MIGRATIONS) {
    if (step.to <= current) continue;
    step.apply(db);
    setUserVersion(db, step.to);
    current = step.to;
  }
  // A version bump with no step of its own (a purely additive change that
  // CREATE TABLE IF NOT EXISTS already handled) still needs its stamp.
  if (current !== SCHEMA_VERSION) setUserVersion(db, SCHEMA_VERSION);
  return SCHEMA_VERSION;
}

/** What a vacuum reclaimed — file size before/after, in bytes. */
export interface VacuumResult {
  path: string;
  bytesBefore: number;
  bytesAfter: number;
  reclaimed: number;
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
