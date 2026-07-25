import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { ingestNative } from '../ingest/index.js';
import { finalizeRun } from '../pipeline.js';
import { generateKeyPairSync } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { signRun, verifyRunFull } from '../integrity/index.js';
import { redactRun, withCommitments } from '../redact/redact.js';
import { RunStore, SCHEMA_VERSION } from './store.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../../fixtures');
const load = (name: string): unknown => JSON.parse(readFileSync(join(fixturesDir, name), 'utf8'));

const run = finalizeRun(ingestNative(load('sample-run-native.json')));

describe('RunStore (acceptance §M2)', () => {
  let store: RunStore;
  beforeEach(() => {
    store = new RunStore(':memory:');
  });
  afterEach(() => {
    store.close();
  });

  it('round-trips save -> get preserving the run exactly', () => {
    store.saveRun(run);
    const loaded = store.getRun(run.id);
    expect(loaded).toEqual(run);
  });

  it('lists ingested runs with summary metadata', () => {
    store.saveRun(run);
    const list = store.listRuns();
    expect(list).toHaveLength(1);
    expect(list[0]!.id).toBe(run.id);
    expect(list[0]!.runHash).toBe(run.runHash);
    expect(list[0]!.steps).toBe(run.totals.steps);
  });

  it('is append-only: re-saving the same id throws', () => {
    store.saveRun(run);
    expect(() => store.saveRun(run)).toThrow(/append-only/);
  });

  it('returns null for an unknown id', () => {
    expect(store.getRun('nope')).toBeNull();
  });

  it('searchRuns finds steps by payload text with run + step context (v0.4)', () => {
    store.saveRun(run);
    const loopRun = finalizeRun(ingestNative(load('sample-run-loop.json')));
    store.saveRun(loopRun);

    const hits = store.searchRuns('4471');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.every((h) => h.runId === loopRun.id)).toBe(true); // only the collections run mentions 4471
    expect(hits[0]!.snippet.toLowerCase()).toContain('4471');
    expect(hits[0]!.stepIndex).toBeGreaterThanOrEqual(0);

    // Case-insensitive; misses return empty, not errors.
    expect(store.searchRuns('COLLECTIONS').length).toBeGreaterThan(0);
    expect(store.searchRuns('zz-no-such-text-zz')).toEqual([]);

    // LIKE metacharacters are literals: '4_71' must NOT wildcard-match '4471'.
    expect(store.searchRuns('4_71')).toEqual([]);

    // Limit caps results.
    expect(store.searchRuns('a', { limit: 3 }).length).toBeLessThanOrEqual(3);
  });

  it('replaceRedacted overwrites in place and refuses unknown ids (v0.6)', () => {
    store.saveRun(run);
    const redacted = { ...run, name: 'redacted copy' };
    store.replaceRedacted(redacted);
    expect(store.getRun(run.id)!.name).toBe('redacted copy');
    expect(store.listRuns()).toHaveLength(1); // in place, not an extra row
    expect(() => store.replaceRedacted({ ...run, id: 'ghost' })).toThrow(/no such run/);
  });

  it('pruneOlderThan deletes only runs ingested before the cutoff and reports them', () => {
    store.saveRun(run);
    store.saveRun({ ...run, id: 'old-run' });
    // Backdate one row directly (tests only — there is no app-level update path).
    (
      store as unknown as {
        db: { prepare: (sql: string) => { run: (...a: unknown[]) => unknown } };
      }
    ).db
      .prepare(`UPDATE runs SET ingested_at = ? WHERE id = ?`)
      .run('2000-01-01T00:00:00.000Z', 'old-run');

    const pruned = store.pruneOlderThan('2020-01-01T00:00:00.000Z');
    expect(pruned.map((p) => p.id)).toEqual(['old-run']);
    expect(pruned[0]!.runHash).toBe(run.runHash);
    expect(store.getRun('old-run')).toBeNull();
    expect(store.getRun(run.id)).not.toBeNull();
  });
});

/**
 * Erasure has to hold against the file, not just against a SELECT. SQLite
 * leaves a superseded row readable in a freed page, so before secure_delete +
 * VACUUM a "redacted" value came straight back out of the .sqlite via `strings`.
 */
describe('RunStore erasure is durable on disk (v0.7.1)', () => {
  const SECRET = 'chase-account-4471-SECRET';
  let dir: string;
  let dbPath: string;
  let store: RunStore;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tg-store-erase-'));
    dbPath = join(dir, 'traceglass.sqlite');
    store = new RunStore(dbPath);
  });
  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  /** Raw bytes of the db plus any WAL sidecar — what an attacker would grep. */
  const onDisk = (): string =>
    ['', '-wal', '-shm']
      .map((suffix) => {
        try {
          return readFileSync(dbPath + suffix, 'latin1');
        } catch {
          return '';
        }
      })
      .join('');

  const withSecret = (id: string) => {
    const steps = run.steps.map((s, i) => (i === 0 ? { ...s, input: SECRET } : s));
    return { ...run, id, steps };
  };

  it('a redacted value is not recoverable from the database file', () => {
    store.saveRun(withSecret('redact-me'));
    expect(onDisk()).toContain(SECRET); // precondition: it really was written

    const scrubbed = store.getRun('redact-me')!;
    store.replaceRedacted({
      ...scrubbed,
      steps: scrubbed.steps.map((s, i) => (i === 0 ? { ...s, input: '[traceglass:redacted]' } : s)),
    });

    expect(store.getRun('redact-me')!.steps[0]!.input).toBe('[traceglass:redacted]');
    expect(onDisk()).not.toContain(SECRET);
  });

  it('a pruned run leaves no readable remains either', () => {
    store.saveRun(withSecret('prune-me'));
    expect(onDisk()).toContain(SECRET);

    expect(store.pruneOlderThan(new Date(Date.now() + 60_000).toISOString())).toHaveLength(1);
    expect(store.getRun('prune-me')).toBeNull();
    expect(onDisk()).not.toContain(SECRET);
  });
});

/**
 * The 0.7.1 fix only purges on the NEXT redaction or prune, so every database
 * written by 0.6.0–0.7.2 still holds recoverable plaintext for values whose
 * owners were told they were erased. v0.8 closes that: schema versioning marks
 * such files, opening one purges it exactly once, and `vacuum()` is the manual
 * lever. These tests reconstruct the pre-fix file byte for byte and prove the
 * secret goes from recoverable to absent.
 */
describe('legacy residue, schema versioning, and vacuum (v0.8)', () => {
  const SECRET = 'chase-account-4471-ULTRASECRET';
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tg-store-legacy-'));
    dbPath = join(dir, 'traceglass.sqlite');
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  /**
   * A real, signed, redactable run whose first step holds the secret — built
   * through the same path a captured run takes, so the redaction below is the
   * genuine article rather than a hand-edited approximation.
   */
  const signedSecretRun = (() => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const priv = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const pub = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const raw = load('sample-run-native.json') as { steps: Array<Record<string, unknown>> };
    raw.steps[0]!.input = { account: SECRET };
    const ingested = ingestNative(raw);
    const committed = { ...ingested, steps: ingested.steps.map((s) => withCommitments(s)) };
    return signRun(finalizeRun(committed), priv, pub);
  })();

  /**
   * Count occurrences of the secret across the db and BOTH WAL sidecars.
   *
   * Counting with `grep -c` would count matching LINES of a binary file, not
   * occurrences — the mistake that nearly hid the original bug. Split-counting
   * the raw bytes is exact; `strings | grep -o | wc -l` is the shell equivalent
   * an auditor would reach for, and is asserted alongside it.
   */
  const occurrences = (): number => {
    let total = 0;
    for (const suffix of ['', '-wal', '-shm']) {
      try {
        total += readFileSync(dbPath + suffix, 'latin1').split(SECRET).length - 1;
      } catch {
        // sidecar absent — contributes nothing
      }
    }
    return total;
  };

  /** What `strings traceglass.sqlite | grep -o SECRET | wc -l` reports. */
  const stringsCount = (): number => {
    let total = 0;
    for (const suffix of ['', '-wal', '-shm']) {
      const file = dbPath + suffix;
      if (!existsSync(file)) continue;
      try {
        total += Number(
          execFileSync(
            'bash',
            [
              '-c',
              `strings -a ${JSON.stringify(file)} | grep -o ${JSON.stringify(SECRET)} | wc -l`,
            ],
            { encoding: 'utf8' },
          ).trim(),
        );
      } catch {
        // `strings` unavailable on this box — the raw byte count above stands.
      }
    }
    return total;
  };

  /**
   * Write the database exactly as 0.6.0–0.7.0 did: secure_delete OFF, no
   * user_version, and a "redaction" that is a bare UPDATE with no checkpoint
   * and no VACUUM. `userVersion` lets a test pretend the file was already
   * stamped, to prove the migration does NOT re-run.
   */
  function writeLegacyDb(opts: { userVersion?: number } = {}): void {
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    db.pragma('secure_delete = OFF');
    db.exec(`CREATE TABLE IF NOT EXISTS runs (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT NOT NULL,
      status TEXT NOT NULL, steps INTEGER NOT NULL, cost REAL NOT NULL, currency TEXT NOT NULL,
      run_hash TEXT NOT NULL, ingested_at TEXT NOT NULL, data TEXT NOT NULL);`);
    if (opts.userVersion !== undefined) db.pragma(`user_version = ${opts.userVersion}`);

    const secretRun = signedSecretRun;
    const insert = db.prepare(
      `INSERT INTO runs (id,name,started_at,ended_at,status,steps,cost,currency,run_hash,ingested_at,data)
       VALUES (@id,@name,@startedAt,@endedAt,@status,@steps,@cost,@currency,@runHash,@ingestedAt,@data)`,
    );
    const row = (id: string, data: string) => ({
      id,
      name: run.name,
      startedAt: run.startedAt,
      endedAt: run.endedAt,
      status: run.status,
      steps: run.totals.steps,
      cost: run.totals.cost,
      currency: run.currency,
      runHash: run.runHash,
      ingestedAt: new Date().toISOString(),
      data,
    });
    insert.run(row(secretRun.id, JSON.stringify(secretRun)));
    // Pad the file so the freed page is not instantly reused by the update.
    for (let i = 0; i < 40; i++) {
      insert.run(row(`pad-${i}`, JSON.stringify({ ...run, id: `pad-${i}` })));
    }

    // A genuine v0.6 redaction — commitments keep the anchor and signature
    // valid — persisted the OLD way: bare UPDATE, no checkpoint, no VACUUM.
    const result = redactRun(secretRun, { paths: ['input.account'], reason: 'erasure request' });
    if (result.redacted.length !== 1) {
      throw new Error(`test setup: expected 1 redaction, got ${result.redacted.length}`);
    }
    db.prepare(`UPDATE runs SET data = @data WHERE id = @id`).run({
      id: secretRun.id,
      data: JSON.stringify(result.run),
    });
    db.close();
  }

  it('opening a pre-versioning database purges the residue its redaction left behind', () => {
    writeLegacyDb();

    // Precondition: the "irreversibly removed" value is sitting in the file.
    expect(occurrences()).toBeGreaterThan(0);
    expect(stringsCount()).toBeGreaterThan(0);

    const store = new RunStore(dbPath);
    try {
      expect(store.schemaVersion).toBe(SCHEMA_VERSION);
      expect(occurrences()).toBe(0);
      expect(stringsCount()).toBe(0);

      // The record survives the purge, intact and still provable.
      expect(store.listRuns()).toHaveLength(41);
      const recovered = store.getRun(signedSecretRun.id)!;
      expect((recovered.steps[0]!.input as { account: string }).account).toBe(
        '[traceglass:redacted]',
      );
      const integrity = verifyRunFull(recovered);
      expect(integrity.chain.ok).toBe(true);
      expect(integrity.signature.ok).toBe(true);
      expect(integrity.ok).toBe(true);
      // The anchor is unchanged by redaction, so the erasure is still provable.
      expect(recovered.runHash).toBe(signedSecretRun.runHash);
    } finally {
      store.close();
    }
  });

  it('the purge runs once, not on every open — and vacuum() is the manual lever', () => {
    // Same residue, but the file claims to be current, so no migration is due.
    writeLegacyDb({ userVersion: SCHEMA_VERSION });
    const before = occurrences();
    expect(before).toBeGreaterThan(0);

    const store = new RunStore(dbPath);
    try {
      // Proof that opening does NOT vacuum: the residue is still there.
      expect(occurrences()).toBe(before);

      const result = store.vacuum();
      expect(occurrences()).toBe(0);
      expect(stringsCount()).toBe(0);
      expect(result.path).toBe(dbPath);
      expect(result.bytesBefore).toBeGreaterThan(0);
      expect(result.bytesAfter).toBeGreaterThan(0);
      expect(result.reclaimed).toBe(Math.max(0, result.bytesBefore - result.bytesAfter));

      // Safe to run repeatedly: no data loss, nothing left to find.
      const again = store.vacuum();
      expect(again.reclaimed).toBeGreaterThanOrEqual(0);
      expect(store.listRuns()).toHaveLength(41);
      const recovered = store.getRun(signedSecretRun.id)!;
      expect((recovered.steps[0]!.input as { account: string }).account).toBe(
        '[traceglass:redacted]',
      );
      expect(verifyRunFull(recovered).ok).toBe(true);
    } finally {
      store.close();
    }
  });

  it('stamps the schema version on a new database and keeps it across opens', () => {
    const first = new RunStore(dbPath);
    expect(first.schemaVersion).toBe(SCHEMA_VERSION);
    first.saveRun(run);
    first.close();

    const second = new RunStore(dbPath);
    expect(second.schemaVersion).toBe(SCHEMA_VERSION);
    expect(second.getRun(run.id)).not.toBeNull();
    second.close();

    const raw = new Database(dbPath);
    expect((raw.pragma('user_version') as Array<{ user_version: number }>)[0]!.user_version).toBe(
      SCHEMA_VERSION,
    );
    raw.close();
  });

  it('refuses to open a database from a future schema version instead of corrupting it', () => {
    const seed = new RunStore(dbPath);
    seed.saveRun(run);
    seed.close();

    const raw = new Database(dbPath);
    raw.pragma(`user_version = ${SCHEMA_VERSION + 7}`);
    raw.close();

    expect(() => new RunStore(dbPath)).toThrow(
      new RegExp(`schema version ${SCHEMA_VERSION + 7}.*at most ${SCHEMA_VERSION}`, 's'),
    );

    // Nothing was modified: an older binary backing off leaves the file usable.
    const check = new Database(dbPath);
    expect((check.pragma('user_version') as Array<{ user_version: number }>)[0]!.user_version).toBe(
      SCHEMA_VERSION + 7,
    );
    expect((check.prepare('SELECT COUNT(*) AS n FROM runs').get() as { n: number }).n).toBe(1);
    check.close();
  });

  it('an in-memory store is current from birth and vacuums harmlessly', () => {
    const mem = new RunStore(':memory:');
    expect(mem.schemaVersion).toBe(SCHEMA_VERSION);
    mem.saveRun(run);
    expect(mem.vacuum()).toEqual({
      path: ':memory:',
      bytesBefore: 0,
      bytesAfter: 0,
      reclaimed: 0,
    });
    expect(mem.getRun(run.id)).not.toBeNull();
    mem.close();
  });
});
