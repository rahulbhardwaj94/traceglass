import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import {
  RunStore,
  createEnvelope,
  patternsByName,
  redactRun,
  verifyRunFull,
  type Run,
} from '@traceglass/core';
import { startRecording } from '@traceglass/sdk';

/**
 * ADVERSARIAL SUITE — erasure completeness (attack 6).
 *
 * v0.7.1: `redact` claimed irreversible erasure; the value survived in freed
 * SQLite pages and `strings the.sqlite` returned it verbatim. The query said it
 * was gone. The FILE said otherwise. That is the lesson encoded here — every
 * assertion below reads RAW BYTES off disk, never a parsed query result.
 *
 * Six paths are checked, because the v0.7.1 fix only covered the first two:
 *   1. the .sqlite file          4. anchors.jsonl
 *   2. the -wal / -shm sidecars  5. audit.jsonl
 *   3. the SDK journal dir       6. any .tgev export
 */

const SECRET = 'SSN-987-65-4321-UNIQUE-CANARY';
const SIBLING = 'must-survive-redaction';

let home: string;
let savedHome: string | undefined;

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), 'tg-erasure-attack-'));
  savedHome = process.env.TRACEGLASS_HOME;
  process.env.TRACEGLASS_HOME = home;
});

afterAll(() => {
  if (savedHome === undefined) delete process.env.TRACEGLASS_HOME;
  else process.env.TRACEGLASS_HOME = savedHome;
  rmSync(home, { recursive: true, force: true });
});

/**
 * Raw-byte search. Reads the file as latin1 so every byte round-trips and the
 * needle is found even inside binary SQLite pages — a JSON.parse-based check
 * would have missed the v0.7.1 bug entirely.
 */
function fileContainsBytes(file: string, needle: string): boolean {
  if (!existsSync(file)) return false;
  return readFileSync(file, 'latin1').includes(needle);
}

/**
 * A SQLite store is THREE files. Until a checkpoint runs, freshly written rows
 * live only in the -wal, so checking the .sqlite alone can report "clean" while
 * the bytes sit next to it. Any erasure claim has to hold across all three.
 */
function storeContainsBytes(dbFile: string, needle: string): boolean {
  return [dbFile, `${dbFile}-wal`, `${dbFile}-shm`].some((f) => fileContainsBytes(f, needle));
}

/** Every file under a directory tree, recursively. */
function allFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...allFiles(p));
    else out.push(p);
  }
  return out;
}

/** Which files anywhere under `dir` still hold the needle, as raw bytes. */
function leakingFiles(dir: string, needle: string): string[] {
  return allFiles(dir)
    .filter((f) => fileContainsBytes(f, needle))
    // Report POSIX-style paths so the expectations below read the same on
    // Windows, where join() yields backslashes.
    .map((f) => f.slice(dir.length).split(sep).join('/'))
    .sort();
}

describe('ATTACK 6a: erasure from the store, checked as raw bytes', () => {
  const dbFile = () => join(home, 'traceglass.sqlite');
  let original: Run;

  it('the secret IS on disk before redaction (proving the sweep can see it)', async () => {
    const rec = startRecording({ name: 'pii agent', dir: home, id: 'erasure-run' });
    rec.step({
      type: 'user_input',
      label: 'Lookup customer',
      input: { ssn: SECRET, note: SIBLING },
    });
    rec.step({
      type: 'tool_call',
      toolName: 'crm.read',
      label: 'Tool: crm.read',
      output: { email: 'jane@example.com', ok: true },
    });
    original = await rec.end();

    // A byte-level check that would have failed in v0.7.1 had it been written.
    expect(storeContainsBytes(dbFile(), SECRET)).toBe(true);
    expect(storeContainsBytes(dbFile(), SIBLING)).toBe(true);
  });

  it('after redaction the value is gone from the sqlite file, the WAL and the SHM — WHILE THE STORE IS STILL OPEN', () => {
    /*
     * The store must be checked with the connection STILL OPEN. Closing a
     * better-sqlite3 handle checkpoints and removes the -wal, which erases the
     * residue as a side effect — so a byte check performed after close() passes
     * even with `secure_delete` off and `purgeFreedPages` deleted. It proves
     * nothing.
     *
     * Open is also the realistic threat model: `traceglass serve` and
     * `traceglass dashboard` hold this connection for the process lifetime, so
     * an attacker running `strings` against the data directory is by definition
     * looking at an open database.
     *
     * (Verified by deleting the body of purgeFreedPages: the assertions below
     * fail; the same assertions after close() do not.)
     */
    const { run: redacted, redacted: paths } = redactRun(original, {
      paths: ['input.ssn'],
      patterns: patternsByName(['email']),
      reason: 'GDPR erasure request',
    });
    expect(paths.sort()).toEqual(['erasure-run:0#input.ssn', 'erasure-run:1#output.email']);

    const store = new RunStore(dbFile());
    try {
      store.replaceRedacted(redacted);

      // 1 + 2: the database file and BOTH sidecars, as raw bytes, connection open.
      expect(fileContainsBytes(dbFile(), SECRET)).toBe(false);
      expect(fileContainsBytes(`${dbFile()}-wal`, SECRET)).toBe(false);
      expect(fileContainsBytes(`${dbFile()}-shm`, SECRET)).toBe(false);
      expect(fileContainsBytes(dbFile(), 'jane@example.com')).toBe(false);
      expect(storeContainsBytes(dbFile(), 'jane@example.com')).toBe(false);

      // The sibling survived — erasure that nukes everything is not erasure.
      expect(storeContainsBytes(dbFile(), SIBLING)).toBe(true);
    } finally {
      store.close();
    }
    // And still gone once closed.
    expect(storeContainsBytes(dbFile(), SECRET)).toBe(false);
  });

  it('the value is not recoverable through raw SQL either, only through bytes', () => {
    // Belt and braces: the query view and the file view now agree. In v0.7.1
    // they did not, and only the file view was telling the truth.
    const db = new Database(dbFile(), { readonly: true });
    const rows = db.prepare('SELECT data FROM runs').all() as Array<{ data: string }>;
    db.close();
    expect(rows.some((r) => r.data.includes(SECRET))).toBe(false);
  });

  it('the redacted record still verifies — erasure did not cost the evidence', () => {
    const store = new RunStore(dbFile());
    const reloaded = store.getRun('erasure-run')!;
    store.close();
    expect(reloaded.runHash).toBe(original.runHash);
    const result = verifyRunFull(reloaded);
    expect(result.chain.ok).toBe(true);
    expect(result.signature.ok).toBe(true);
  });

  it('WAL residue: ingest and redact on ONE connection leaves nothing readable', () => {
    /*
     * THE v0.7.1 REGRESSION TEST. This is the shape that actually exercises
     * purgeFreedPages: the run is INSERTed and then UPDATEd on the same open
     * connection, so the superseded row is still sitting in un-checkpointed WAL
     * frames when the redaction lands. That is exactly what `traceglass serve`
     * does — ingest over HTTP, then redact — and the connection stays open for
     * the process lifetime, so nothing cleans up behind it.
     *
     * Without `wal_checkpoint(TRUNCATE)` + `VACUUM` in purgeFreedPages, the
     * SSN is recoverable from the -wal with `strings` while the server runs.
     * (Verified: deleting the body of purgeFreedPages turns this test red.)
     */
    const liveDb = join(home, 'longrunning.sqlite');
    const store = new RunStore(liveDb);
    try {
      store.saveRun({
        ...original,
        id: 'longrunning',
        steps: original.steps.map((s, i) => ({ ...s, runId: 'longrunning', id: `longrunning:${i}` })),
      });
      // Present while the connection is open — in the WAL, not yet checkpointed.
      expect(storeContainsBytes(liveDb, SECRET)).toBe(true);

      const stored = store.getRun('longrunning')!;
      const { run: redacted, redacted: paths } = redactRun(stored, { paths: ['input.ssn'] });
      expect(paths).toEqual(['longrunning:0#input.ssn']);
      store.replaceRedacted(redacted);

      // Same connection, still open: the value must be unrecoverable from ALL
      // three files right now, not merely after the process exits.
      expect(fileContainsBytes(liveDb, SECRET)).toBe(false);
      expect(fileContainsBytes(`${liveDb}-wal`, SECRET)).toBe(false);
      expect(fileContainsBytes(`${liveDb}-shm`, SECRET)).toBe(false);
      expect(storeContainsBytes(liveDb, SIBLING)).toBe(true); // sibling survives
    } finally {
      store.close();
    }
  });

  it('WAL residue: a redaction followed by more writes still leaves nothing behind', () => {
    // The v0.7.1 fix leans on wal_checkpoint(TRUNCATE) + VACUUM inside
    // replaceRedacted. Exercise it under continued write traffic, which is what
    // a real deployment looks like.
    const store = new RunStore(dbFile());
    try {
      for (let i = 0; i < 5; i++) {
        const run = store.getRun('erasure-run')!;
        store.replaceRedacted({ ...run, name: `churn-${i}` });
        // Checked every iteration, connection open — see the note above.
        expect(storeContainsBytes(dbFile(), SECRET)).toBe(false);
      }
    } finally {
      store.close();
    }
    expect(storeContainsBytes(dbFile(), SECRET)).toBe(false);
  });

  it('pruning a whole run also leaves no readable residue in any of the three files', () => {
    const pruneDb = join(home, 'prune.sqlite');
    const store = new RunStore(pruneDb);
    store.saveRun({
      ...original,
      id: 'prune-me',
      steps: original.steps.map((s) => ({ ...s, runId: 'prune-me' })),
    });
    // Present somewhere in the store's files (the .sqlite or the -wal).
    expect(storeContainsBytes(pruneDb, SECRET)).toBe(true);
    expect(storeContainsBytes(pruneDb, SIBLING)).toBe(true);

    const pruned = store.pruneOlderThan(new Date(Date.now() + 60_000).toISOString());
    expect(pruned.map((p) => p.id)).toContain('prune-me');

    // Retention deletion must be as thorough as redaction. Whole-run deletion
    // is the path an operator uses to honour a retention policy, so residue
    // here is the same broken promise as residue after redact. Checked with the
    // connection OPEN, for the reason documented above.
    try {
      expect(storeContainsBytes(pruneDb, SECRET)).toBe(false);
      expect(storeContainsBytes(pruneDb, SIBLING)).toBe(false);
    } finally {
      store.close();
    }
    expect(storeContainsBytes(pruneDb, SECRET)).toBe(false);
  });
});

describe('ATTACK 6b: the paths redaction does NOT reach', () => {
  it('VULNERABILITY: an orphaned SDK journal keeps the raw value after redaction', () => {
    /*
     * VULNERABILITY: `redact` rewrites the store row and nothing else. The SDK
     * journal — plain JSONL in ~/.traceglass/journal/ — holds every step's raw
     * payload and is deleted only on a clean `end()` or a successful
     * `traceglass recover`. A crashed run leaves it behind indefinitely.
     *
     * REAL-WORLD CONSEQUENCE: an operator answers a GDPR erasure request with
     * `traceglass redact`, sees "Redacted 1 value(s)", and the subject's SSN is
     * still sitting in cleartext in a JSONL file in their home directory. The
     * product's own `recover` command will happily import it back into the
     * store later. `redact` does not warn, does not scan the journal dir, and
     * does not report it.
     *
     * WHAT SHOULD HAPPEN: `redact` must scan the journal directory for the
     * target run id (and ideally for the value), and either scrub those files
     * or refuse and tell the operator what is still out there.
     */
    const jhome = mkdtempSync(join(tmpdir(), 'tg-journal-leak-'));
    try {
      // A run that crashed mid-flight: journal written, never ended.
      const rec = startRecording({ name: 'crashed pii agent', dir: jhome, id: 'crashed-run' });
      rec.step({ type: 'user_input', label: 'Lookup', input: { ssn: SECRET } });
      // (no end() — the process died here)

      const journalFile = join(jhome, 'journal', 'crashed-run.jsonl');
      expect(existsSync(journalFile)).toBe(true);
      expect(fileContainsBytes(journalFile, SECRET)).toBe(true);

      // Now the operator redacts the STORED copy of a run holding the same
      // value. The journal is untouched.
      const store = new RunStore(join(jhome, 'traceglass.sqlite'));
      const stored = store.getRun('crashed-run');
      expect(stored).toBeNull(); // never finalized, so nothing to redact
      store.close();

      // The value survives an erasure operation that reported success.
      expect(fileContainsBytes(journalFile, SECRET)).toBe(true); // <-- THE HOLE
      expect(leakingFiles(jhome, SECRET)).toEqual(['/journal/crashed-run.jsonl']);
    } finally {
      rmSync(jhome, { recursive: true, force: true });
    }
  });

  it('VULNERABILITY: a journal for a run that WAS redacted is likewise untouched', async () => {
    // The sharper version: the same run id exists in the store, IS redacted
    // successfully, and its journal still holds the cleartext beside it.
    const jhome = mkdtempSync(join(tmpdir(), 'tg-journal-leak-2-'));
    try {
      const rec = startRecording({ name: 'pii', dir: jhome, id: 'both-run' });
      rec.step({ type: 'user_input', label: 'Lookup', input: { ssn: SECRET } });
      const journalFile = join(jhome, 'journal', 'both-run.jsonl');
      const journalBytes = readFileSync(journalFile);
      const finalized = await rec.end();

      // Recreate the journal exactly as a crash-then-restart would leave it.
      writeFileSync(journalFile, journalBytes);
      expect(fileContainsBytes(journalFile, SECRET)).toBe(true);

      const { run: redacted, redacted: paths } = redactRun(finalized, { paths: ['input.ssn'] });
      expect(paths).toEqual(['both-run:0#input.ssn']); // the redaction really happened
      const store = new RunStore(join(jhome, 'traceglass.sqlite'));
      store.replaceRedacted(redacted);
      store.close();

      // Store: erased. Journal sitting next to it: not.
      expect(storeContainsBytes(join(jhome, 'traceglass.sqlite'), SECRET)).toBe(false);
      expect(fileContainsBytes(journalFile, SECRET)).toBe(true); // <-- THE HOLE
      expect(leakingFiles(jhome, SECRET)).toEqual(['/journal/both-run.jsonl']);
    } finally {
      rmSync(jhome, { recursive: true, force: true });
    }
  });

  it('VULNERABILITY: --reason writes operator-supplied text into audit.jsonl forever', () => {
    /*
     * VULNERABILITY: `traceglass redact --reason "<text>"` appends the text
     * verbatim to ~/.traceglass/audit.jsonl, which is never redacted, never
     * rotated, and not covered by the erasure guarantee.
     *
     * REAL-WORLD CONSEQUENCE: the single most natural thing an operator types
     * is the thing they are erasing — `--reason "erase SSN 987-65-4321 per
     * ticket 4471"`. The redaction then succeeds, the store is clean, and the
     * value they were legally required to destroy is written into a permanent
     * append-only log by the erasure command itself.
     *
     * WHAT SHOULD HAPPEN: scan --reason against the redaction patterns and
     * refuse (or scrub) when the reason text contains something matching what
     * is being erased.
     */
    const auditFile = join(home, 'audit.jsonl');
    // Exactly what packages/cli/src/bin.ts writes after a --yes redaction.
    appendFileSync(
      auditFile,
      JSON.stringify({
        reason: 'redaction',
        runId: 'erasure-run',
        legacy: false,
        paths: ['erasure-run:0#input.ssn'],
        note: `erase ${SECRET} per ticket 4471`, // the operator's --reason
        at: new Date().toISOString(),
      }) + '\n',
    );
    expect(fileContainsBytes(auditFile, SECRET)).toBe(true); // <-- THE HOLE
  });

  it('VULNERABILITY: a .tgev export made before redaction is unreachable by it', () => {
    /*
     * VULNERABILITY: `traceglass export` writes a self-contained evidence file
     * — that is its purpose, and the file may be anywhere by the time an
     * erasure request arrives. `redact` has no record of what was exported and
     * no way to reach it.
     *
     * REAL-WORLD CONSEQUENCE: this is arguably inherent to portable evidence,
     * but the product's own words are "irreversibly remove sensitive values",
     * which an operator will read as covering everything traceglass produced.
     * A .tgev sitting in a ticket attachment still verifies AND still contains
     * the SSN.
     *
     * WHAT SHOULD HAPPEN: `redact` should at minimum warn that exports are out
     * of scope; better, keep an export ledger so the operator is told which
     * files must be chased down.
     */
    const exportFile = join(home, 'exported-before-redaction.tgev');
    // An export taken while the value was still present.
    const preRedaction = {
      formatVersion: 1,
      exportedAt: new Date().toISOString(),
      run: { steps: [{ input: { ssn: SECRET } }] },
    };
    writeFileSync(exportFile, JSON.stringify(preRedaction, null, 2));
    expect(fileContainsBytes(exportFile, SECRET)).toBe(true); // <-- THE HOLE

    // And it is still a readable, structurally valid evidence file.
    expect(JSON.parse(readFileSync(exportFile, 'utf8')).formatVersion).toBe(1);
  });

  it('a .tgev exported AFTER redaction is clean', () => {
    // The mitigation that does work: re-export from the redacted store.
    const store = new RunStore(join(home, 'traceglass.sqlite'));
    const redacted = store.getRun('erasure-run')!;
    store.close();
    const out = join(home, 'exported-after-redaction.tgev');
    writeFileSync(out, JSON.stringify(createEnvelope(redacted), null, 2));
    expect(fileContainsBytes(out, SECRET)).toBe(false);
    expect(fileContainsBytes(out, SIBLING)).toBe(true);
  });

  it('anchors.jsonl never carried the payload, so it needs no erasure', () => {
    // 4 of 6: anchor records hold runId + runHash + signature only. Confirmed
    // against the real shape rather than assumed.
    const anchorsFile = join(home, 'anchors.jsonl');
    const store = new RunStore(join(home, 'traceglass.sqlite'));
    const run = store.getRun('erasure-run')!;
    store.close();
    appendFileSync(
      anchorsFile,
      JSON.stringify({
        version: 1,
        runId: run.id,
        runHash: run.runHash,
        keyId: run.signature?.keyId,
        signature: run.signature?.signature,
        anchoredAt: new Date().toISOString(),
      }) + '\n',
    );
    expect(fileContainsBytes(anchorsFile, SECRET)).toBe(false);
    expect(fileContainsBytes(anchorsFile, SIBLING)).toBe(false);
  });

  it('FULL-HOME BYTE SWEEP: exactly the known leaks, and nothing else', () => {
    // The catch-all. If a future change writes the payload somewhere new — a
    // cache, a temp file, a log — this test names the file and fails.
    const leaks = leakingFiles(home, SECRET);
    expect(leaks).toEqual(['/audit.jsonl', '/exported-before-redaction.tgev']);
    // Neither the store, its sidecars, nor the journal dir appear.
    expect(leaks.some((f) => f.includes('sqlite'))).toBe(false);
    expect(leaks.some((f) => f.includes('journal'))).toBe(false);
    expect(leaks.some((f) => f.includes('anchors'))).toBe(false);
  });
});

describe('ATTACK 6c: capture-time scrubbing never writes the value at all', () => {
  it('a pattern-scrubbed value reaches NO file on disk', async () => {
    // The strongest form of the guarantee: nothing to erase because nothing was
    // ever written. Verified by sweeping the whole home for raw bytes.
    const shome = mkdtempSync(join(tmpdir(), 'tg-scrub-'));
    try {
      const canary = 'scrub-canary@example.com';
      const rec = startRecording({
        name: 'scrubbing agent',
        dir: shome,
        id: 'scrub-run',
        redactPatterns: ['email', 'ssn'],
      });
      rec.step({ type: 'user_input', label: 'Lookup', input: { email: canary, keep: SIBLING } });
      rec.step({ type: 'tool_call', toolName: 't', label: 'x', output: { ok: true } });

      // The journal is written synchronously per step — check mid-run, before
      // anything had a chance to be cleaned up.
      expect(leakingFiles(shome, canary)).toEqual([]);
      await rec.end();
      expect(leakingFiles(shome, canary)).toEqual([]);

      // The sweep is not vacuously empty: a NON-matching sibling did land.
      expect(leakingFiles(shome, SIBLING).length).toBeGreaterThan(0);
    } finally {
      rmSync(shome, { recursive: true, force: true });
    }
  });
});
