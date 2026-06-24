#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Command } from 'commander';
import {
  RunStore,
  ingestAndFinalize,
  ingestClaudeCodeAndFinalize,
  discoverSessions,
  findSession,
  readSessionRecords,
  renderReport,
  verifyRun,
  type Run,
  type SessionInfo,
} from '@traceglass/core';
import { storePath } from './paths.js';
import { startServer } from './server.js';
import { openBrowser } from './open-browser.js';

const program = new Command();
program
  .name('traceglass')
  .description('Flight recorder & tamper-evident audit dashboard for autonomous agents')
  .version('0.2.0');

function openStore(): RunStore {
  return new RunStore(storePath());
}

/** Reduce any thrown error (incl. Zod) to a single clear, in-voice line. */
function friendly(e: unknown): string {
  if (e && typeof e === 'object' && 'issues' in e && Array.isArray((e as { issues: unknown[] }).issues)) {
    const issue = (e as { issues: Array<{ path: Array<string | number>; message: string }> }).issues[0];
    if (issue) return `invalid trace at "${issue.path.join('.') || '(root)'}" — ${issue.message}`;
  }
  return e instanceof Error ? (e.message.split('\n')[0] ?? e.message) : String(e);
}

function die(message: string): never {
  console.error(`✗ ${message}`);
  process.exit(1);
}

/** Ingest a trace file into the store (idempotent on a run id already present). */
function ingestFile(store: RunStore, file: string): Run {
  const path = resolve(file);
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return die(`Cannot read file: ${file}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return die(`${file} is not valid JSON.`);
  }
  let run: Run;
  try {
    run = ingestAndFinalize(json);
  } catch (e) {
    return die(`Could not read a run from ${file}: ${friendly(e)}`);
  }
  const existing = store.getRun(run.id);
  if (existing) {
    console.log(`Run "${run.id}" already ingested; re-opening the stored record.`);
    return existing;
  }
  store.saveRun(run);
  console.log(`Ingested run "${run.id}" (${run.totals.steps} steps).`);
  return run;
}

/** Ingest a Claude Code session into the store (idempotent on its run id). */
function ingestSession(store: RunStore, session: SessionInfo): Run {
  let run: Run;
  try {
    run = ingestClaudeCodeAndFinalize(readSessionRecords(session.file), {
      name: session.firstPrompt,
    });
  } catch (e) {
    return die(`Could not read session "${session.id}": ${friendly(e)}`);
  }
  const existing = store.getRun(run.id);
  if (existing) {
    console.log(`Session "${session.id}" already ingested; re-opening the stored record.`);
    return existing;
  }
  store.saveRun(run);
  console.log(`Ingested session "${session.id}" (${run.totals.steps} steps).`);
  return run;
}

/**
 * Serve the dashboard. With a runId, deep-links to that run; without one, boots
 * the session-picker landing screen (?picker=1).
 */
async function serveAndOpen(
  store: RunStore,
  runId: string | null,
  shouldOpen: boolean,
): Promise<void> {
  const server = await startServer(store);
  const target = runId
    ? `${server.url}/?run=${encodeURIComponent(runId)}`
    : `${server.url}/?picker=1`;
  console.log(`\n  traceglass dashboard → ${target}\n`);
  console.log('  Press Ctrl+C to stop.\n');
  if (shouldOpen) openBrowser(target);

  const shutdown = () => {
    server.close().finally(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

program
  .command('open')
  .description('Ingest a trace file or Claude Code session (or re-open a stored run) and launch the dashboard')
  .argument('[trace-file]', 'path to an OTel or native trace JSON file')
  .option('--id <runId>', 're-open an already-ingested run by id')
  .option('--session <id>', 'ingest + replay a Claude Code session by id (see `traceglass sessions`)')
  .option('--no-open', 'do not auto-open the browser')
  .action(
    async (
      traceFile: string | undefined,
      opts: { id?: string; session?: string; open: boolean },
    ) => {
      const store = openStore();
      let runId: string | null = null;
      if (opts.id) {
        const run = store.getRun(opts.id);
        if (!run) {
          console.error(`No stored run with id "${opts.id}". Use \`traceglass list\`.`);
          process.exit(1);
        }
        runId = run.id;
      } else if (opts.session) {
        const session = findSession(opts.session);
        if (!session) {
          console.error(`No Claude Code session with id "${opts.session}". Use \`traceglass sessions\`.`);
          process.exit(1);
        }
        runId = ingestSession(store, session).id;
      } else if (traceFile) {
        runId = ingestFile(store, traceFile).id;
      } else {
        // No target → boot the session picker landing screen.
        console.log('  No run specified — opening the session picker.');
      }
      await serveAndOpen(store, runId, opts.open);
    },
  );

program
  .command('sessions')
  .description('List discovered Claude Code sessions you can replay')
  .action(() => {
    const sessions = discoverSessions();
    if (sessions.length === 0) {
      console.log('No Claude Code sessions found under ~/.claude/projects.');
      return;
    }
    for (const s of sessions) {
      const when = s.endedAt ? s.endedAt.slice(0, 16).replace('T', ' ') : '—';
      const label = s.firstPrompt.length > 60 ? `${s.firstPrompt.slice(0, 57)}…` : s.firstPrompt;
      console.log(`${s.id}\t${when}\t${s.messageCount} msgs\t${s.project}\t${label}`);
    }
    console.log('\n  Replay one with: traceglass open --session <id>');
  });

program
  .command('demo')
  .description('Open the dashboard on a bundled sample run (a collections agent stuck in a tool loop)')
  .option('--no-open', 'do not auto-open the browser')
  .action(async (opts: { open: boolean }) => {
    const demoTrace = join(dirname(fileURLToPath(import.meta.url)), 'demo-trace.json');
    const store = openStore();
    const run = ingestFile(store, demoTrace);
    console.log('  Tip: scrub the timeline to the loop, then run `traceglass verify` to see the hash chain.');
    await serveAndOpen(store, run.id, opts.open);
  });

program
  .command('verify')
  .description('Verify the integrity hash chain of a stored run; exit 1 if tampered')
  .argument('<runId>', 'id of a stored run')
  .action((runId: string) => {
    const store = openStore();
    const run = store.getRun(runId);
    if (!run) {
      console.error(`No stored run with id "${runId}".`);
      process.exit(1);
    }
    const result = verifyRun(run);
    console.log(result.message);
    console.log(`runHash: ${result.storedRunHash}`);
    if (!result.ok) {
      console.log(`expected: ${result.expectedRunHash}`);
      process.exit(1);
    }
    store.close();
  });

program
  .command('report')
  .description('Write a standalone HTML audit report for a stored run')
  .argument('<runId>', 'id of a stored run')
  .requiredOption('-o, --out <file>', 'output HTML file path')
  .action((runId: string, opts: { out: string }) => {
    const store = openStore();
    const run = store.getRun(runId);
    if (!run) {
      console.error(`No stored run with id "${runId}".`);
      process.exit(1);
    }
    writeFileSync(resolve(opts.out), renderReport(run));
    console.log(`Wrote audit report → ${opts.out}`);
    store.close();
  });

program
  .command('list')
  .description('List ingested runs')
  .action(() => {
    const store = openStore();
    const runs = store.listRuns();
    if (runs.length === 0) {
      console.log('No runs ingested yet. Try: traceglass open <trace-file>');
    } else {
      for (const r of runs) {
        console.log(
          `${r.id}\t${r.status}\t${r.steps} steps\t${r.currency} ${r.cost.toFixed(2)}\t${r.name}`,
        );
      }
    }
    store.close();
  });

program.parseAsync(process.argv);
