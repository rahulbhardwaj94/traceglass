#!/usr/bin/env node
import {
  appendFileSync,
  existsSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
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
  verifyRunFull,
  readJournal,
  finalizeJournal,
  listLiveRecordings,
  findLiveRecording,
  liveRunFromJournal,
  createEnvelope,
  parseEvidence,
  parsePolicy,
  evaluatePolicy,
  redactRun,
  redactLegacyRun,
  patternsByName,
  DEFAULT_PATTERNS,
  type Policy,
  type Run,
  type SessionInfo,
} from '@traceglass/core';
import { dataDir, storePath } from './paths.js';
import { startServe, startServer } from './server.js';
import { openBrowser } from './open-browser.js';
import { generateKeys, maybeSign } from './keys.js';
import { FileAnchorSink, anchorRecordForRun, defaultAnchorsPath } from './anchors.js';
import { sweepSessions } from './watch.js';

const program = new Command();
program
  .name('traceglass')
  .description('Flight recorder & tamper-evident audit dashboard for autonomous agents')
  .version('0.7.2');

function openStore(): RunStore {
  return new RunStore(storePath());
}

/** Reduce any thrown error (incl. Zod) to a single clear, in-voice line. */
function friendly(e: unknown): string {
  if (
    e &&
    typeof e === 'object' &&
    'issues' in e &&
    Array.isArray((e as { issues: unknown[] }).issues)
  ) {
    const issue = (e as { issues: Array<{ path: Array<string | number>; message: string }> })
      .issues[0];
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
    run = maybeSign(ingestAndFinalize(json));
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
    run = maybeSign(
      ingestClaudeCodeAndFinalize(readSessionRecords(session.file), {
        name: session.firstPrompt,
      }),
    );
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
  .description(
    'Ingest a trace file or Claude Code session (or re-open a stored run) and launch the dashboard',
  )
  .argument('[trace-file]', 'path to an OTel or native trace JSON file')
  .option('--id <runId>', 're-open an already-ingested run by id')
  .option(
    '--session <id>',
    'ingest + replay a Claude Code session by id (see `traceglass sessions`)',
  )
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
          console.error(
            `No Claude Code session with id "${opts.session}". Use \`traceglass sessions\`.`,
          );
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
  .description(
    'Open the dashboard on a bundled sample run (a collections agent stuck in a tool loop)',
  )
  .option('--no-open', 'do not auto-open the browser')
  .action(async (opts: { open: boolean }) => {
    const demoTrace = join(dirname(fileURLToPath(import.meta.url)), 'demo-trace.json');
    const store = openStore();
    const run = ingestFile(store, demoTrace);
    console.log(
      '  Tip: scrub the timeline to the loop, then run `traceglass verify` to see the hash chain.',
    );
    await serveAndOpen(store, run.id, opts.open);
  });

/**
 * Resolve a verify/report target: a local file path wins over a stored runId
 * (evidence files are self-contained — no store or keys needed to check them).
 */
function loadRunOrEvidence(store: RunStore, arg: string): Run {
  const asFile = resolve(arg);
  if (existsSync(asFile)) {
    try {
      return parseEvidence(JSON.parse(readFileSync(asFile, 'utf8')));
    } catch (e) {
      return die(`Could not read evidence from ${arg}: ${friendly(e)}`);
    }
  }
  const run = store.getRun(arg);
  if (!run) return die(`No stored run with id "${arg}" and no such file.`);
  return run;
}

program
  .command('verify')
  .description(
    'Verify a stored run or a .tgev evidence file (chain + signature); exit 1 if tampered',
  )
  .argument('<runId-or-file>', 'id of a stored run, or path to an exported evidence file')
  .option('--json', 'machine-readable JSON output (for CI)')
  .action((arg: string, opts: { json?: boolean }) => {
    const store = openStore();
    const run = loadRunOrEvidence(store, arg);
    const result = verifyRunFull(run);
    if (opts.json) {
      console.log(JSON.stringify({ runId: run.id, ...result }, null, 2));
    } else {
      console.log(result.chain.message);
      console.log(result.signature.message);
      console.log(`runHash: ${result.chain.storedRunHash}`);
      if (!result.chain.ok) console.log(`expected: ${result.chain.expectedRunHash}`);
    }
    store.close();
    if (!result.ok) process.exit(1);
  });

program
  .command('check')
  .description(
    'Check a stored run or .tgev file against a guardrail policy; exit 1 on any violation',
  )
  .argument('<runId-or-file>', 'id of a stored run, or path to an exported evidence file')
  .requiredOption('-p, --policy <file>', 'policy JSON file (see README for the rule set)')
  .option('--json', 'machine-readable JSON output (for CI)')
  .action((arg: string, opts: { policy: string; json?: boolean }) => {
    const store = openStore();
    const run = loadRunOrEvidence(store, arg);
    let policy;
    try {
      policy = parsePolicy(JSON.parse(readFileSync(resolve(opts.policy), 'utf8')));
    } catch (e) {
      return die(`Could not read policy ${opts.policy}: ${friendly(e)}`);
    }
    // A policy verdict is only meaningful over an authentic record, so
    // integrity (chain + signature) is checked alongside the rules.
    const integrity = verifyRunFull(run);
    const result = evaluatePolicy(run, policy);
    const ok = integrity.ok && result.ok;
    if (opts.json) {
      console.log(JSON.stringify({ runId: run.id, ok, integrity, policy: result }, null, 2));
    } else {
      console.log(integrity.chain.message);
      console.log(integrity.signature.message);
      const name = result.policyName ? ` "${result.policyName}"` : '';
      if (result.ok) {
        console.log(`Policy${name}: PASS — no violations.`);
      } else {
        console.log(`Policy${name}: FAIL — ${result.violations.length} violation(s):`);
        for (const v of result.violations) {
          console.log(`  ✗ [${v.rule}] ${v.message}`);
        }
      }
    }
    store.close();
    if (!ok) process.exit(1);
  });

program
  .command('search')
  .description('Search every stored run for text in step labels, tools, and payloads')
  .argument('<text>', 'text to find (case-insensitive)')
  .option('--limit <n>', 'maximum hits to return', '50')
  .option('--json', 'machine-readable JSON output')
  .action((text: string, opts: { limit: string; json?: boolean }) => {
    const store = openStore();
    const hits = store.searchRuns(text, { limit: Number(opts.limit) || 50 });
    if (opts.json) {
      console.log(JSON.stringify(hits, null, 2));
    } else if (hits.length === 0) {
      console.log(`No steps matching "${text}".`);
    } else {
      for (const h of hits) {
        console.log(`${h.runId}\tstep #${h.stepIndex} (${h.stepType})\t${h.label}`);
        console.log(`  ${h.snippet}`);
      }
      console.log(`\n${hits.length} hit(s). Replay a run with: traceglass open --id <runId>`);
    }
    store.close();
  });

program
  .command('report')
  .description('Write a standalone HTML audit report for a stored run or a .tgev evidence file')
  .argument('<runId-or-file>', 'id of a stored run, or path to an exported evidence file')
  .requiredOption('-o, --out <file>', 'output HTML file path')
  .action((arg: string, opts: { out: string }) => {
    const store = openStore();
    const run = loadRunOrEvidence(store, arg);
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

program
  .command('serve')
  .description('Run as a collector: fixed port, authenticated ingest API, optional retention')
  .option('--port <port>', 'port to listen on', '4318')
  .option('--host <host>', 'host to bind (non-loopback requires a token)', '127.0.0.1')
  .option('--token <token>', 'bearer token for ingest (or set TRACEGLASS_TOKEN)')
  .option(
    '--retain <days>',
    'delete runs older than this many days (audited); default: keep forever',
  )
  .action(async (opts: { port: string; host: string; token?: string; retain?: string }) => {
    const store = openStore();
    const token = opts.token ?? process.env.TRACEGLASS_TOKEN;
    const retainDays = opts.retain !== undefined ? Number(opts.retain) : null;
    if (retainDays !== null && (!Number.isFinite(retainDays) || retainDays <= 0)) {
      return die('--retain must be a positive number of days.');
    }

    const auditPath = join(dataDir(), 'audit.jsonl');
    const sweep = () => {
      if (retainDays === null) return;
      const cutoff = new Date(Date.now() - retainDays * 24 * 60 * 60 * 1000).toISOString();
      const pruned = store.pruneOlderThan(cutoff);
      if (pruned.length > 0) {
        const now = new Date().toISOString();
        const lines = pruned
          .map((p) => JSON.stringify({ ...p, prunedAt: now, reason: 'retention', retainDays }))
          .join('\n');
        appendFileSync(auditPath, lines + '\n');
        console.log(
          `Retention: pruned ${pruned.length} run(s) older than ${retainDays}d (audited → ${auditPath}).`,
        );
      }
    };

    let server;
    try {
      server = await startServe(store, {
        port: Number(opts.port),
        host: opts.host,
        token,
        signer: maybeSign,
      });
    } catch (e) {
      return die(friendly(e));
    }
    sweep();
    const timer = retainDays !== null ? setInterval(sweep, 6 * 60 * 60 * 1000) : null;

    console.log(`\n  traceglass collector → ${server.url}`);
    console.log(`  Dashboard: ${server.url}/?picker=1`);
    console.log(`  Ingest:    curl -X POST ${server.url}/api/ingest \\`);
    console.log(
      `               -H 'content-type: application/json' ${token ? `-H "Authorization: Bearer $TRACEGLASS_TOKEN" ` : ''}\\`,
    );
    console.log(`               --data @trace.json`);
    console.log(`  OTLP/HTTP: POST ${server.url}/v1/traces`);
    console.log(
      `  Auth:      ${token ? 'bearer token required on POST' : 'loopback only, no token set'}`,
    );
    console.log(
      `  Retention: ${retainDays !== null ? `${retainDays} days (audited deletions)` : 'keep forever'}\n`,
    );
    console.log('  Press Ctrl+C to stop.\n');

    const shutdown = () => {
      if (timer) clearInterval(timer);
      server.close().finally(() => process.exit(0));
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  });

program
  .command('tail')
  .description('Watch a recording live as it happens — steps, cost, and warnings stream in')
  .argument('[runId]', 'run to follow (default: the most recently active recording)')
  .option('--interval <ms>', 'poll interval in milliseconds', '500')
  .option('--list', 'list in-progress recordings and exit')
  .action(async (runId: string | undefined, opts: { interval: string; list?: boolean }) => {
    if (opts.list) {
      const live = listLiveRecordings();
      if (live.length === 0) {
        console.log('No recordings in progress.');
        return;
      }
      for (const r of live) {
        console.log(`${r.runId}\t${r.steps} steps\t${r.updatedAt}\t${r.name}`);
      }
      return;
    }

    const initial = runId ? findLiveRecording(runId) : listLiveRecordings()[0];
    if (!initial) {
      return die(
        runId
          ? `No recording in progress with id "${runId}". Use \`traceglass tail --list\`.`
          : 'No recordings in progress. Start one with the SDK, then tail it.',
      );
    }

    const target = initial.runId;
    console.log(`\n  ▸ tailing "${initial.name}" (${target})\n`);
    let printed = 0;
    let warned = new Set<string>();
    const intervalMs = Math.max(100, Number(opts.interval) || 500);

    const render = (): boolean => {
      const live = findLiveRecording(target);
      if (!live) {
        // Journal gone: the run finalized and moved into the store.
        const store = openStore();
        const stored = store.getRun(target);
        store.close();
        if (stored) {
          console.log(
            `\n  ● run ${stored.status} — ${stored.totals.steps} steps, ${stored.currency} ${stored.totals.cost.toFixed(2)}, ${stored.totals.tokens} tokens`,
          );
          console.log(
            `    anchor ${stored.runHash.slice(0, 16)}…${stored.signature ? ' · signed' : ''}`,
          );
          console.log(`    replay: traceglass open --id ${target}\n`);
        } else {
          console.log('\n  ● recording ended.\n');
        }
        return false;
      }
      let run;
      try {
        run = liveRunFromJournal(readJournal(live.file));
      } catch {
        return true; // mid-write; try again next tick
      }
      for (const step of run.steps.slice(printed)) {
        const cost = step.cost > 0 ? ` ${run.currency} ${step.cost.toFixed(2)}` : '';
        const tok = step.tokens > 0 ? ` ${step.tokens}tok` : '';
        console.log(
          `  ${String(step.index).padStart(3)} ${step.type.padEnd(14)} ${step.label}${cost}${tok}`,
        );
      }
      printed = run.steps.length;
      for (const w of run.warnings) {
        const key = `${w.kind}:${w.stepIds.join(',')}`;
        if (warned.has(key)) continue;
        warned.add(key);
        console.log(`  ⚠ ${w.kind.toUpperCase()}: ${w.message}`);
      }
      return true;
    };

    render();
    await new Promise<void>((resolve) => {
      const timer = setInterval(() => {
        if (!render()) {
          clearInterval(timer);
          resolve();
        }
      }, intervalMs);
      const stop = () => {
        clearInterval(timer);
        console.log('\n  (stopped tailing; the recording continues)\n');
        resolve();
      };
      process.on('SIGINT', stop);
      process.on('SIGTERM', stop);
    });
  });

program
  .command('watch')
  .description(
    'Continuously turn finished Claude Code sessions into signed, policy-checked evidence',
  )
  .option('--dir <dir>', 'Claude Code projects dir (default: ~/.claude/projects)')
  .option('--interval <secs>', 'seconds between sweeps', '30')
  .option('--settle <secs>', 'ingest a session only after this long without changes', '60')
  .option('--policy <file>', 'check each new run against this guardrail policy')
  .option('--anchor', 'append each new run to the anchors file')
  .option('--once', 'run a single sweep and exit; exits 1 if any policy violation was found')
  .action(
    async (opts: {
      dir?: string;
      interval: string;
      settle: string;
      policy?: string;
      anchor?: boolean;
      once?: boolean;
    }) => {
      const store = openStore();
      let policy: Policy | undefined;
      if (opts.policy) {
        try {
          policy = parsePolicy(JSON.parse(readFileSync(resolve(opts.policy), 'utf8')));
        } catch (e) {
          return die(`Could not read policy ${opts.policy}: ${friendly(e)}`);
        }
      }
      const settleMs = Math.max(0, Number(opts.settle)) * 1000;
      const sweep = () =>
        sweepSessions(store, {
          dir: opts.dir,
          settleMs,
          policy,
          anchor: opts.anchor,
          log: (line) => console.log(`  ${line}`),
        });

      if (opts.once) {
        const result = await sweep();
        console.log(
          `Sweep done: ${result.ingested.length} session(s) recorded, ${result.skipped} skipped, ${result.violations} policy violation(s).`,
        );
        store.close();
        if (result.violations > 0) process.exit(1);
        return;
      }

      const intervalMs = Math.max(5, Number(opts.interval)) * 1000;
      console.log('\n  traceglass watch — every finished Claude Code session becomes evidence.');
      console.log(
        `  Sweeping every ${intervalMs / 1000}s (settle ${settleMs / 1000}s)${policy ? ' · policy checks on' : ''}${opts.anchor ? ' · anchoring on' : ''}.`,
      );
      console.log('  Press Ctrl+C to stop.\n');
      await sweep();
      const timer = setInterval(() => void sweep(), intervalMs);
      const shutdown = () => {
        clearInterval(timer);
        store.close();
        process.exit(0);
      };
      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
    },
  );

program
  .command('recover')
  .description(
    'Finalize orphaned recording journals (crashed SDK runs) into stored, verifiable runs',
  )
  .action(() => {
    const journalDir = join(dataDir(), 'journal');
    if (!existsSync(journalDir)) {
      console.log('No journals to recover.');
      return;
    }
    const files = readdirSync(journalDir).filter((f) => f.endsWith('.jsonl'));
    if (files.length === 0) {
      console.log('No journals to recover.');
      return;
    }
    const store = openStore();
    let recovered = 0;
    for (const f of files) {
      const file = join(journalDir, f);
      try {
        const contents = readJournal(file);
        if (store.getRun(contents.meta.id)) {
          console.log(`Journal ${f}: run already stored; removing journal.`);
          unlinkSync(file);
          continue;
        }
        const run = maybeSign(finalizeJournal(contents));
        store.saveRun(run);
        unlinkSync(file);
        recovered += 1;
        console.log(
          `Recovered "${run.id}" (${run.totals.steps} steps, status ${run.status}${run.status === 'failed' ? ' — recording did not end cleanly' : ''}).`,
        );
      } catch (e) {
        console.error(`✗ Journal ${f}: ${friendly(e)} (left in place)`);
      }
    }
    console.log(`Recovered ${recovered} run(s).`);
    store.close();
  });

program
  .command('keygen')
  .description('Generate a local Ed25519 signing keypair; new ingests are signed automatically')
  .option('--force', 'replace an existing keypair')
  .action((opts: { force?: boolean }) => {
    let result: ReturnType<typeof generateKeys>;
    try {
      result = generateKeys({ force: opts.force });
    } catch (e) {
      return die(friendly(e));
    }
    console.log(`Generated Ed25519 signing key (keyId ${result.keyId}).`);
    console.log(`Public key: ${result.publicKeyFile}`);
    console.log('New runs will be signed at ingest. The private key stays local (mode 0600).');
  });

program
  .command('redact')
  .description(
    'Irreversibly remove sensitive values from a stored run — the hash chain and signature still verify',
  )
  .argument('<runId>', 'id of a stored run')
  .option('--path <path...>', 'leaf path(s) to remove, e.g. "input.ssn" or "<stepId>#input.ssn"')
  .option(
    '--pattern <name...>',
    `built-in detector(s): ${DEFAULT_PATTERNS.map((p) => p.name).join(', ')}`,
  )
  .option('--reason <text>', 'recorded in the redaction audit trail')
  .option('--legacy', 're-chain + re-sign a pre-0.6 run (weaker guarantee — see docs)')
  .option('--yes', 'actually perform the redaction (without this, it is a dry run)')
  .option('--json', 'machine-readable output')
  .action(
    (
      runId: string,
      opts: {
        path?: string[];
        pattern?: string[];
        reason?: string;
        legacy?: boolean;
        yes?: boolean;
        json?: boolean;
      },
    ) => {
      const store = openStore();
      const run = store.getRun(runId);
      if (!run) return die(`No stored run with id "${runId}".`);
      if (!opts.path && !opts.pattern) {
        return die('Nothing to redact — pass --path and/or --pattern.');
      }
      let patterns;
      try {
        patterns = opts.pattern ? patternsByName(opts.pattern) : undefined;
      } catch (e) {
        return die(friendly(e));
      }

      const redactOpts = {
        ...(opts.path ? { paths: opts.path } : {}),
        ...(patterns ? { patterns } : {}),
        ...(opts.reason !== undefined ? { reason: opts.reason } : {}),
      };

      let result;
      let previousRunHash: string | undefined;
      try {
        if (opts.legacy) {
          const legacy = redactLegacyRun(run, redactOpts);
          result = legacy;
          previousRunHash = legacy.previousRunHash;
        } else {
          result = redactRun(run, redactOpts);
        }
      } catch (e) {
        return die(friendly(e));
      }

      if (result.redacted.length === 0) {
        const uncommitted = !opts.legacy && run.steps.some((s) => !s.commitments);
        console.log(
          uncommitted
            ? `Nothing removed — this run was recorded before v0.6 and carries no commitments.\n  Re-run with --legacy to redact it by re-chaining and re-signing (weaker guarantee:\n  the anchor changes, so the original values can no longer be proven).`
            : 'Nothing matched — no values removed.',
        );
        store.close();
        return;
      }

      // Legacy re-chaining invalidates the old signature; re-sign the new chain.
      let finalRun = result.run;
      if (opts.legacy) finalRun = maybeSign({ ...finalRun, signature: undefined } as Run);

      const integrity = verifyRunFull(finalRun);

      if (opts.json) {
        console.log(
          JSON.stringify(
            {
              runId,
              dryRun: !opts.yes,
              legacy: Boolean(opts.legacy),
              redacted: result.redacted,
              runHashUnchanged: !opts.legacy && finalRun.runHash === run.runHash,
              ...(previousRunHash ? { previousRunHash, newRunHash: finalRun.runHash } : {}),
              integrity,
            },
            null,
            2,
          ),
        );
      } else {
        console.log(
          `${opts.yes ? 'Redacted' : 'DRY RUN — would redact'} ${result.redacted.length} value(s):`,
        );
        for (const path of result.redacted) console.log(`  - ${path}`);
        if (opts.legacy) {
          console.log(
            `\n  ! Legacy mode: this run was re-chained and re-signed.\n    anchor ${previousRunHash} -> ${finalRun.runHash}\n    A verifier can confirm the redacted record is intact and signed,\n    but can no longer prove what the original values were.`,
          );
        } else {
          console.log(
            `\n  Integrity anchor UNCHANGED (${finalRun.runHash.slice(0, 16)}…) — the chain and signature still verify.`,
          );
        }
        console.log(`  ${integrity.chain.message}`);
        console.log(`  ${integrity.signature.message}`);
        if (!opts.yes) console.log('\n  Re-run with --yes to apply. This cannot be undone.');
      }

      if (opts.yes) {
        if (!integrity.ok) {
          return die('Refusing to save: the redacted run does not verify. Nothing was changed.');
        }
        store.replaceRedacted(finalRun);
        appendFileSync(
          join(dataDir(), 'audit.jsonl'),
          JSON.stringify({
            reason: 'redaction',
            runId,
            legacy: Boolean(opts.legacy),
            paths: result.redacted,
            note: opts.reason,
            at: new Date().toISOString(),
          }) + '\n',
        );
      }
      store.close();
    },
  );

program
  .command('export')
  .description(
    'Export a stored run as a portable .tgev evidence file, verifiable offline by anyone',
  )
  .argument('<runId>', 'id of a stored run')
  .option('-o, --out <file>', 'output file (default: run-<id>.tgev)')
  .action((runId: string, opts: { out?: string }) => {
    const store = openStore();
    const run = store.getRun(runId);
    if (!run) return die(`No stored run with id "${runId}".`);
    const out = resolve(opts.out ?? `run-${runId}.tgev`);
    writeFileSync(out, JSON.stringify(createEnvelope(run), null, 2));
    console.log(`Exported evidence → ${out}`);
    console.log(`runHash: ${run.runHash}`);
    console.log(
      run.signature
        ? `signed:  yes (keyId ${run.signature.keyId})`
        : 'signed:  no (run `traceglass keygen` to sign future ingests)',
    );
    console.log('Anyone can check it with: traceglass verify <file> — no store or keys needed.');
    store.close();
  });

program
  .command('anchor')
  .description(
    'Append run anchors (runHash + signature) to a JSONL file you can push to WORM storage',
  )
  .argument('[runId]', 'anchor a single stored run')
  .option('--all', 'anchor every stored run')
  .option('-o, --out <file>', 'anchors file (default: ~/.traceglass/anchors.jsonl)')
  .action(async (runId: string | undefined, opts: { all?: boolean; out?: string }) => {
    if (!runId && !opts.all) return die('Provide a runId or --all.');
    const store = openStore();
    const runs: Run[] = [];
    if (opts.all) {
      for (const summary of store.listRuns()) {
        const run = store.getRun(summary.id);
        if (run) runs.push(run);
      }
    } else if (runId) {
      const run = store.getRun(runId);
      if (!run) return die(`No stored run with id "${runId}".`);
      runs.push(run);
    }
    const sink = new FileAnchorSink(resolve(opts.out ?? defaultAnchorsPath()));
    const existing = sink.existingRunIds();
    const fresh = runs.filter((r) => !existing.has(r.id));
    await sink.append(fresh.map(anchorRecordForRun));
    const skipped = runs.length - fresh.length;
    console.log(
      `Anchored ${fresh.length} run(s)${skipped > 0 ? ` (${skipped} already anchored)` : ''} → ${resolve(opts.out ?? defaultAnchorsPath())}`,
    );
    store.close();
  });

program.parseAsync(process.argv);
