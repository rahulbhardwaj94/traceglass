import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { Run } from '@traceglass/core';
import { dataDir } from './paths.js';

/**
 * Anchor records externalize a run's integrity anchor (runHash + signature) so
 * it can be pinned somewhere the store can't touch — printed, emailed, or
 * pushed to WORM storage (e.g. S3 Object Lock). A verifier later compares a
 * run's recomputed anchor against this out-of-band copy.
 *
 * AnchorSink is the plugin seam: v0.3 ships only the local JSONL file sink
 * (zero network egress). RFC 3161 timestamping or Sigstore/Rekor become
 * additional sinks later without touching callers.
 */
export interface AnchorRecord {
  version: 1;
  runId: string;
  runHash: string;
  keyId?: string;
  signature?: string;
  anchoredAt: string;
}

export interface AnchorSink {
  append(records: AnchorRecord[]): Promise<void>;
}

/** Appends anchor records as JSONL; idempotent per runId. */
export class FileAnchorSink implements AnchorSink {
  constructor(private readonly path: string) {}

  /** runIds already present in the file (so re-anchoring is a no-op). */
  existingRunIds(): Set<string> {
    if (!existsSync(this.path)) return new Set();
    const ids = new Set<string>();
    for (const line of readFileSync(this.path, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const parsed = JSON.parse(line) as { runId?: string };
        if (parsed.runId) ids.add(parsed.runId);
      } catch {
        // Skip malformed lines; they don't block new anchors.
      }
    }
    return ids;
  }

  async append(records: AnchorRecord[]): Promise<void> {
    if (records.length === 0) return;
    mkdirSync(dirname(this.path), { recursive: true });
    const lines = records.map((r) => JSON.stringify(r) + '\n').join('');
    appendFileSync(this.path, lines);
  }
}

export function defaultAnchorsPath(): string {
  return join(dataDir(), 'anchors.jsonl');
}

export function anchorRecordForRun(run: Run): AnchorRecord {
  return {
    version: 1,
    runId: run.id,
    runHash: run.runHash,
    ...(run.signature ? { keyId: run.signature.keyId, signature: run.signature.signature } : {}),
    anchoredAt: new Date().toISOString(),
  };
}
