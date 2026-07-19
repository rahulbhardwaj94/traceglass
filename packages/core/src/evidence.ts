import { parseRun, type Run } from './model.js';

/**
 * Portable evidence envelope (.tgev): a single self-contained JSON file a
 * third party can verify offline — the hash chain from the steps themselves,
 * and the signature from the public key embedded in run.signature. No store,
 * no keys, no network required.
 */

export const EVIDENCE_FORMAT_VERSION = 1;

export interface EvidenceEnvelope {
  formatVersion: typeof EVIDENCE_FORMAT_VERSION;
  exportedAt: string;
  run: Run;
}

export function createEnvelope(run: Run): EvidenceEnvelope {
  return { formatVersion: EVIDENCE_FORMAT_VERSION, exportedAt: new Date().toISOString(), run };
}

/**
 * Accept either an evidence envelope or a bare Run JSON value; validate and
 * return the run. Rejects unknown envelope versions with a clear message.
 */
export function parseEvidence(value: unknown): Run {
  if (value && typeof value === 'object' && 'formatVersion' in value) {
    const envelope = value as { formatVersion: unknown; run?: unknown };
    if (envelope.formatVersion !== EVIDENCE_FORMAT_VERSION) {
      throw new Error(
        `Unsupported evidence format version ${String(envelope.formatVersion)} (this build reads version ${EVIDENCE_FORMAT_VERSION}).`,
      );
    }
    return parseRun(envelope.run);
  }
  return parseRun(value);
}
