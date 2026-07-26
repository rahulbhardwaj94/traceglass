import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { keyIdFromPublicKey, signRun, type Run } from '@traceglass/core';
import { dataDir } from './paths.js';

/**
 * Local Ed25519 signing keys. The private key never leaves <dataDir>/keys and
 * is written 0600. Regenerating keys orphans signatures made with the old key
 * (they stay verifiable via the public key embedded in each run's signature,
 * but no longer match the current keyId).
 */

export function keysDir(): string {
  return join(dataDir(), 'keys');
}

function privateKeyPath(): string {
  return join(keysDir(), 'private.pem');
}

function publicKeyPath(): string {
  return join(keysDir(), 'public.pem');
}

export interface LoadedKeys {
  privateKeyPem: string;
  publicKeyPem: string;
  keyId: string;
}

/** Generate a keypair on disk. Refuses to overwrite unless force is set. */
export function generateKeys(opts: { force?: boolean } = {}): {
  publicKeyPem: string;
  keyId: string;
  publicKeyFile: string;
  privateKeyFile: string;
  /** False when the filesystem ignored the 0600 request (Windows). */
  ownerOnly: boolean;
} {
  if (existsSync(privateKeyPath()) && !opts.force) {
    throw new Error(
      `A signing key already exists at ${privateKeyPath()}. Re-run with --force to replace it (old signatures keep their embedded public key but will no longer match the current keyId).`,
    );
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  mkdirSync(keysDir(), { recursive: true });
  writeFileSync(privateKeyPath(), privateKeyPem, { mode: 0o600 });
  writeFileSync(publicKeyPath(), publicKeyPem);
  return {
    publicKeyPem,
    keyId: keyIdFromPublicKey(publicKeyPem),
    publicKeyFile: publicKeyPath(),
    privateKeyFile: privateKeyPath(),
    ownerOnly: privateKeyIsOwnerOnly(),
  };
}

/**
 * Did the 0600 request actually take effect?
 *
 * Windows has no POSIX permission bits — Node's mode argument only toggles the
 * read-only flag there, so the key lands world-readable to every account on the
 * machine. The protection is real on POSIX and absent on Windows, and callers
 * must not print a blanket "mode 0600" claim that is false on one of them.
 */
export function privateKeyIsOwnerOnly(): boolean {
  if (!existsSync(privateKeyPath())) return false;
  return (statSync(privateKeyPath()).mode & 0o077) === 0;
}

/** Load the keypair, or null if none has been generated. */
export function loadKeys(): LoadedKeys | null {
  if (!existsSync(privateKeyPath()) || !existsSync(publicKeyPath())) return null;
  const privateKeyPem = readFileSync(privateKeyPath(), 'utf8');
  const publicKeyPem = readFileSync(publicKeyPath(), 'utf8');
  return { privateKeyPem, publicKeyPem, keyId: keyIdFromPublicKey(publicKeyPem) };
}

/** Sign the run if local keys exist and it isn't already signed; else pass through. */
export function maybeSign(run: Run): Run {
  if (run.signature) return run;
  const keys = loadKeys();
  if (!keys) return run;
  return signRun(run, keys.privateKeyPem, keys.publicKeyPem);
}
