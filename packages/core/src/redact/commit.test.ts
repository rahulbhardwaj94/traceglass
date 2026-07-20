import { describe, expect, it } from 'vitest';
import {
  buildCommitments,
  buildFieldCommitments,
  commitmentFor,
  getAtPath,
  setAtPath,
  verifyCommitments,
  walkLeaves,
} from './commit.js';

describe('walkLeaves', () => {
  it('visits every scalar leaf with a dotted/indexed path', () => {
    const seen: Array<[string, unknown]> = [];
    walkLeaves({ a: 1, b: { c: 'x' }, d: [true, null] }, (p, v) => seen.push([p, v]), 'input');
    expect(seen).toEqual([
      ['input.a', 1],
      ['input.b.c', 'x'],
      ['input.d[0]', true],
      ['input.d[1]', null],
    ]);
  });

  it('treats empty containers as leaves so emptiness is committed too', () => {
    const seen: string[] = [];
    walkLeaves({ a: {}, b: [] }, (p) => seen.push(p), 'input');
    expect(seen).toEqual(['input.a', 'input.b']);
  });

  it('handles a bare scalar payload as a single root leaf', () => {
    const seen: Array<[string, unknown]> = [];
    walkLeaves('hello', (p, v) => seen.push([p, v]), 'output');
    expect(seen).toEqual([['output', 'hello']]);
  });
});

describe('getAtPath / setAtPath', () => {
  const obj = { a: { b: [{ c: 'deep' }] } };

  it('reads nested and indexed paths', () => {
    expect(getAtPath(obj, 'a.b[0].c')).toBe('deep');
    expect(getAtPath(obj, '')).toBe(obj);
    expect(getAtPath(obj, 'a.missing')).toBeUndefined();
  });

  it('writes without mutating the original', () => {
    const next = setAtPath(obj, 'a.b[0].c', 'REDACTED');
    expect(getAtPath(next, 'a.b[0].c')).toBe('REDACTED');
    expect(getAtPath(obj, 'a.b[0].c')).toBe('deep'); // original untouched
  });
});

describe('commitments', () => {
  it('a commitment depends on both salt and value', () => {
    expect(commitmentFor('s1', 'v')).not.toBe(commitmentFor('s2', 'v'));
    expect(commitmentFor('s1', 'v')).not.toBe(commitmentFor('s1', 'w'));
    expect(commitmentFor('s1', 'v')).toBe(commitmentFor('s1', 'v')); // deterministic
  });

  it('salts are unique per leaf, so identical values do not collide', () => {
    const { commitments, salts } = buildFieldCommitments('input', { a: 'same', b: 'same' });
    expect(salts['input.a']).not.toBe(salts['input.b']);
    expect(commitments['input.a']).not.toBe(commitments['input.b']);
  });

  it('builds commitments across every present payload field only', () => {
    const built = buildCommitments({ input: { x: 1 }, dataPayload: { y: 2 } });
    expect(Object.keys(built.commitments).sort()).toEqual(['dataPayload.y', 'input.x']);
    expect(Object.keys(built.salts).sort()).toEqual(['dataPayload.y', 'input.x']);
  });

  it('verifies untouched payloads and detects a tampered visible leaf', () => {
    const payload = { input: { ssn: '123-45-6789', note: 'ok' } };
    const { commitments, salts } = buildCommitments(payload);

    const clean = verifyCommitments(payload, commitments, salts);
    expect(clean.ok).toBe(true);
    expect(clean.verified.sort()).toEqual(['input.note', 'input.ssn']);
    expect(clean.redacted).toEqual([]);

    const tampered = { input: { ssn: '999-99-9999', note: 'ok' } };
    const bad = verifyCommitments(tampered, commitments, salts);
    expect(bad.ok).toBe(false);
    expect(bad.mismatched).toEqual(['input.ssn']);
    expect(bad.verified).toEqual(['input.note']); // the rest still checks out
  });

  it('a redacted leaf (salt destroyed) verifies as redacted, not as tampering', () => {
    const payload = { input: { ssn: '123-45-6789', note: 'ok' } };
    const { commitments, salts } = buildCommitments(payload);

    // Redact: drop the value and destroy the salt.
    const redactedPayload = { input: { ssn: '[traceglass:redacted]', note: 'ok' } };
    const remainingSalts = { ...salts };
    delete remainingSalts['input.ssn'];

    const result = verifyCommitments(redactedPayload, commitments, remainingSalts);
    expect(result.ok).toBe(true); // NOT flagged as tampering
    expect(result.redacted).toEqual(['input.ssn']);
    expect(result.verified).toEqual(['input.note']); // sibling still verifiable
  });

  it('destroying the salt makes the original unrecoverable by brute force', () => {
    // With the salt gone, a verifier cannot confirm ANY guess — even the truth.
    const { commitments, salts } = buildCommitments({ input: { flag: true } });
    const commitment = commitments['input.flag']!;
    const realSalt = salts['input.flag']!;
    expect(commitmentFor(realSalt, true)).toBe(commitment); // provable WITH salt
    // Without the salt, guessing the value gets you nothing:
    expect(commitmentFor('guessed-salt', true)).not.toBe(commitment);
  });
});
