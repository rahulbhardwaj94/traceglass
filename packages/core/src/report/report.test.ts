import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ingestNative } from '../ingest/index.js';
import { finalizeRun } from '../pipeline.js';
import { renderReport } from './html.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../../fixtures');
const run = finalizeRun(
  ingestNative(JSON.parse(readFileSync(join(fixturesDir, 'sample-run-loop.json'), 'utf8'))),
);

describe('renderReport', () => {
  const html = renderReport(run);

  it('emits pure ASCII (no mojibake-prone bytes)', () => {
    // eslint-disable-next-line no-control-regex
    expect(html).toMatch(/^[\x00-\x7F]*$/);
  });

  it('folds the middle dot in the run name to a numeric entity', () => {
    expect(run.name).toContain('·');
    expect(html).toContain('&#183;');
    expect(html).not.toContain('·');
  });

  it('includes the integrity anchor and verified badge', () => {
    expect(html).toContain(run.runHash);
    expect(html).toContain('Integrity verified');
  });

  it('surfaces the loop warning and a data payload', () => {
    expect(html).toContain('called 3x in a row');
    expect(html).toContain('outstanding');
  });
});
