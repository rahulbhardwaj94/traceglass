import { homedir } from 'node:os';
import { join } from 'node:path';

/** Directory where traceglass keeps its append-only store. */
export function dataDir(): string {
  return process.env.TRACEGLASS_HOME ?? join(homedir(), '.traceglass');
}

/** Path to the SQLite store file. */
export function storePath(): string {
  return join(dataDir(), 'traceglass.sqlite');
}
