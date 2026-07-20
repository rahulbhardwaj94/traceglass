import type { Run, RunSummary, SessionInfo, VerifyResult } from './types.js';

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} → ${res.status}`);
  return (await res.json()) as T;
}

async function postJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { method: 'POST' });
  if (!res.ok) throw new Error(`${url} → ${res.status}`);
  return (await res.json()) as T;
}

export const api = {
  listRuns: () => getJson<RunSummary[]>('/api/runs'),
  getRun: (id: string) => getJson<Run>(`/api/runs/${encodeURIComponent(id)}`),
  verify: (id: string) => getJson<VerifyResult>(`/api/runs/${encodeURIComponent(id)}/verify`),
  reportUrl: (id: string) => `/api/runs/${encodeURIComponent(id)}/report`,
  listSessions: () => getJson<SessionInfo[]>('/api/sessions'),
  liveRun: (id: string) => getJson<Run>(`/api/live/${encodeURIComponent(id)}`),
  ingestSession: (id: string) =>
    postJson<{ runId: string }>(`/api/sessions/${encodeURIComponent(id)}/ingest`),
};

/** Read the run id from the URL (?run=<id>). */
export function runIdFromUrl(): string | null {
  return new URLSearchParams(window.location.search).get('run');
}

/** Read the live run id from the URL (?live=<id>) — tail mode (v0.7). */
export function liveIdFromUrl(): string | null {
  return new URLSearchParams(window.location.search).get('live');
}

/** True when the URL requests the session-picker landing screen (?picker=1). */
export function pickerFromUrl(): boolean {
  return new URLSearchParams(window.location.search).get('picker') !== null;
}
