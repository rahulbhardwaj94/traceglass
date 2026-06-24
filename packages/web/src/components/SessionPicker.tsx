import { useEffect, useState } from 'react';
import type { RunSummary, SessionInfo } from '../types.js';
import { api } from '../api.js';
import { Icon } from './Icon.js';

/** Navigate to a run by reloading with ?run=<id> — re-mounts App into replay. */
function openRun(id: string) {
  window.location.search = `?run=${encodeURIComponent(id)}`;
}

function relTime(iso: string): string {
  if (!iso) return '';
  const d = Date.parse(iso);
  if (!Number.isFinite(d)) return '';
  const mins = Math.round((Date.now() - d) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

/** Last path segment of a cwd, for a compact project label. */
function shortProject(p: string): string {
  const parts = p.split(/[/\\]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1]! : p;
}

export function SessionPicker() {
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [s, r] = await Promise.all([api.listSessions(), api.listRuns()]);
        if (cancelled) return;
        setSessions(s);
        setRuns(r);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function pick(session: SessionInfo) {
    setBusy(session.id);
    setError(null);
    try {
      const { runId } = await api.ingestSession(session.id);
      openRun(runId);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(null);
    }
  }

  return (
    <div className="picker">
      <header className="picker-head">
        <div className="brand">
          <span className="wordmark">traceglass</span>
          <span className="tag">flight recorder</span>
        </div>
        <p className="picker-sub">
          Pick an agent run to replay. traceglass ingests your Claude Code
          sessions directly — every tool call, token, and the data the agent
          touched — and never sends a byte off this machine.
        </p>
      </header>

      {error && <p className="msg-error">{error}</p>}

      {runs.length > 0 && (
        <section className="picker-section">
          <h2 className="picker-h">Already ingested</h2>
          <ul className="picker-list">
            {runs.map((r) => (
              <li key={r.id}>
                <button className="picker-row" onClick={() => openRun(r.id)}>
                  <span className={'picker-led ' + r.status} />
                  <span className="picker-row-main">
                    <span className="picker-row-title">{r.name}</span>
                    <span className="picker-row-meta mono">
                      {r.steps} steps · {r.currency} {r.cost.toFixed(2)}
                    </span>
                  </span>
                  <span className="picker-go">
                    <Icon name="fwd" size={16} />
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="picker-section">
        <h2 className="picker-h">
          Claude Code sessions{sessions ? ` (${sessions.length})` : ''}
        </h2>
        {sessions === null && !error && <p className="msg-muted">Scanning ~/.claude/projects…</p>}
        {sessions !== null && sessions.length === 0 && (
          <p className="msg-muted">
            No Claude Code sessions found under <span className="mono">~/.claude/projects</span>.
          </p>
        )}
        <ul className="picker-list">
          {sessions?.map((s) => (
            <li key={s.id}>
              <button
                className="picker-row"
                disabled={busy !== null}
                onClick={() => pick(s)}
              >
                <span className="picker-proj mono">{shortProject(s.project)}</span>
                <span className="picker-row-main">
                  <span className="picker-row-title">{s.firstPrompt}</span>
                  <span className="picker-row-meta mono">
                    {s.messageCount} msgs · {relTime(s.endedAt)}
                  </span>
                </span>
                <span className="picker-go">
                  {busy === s.id ? <span className="picker-spin">…</span> : <Icon name="fwd" size={16} />}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
