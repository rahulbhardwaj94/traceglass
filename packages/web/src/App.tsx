import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Run, VerifyResult } from './types.js';
import { api, runIdFromUrl, pickerFromUrl } from './api.js';
import { clockOf } from './format.js';
import { indexStepsById, loopStepIdSet, medianNonZeroCost } from './lib/derive.js';
import { Icon } from './components/Icon.js';
import { IntegrityBadge } from './components/IntegrityBadge.js';
import { Timeline } from './components/Timeline.js';
import { Transport } from './components/Transport.js';
import { StepDetail } from './components/StepDetail.js';
import { ReasoningPanel } from './components/ReasoningPanel.js';
import { Totals } from './components/Totals.js';
import { Warnings } from './components/Warnings.js';
import { SessionPicker } from './components/SessionPicker.js';

const PLAY_INTERVAL_MS = 700;

export function App() {
  const [run, setRun] = useState<Run | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState(0);
  const [playing, setPlaying] = useState(false);

  // With no run id in the URL, show the session picker landing screen.
  const runId = runIdFromUrl();
  const showPicker = pickerFromUrl() || !runId;

  // Load the run + verification once on mount (skipped in picker mode).
  useEffect(() => {
    if (showPicker || !runId) return;
    let cancelled = false;
    (async () => {
      try {
        const [r, v] = await Promise.all([api.getRun(runId), api.verify(runId)]);
        if (cancelled) return;
        setRun(r);
        setVerify(v);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [showPicker, runId]);

  const select = useCallback((index: number) => setSelected(index), []);

  // Playback advances the scrubber; stops at the end.
  useEffect(() => {
    if (!playing || !run) return;
    const id = window.setInterval(() => {
      setSelected((cur) => {
        if (cur >= run.steps.length - 1) {
          setPlaying(false);
          return cur;
        }
        return cur + 1;
      });
    }, PLAY_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [playing, run]);

  // Keyboard scrubbing.
  useEffect(() => {
    if (!run) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight') setSelected((c) => Math.min(run.steps.length - 1, c + 1));
      else if (e.key === 'ArrowLeft') setSelected((c) => Math.max(0, c - 1));
      else if (e.key === ' ') {
        e.preventDefault();
        setPlaying((p) => !p);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [run]);

  const loopIds = useMemo(() => (run ? loopStepIdSet(run) : new Set<string>()), [run]);
  const indexById = useMemo(() => (run ? indexStepsById(run.steps) : new Map()), [run]);
  const median = useMemo(() => (run ? medianNonZeroCost(run.steps) : 0), [run]);

  if (showPicker) {
    return <SessionPicker />;
  }

  if (error) {
    return (
      <div className="app app--msg">
        <div className="brand">
          <span className="wordmark">traceglass</span>
          <span className="tag">flight recorder</span>
        </div>
        <p className="msg-error">{error}</p>
      </div>
    );
  }
  if (!run) {
    return (
      <div className="app app--msg">
        <div className="brand">
          <span className="wordmark">traceglass</span>
          <span className="tag">flight recorder</span>
        </div>
        <p className="msg-muted">Loading run…</p>
      </div>
    );
  }

  const step = run.steps[selected]!;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="wordmark">traceglass</span>
          <span className="tag">flight recorder</span>
        </div>

        <div className="runmeta">
          <span className="runid mono">{run.id}</span>
          <span className="dot" />
          <span className="runtime mono">{clockOf(run.startedAt)}</span>
          <span className="dot" />
          <span className={'runstatus ' + run.status}>
            <span className="rs-led" />
            {run.status === 'failed' ? 'Run failed' : 'Run completed'}
          </span>
        </div>

        <div className="topright">
          <IntegrityBadge run={run} verify={verify} />
          <a className="export" href={api.reportUrl(run.id)} target="_blank" rel="noreferrer">
            <Icon name="export" size={16} /> Export audit report
          </a>
        </div>
      </header>

      <Timeline run={run} selected={selected} loopStepIds={loopIds} onSelect={select} />
      <Transport
        run={run}
        selected={selected}
        playing={playing}
        onSelect={select}
        onPlayToggle={() => setPlaying((p) => !p)}
      />

      <main className="main">
        <div className="col-left">
          <StepDetail step={step} run={run} median={median} />
          <ReasoningPanel steps={run.steps} selected={selected} />
        </div>
        <div className="col-right">
          <Totals run={run} selected={selected} />
          <Warnings
            run={run}
            selected={selected}
            median={median}
            stepIndexById={indexById}
            onJump={(i) => {
              setPlaying(false);
              select(i);
            }}
          />
        </div>
      </main>
    </div>
  );
}
