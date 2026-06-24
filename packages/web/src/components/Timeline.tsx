import { useCallback, useEffect, useRef } from 'react';
import type { Run } from '../types.js';
import { clockOf, ms, typeLabel } from '../format.js';
import { loopSpan } from '../lib/derive.js';
import { Icon } from './Icon.js';

interface Props {
  run: Run;
  selected: number;
  loopStepIds: Set<string>;
  onSelect: (index: number) => void;
}

export function Timeline({ run, selected, loopStepIds, onSelect }: Props) {
  const railRef = useRef<HTMLDivElement>(null);
  const dragging = useRef(false);
  const steps = run.steps;
  const n = steps.length;
  const frac = (i: number): number => (n === 1 ? 0.5 : i / (n - 1));

  const pick = useCallback(
    (clientX: number) => {
      const el = railRef.current;
      if (!el) return;
      const r = el.getBoundingClientRect();
      const f = Math.min(1, Math.max(0, (clientX - r.left) / r.width));
      onSelect(Math.round(f * (n - 1)));
    },
    [n, onSelect],
  );

  useEffect(() => {
    const move = (e: PointerEvent) => {
      if (dragging.current) pick(e.clientX);
    };
    const up = () => {
      dragging.current = false;
      document.body.classList.remove('grabbing');
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    return () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
    };
  }, [pick]);

  const span = loopSpan(steps, loopStepIds);

  // Grow the track when crowded so many-step runs space out and scroll
  // horizontally instead of collapsing into an unreadable smear.
  const trackMinWidth = `max(100%, ${n * 86}px)`;

  return (
    <section className="timeline">
      <div className="tl-head">
        <span className="tl-title">Execution timeline</span>
        <span className="tl-sub mono">
          {n} steps · {ms(run.totals.durationMs)} wall-clock
        </span>
      </div>

      <div className="tl-row">
        <div className="tl-track" style={{ minWidth: trackMinWidth }}>
          <div
            className="tl-rail"
            ref={railRef}
            onPointerDown={(e) => {
              dragging.current = true;
              document.body.classList.add('grabbing');
              pick(e.clientX);
            }}
          >
            <div className="tl-base" />
            <div className="tl-fill" style={{ width: `${frac(selected) * 100}%` }} />

            {span && (
            <div
              className="tl-loop"
              style={{
                left: `${frac(span.start) * 100}%`,
                width: `${(frac(span.end) - frac(span.start)) * 100}%`,
              }}
            >
              <span className="tl-loop-tag mono">
                <Icon name="loop" size={11} /> loop ×{span.end - span.start + 1}
              </span>
            </div>
          )}

          {steps.map((s, i) => {
            const cls = [
              'tl-node',
              s.type,
              loopStepIds.has(s.id) ? 'loop' : '',
              i < selected ? 'past' : '',
              i === selected ? 'active' : '',
              i > selected ? 'future' : '',
            ]
              .filter(Boolean)
              .join(' ');
            return (
              <button
                key={s.id}
                className={cls}
                style={{ left: `${frac(i) * 100}%` }}
                onPointerDown={(e) => {
                  e.stopPropagation();
                  onSelect(i);
                }}
                title={`#${i + 1} ${typeLabel(s.type)} — ${s.label}`}
              >
                <span className="tl-dot" />
                <span className="tl-label">{typeLabel(s.type)}</span>
                <span className="tl-time mono">{clockOf(s.startedAt)}</span>
              </button>
            );
          })}

          </div>
        </div>
      </div>
    </section>
  );
}
