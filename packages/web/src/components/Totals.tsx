import type { Run } from '../types.js';
import { accumulate, commas, money, ms } from '../format.js';
import { useTween } from '../hooks/useTween.js';

/** Wall-clock elapsed from run start to the end of the selected step. */
function elapsedAt(run: Run, selected: number): number {
  const step = run.steps[selected];
  if (!step) return 0;
  const t0 = Date.parse(run.startedAt);
  const offset = Date.parse(step.startedAt) - t0;
  return Math.max(0, offset) + step.durationMs;
}

/** Running totals that climb as you scrub (PRD §5.4). */
export function Totals({ run, selected }: { run: Run; selected: number }) {
  const acc = accumulate(run.steps, selected);
  const tokens = useTween(acc.tokens);
  const cost = useTween(acc.cost);
  const elapsed = useTween(elapsedAt(run, selected));

  return (
    <div className="totals">
      <div className="tcard">
        <div className="tc-v mono">
          <b>{selected + 1}</b>
          <span className="tc-of"> / {run.totals.steps}</span>
        </div>
        <div className="tc-k">Step</div>
        <div className="tc-sub">of run</div>
      </div>
      <div className="tcard">
        <div className="tc-v mono">{commas(tokens)}</div>
        <div className="tc-k">Tokens</div>
        <div className="tc-sub">accumulated</div>
      </div>
      <div className="tcard accent">
        <div className="tc-v mono">{money(run.currency, cost)}</div>
        <div className="tc-k">Cost</div>
        <div className="tc-sub">accumulated</div>
      </div>
      <div className="tcard">
        <div className="tc-v mono">{ms(elapsed)}</div>
        <div className="tc-k">Elapsed</div>
        <div className="tc-sub">from start</div>
      </div>
    </div>
  );
}
