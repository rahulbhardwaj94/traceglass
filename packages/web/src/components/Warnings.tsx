import type { Run, WarningKind } from '../types.js';
import { warningMeta } from '../lib/derive.js';
import { Icon, type IconName } from './Icon.js';

const KIND_LABEL: Record<WarningKind, string> = {
  loop: 'Loop',
  high_cost_step: 'High cost',
  error: 'Error',
};

const WARN_ICON: Record<WarningKind, IconName> = {
  loop: 'loop',
  high_cost_step: 'cost',
  error: 'alert',
};

// A stable CSS modifier per kind (shorter than the model's enum key).
const KIND_CLASS: Record<WarningKind, string> = {
  loop: 'loop',
  high_cost_step: 'high_cost',
  error: 'error',
};

interface Props {
  run: Run;
  selected: number;
  median: number;
  stepIndexById: Map<string, number>;
  onJump: (index: number) => void;
}

export function Warnings({ run, selected, median, stepIndexById, onJump }: Props) {
  const ws = run.warnings;
  return (
    <div className="card warnings">
      <div className="wn-head">
        <span className="wn-title">Warnings</span>
        <span className="wn-count mono">{ws.length}</span>
      </div>
      {ws.length === 0 ? (
        <p className="wn-empty">No warnings — clean run.</p>
      ) : (
        <div className="wn-list">
          {ws.map((w, i) => {
            const idxs = w.stepIds
              .map((id) => stepIndexById.get(id))
              .filter((n): n is number => n !== undefined);
            const active = idxs.includes(selected);
            const first = idxs[0] ?? 0;
            return (
              <button
                key={i}
                className={'wn ' + KIND_CLASS[w.kind] + (active ? ' active' : '')}
                onClick={() => onJump(first)}
              >
                <span className="wn-rail" />
                <span className="wn-ico">
                  <Icon name={WARN_ICON[w.kind]} size={15} />
                </span>
                <span className="wn-body">
                  <span className="wn-row1">
                    <span className="wn-kind">{KIND_LABEL[w.kind]}</span>
                    <span className="wn-meta mono">{warningMeta(w, run.steps, median)}</span>
                  </span>
                  <span className="wn-msg">{w.message}</span>
                  <span className="wn-jump mono">jump to step #{first + 1} →</span>
                </span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
