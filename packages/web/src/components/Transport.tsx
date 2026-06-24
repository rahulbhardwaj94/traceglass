import type { Run } from '../types.js';
import { typeLabel } from '../format.js';
import { Icon } from './Icon.js';

interface Props {
  run: Run;
  selected: number;
  playing: boolean;
  onSelect: (index: number) => void;
  onPlayToggle: () => void;
}

export function Transport({ run, selected, playing, onSelect, onPlayToggle }: Props) {
  const n = run.steps.length;
  const last = n - 1;
  return (
    <div className="transport">
      <div className="tp-buttons">
        <button className="tp" onClick={() => onSelect(0)} title="Rewind to start">
          <Icon name="rewind" />
        </button>
        <button className="tp" onClick={() => onSelect(Math.max(0, selected - 1))} title="Step back">
          <Icon name="back" />
        </button>
        <button className="tp play" onClick={onPlayToggle} title={playing ? 'Pause' : 'Play'}>
          <Icon name={playing ? 'pause' : 'play'} size={18} />
        </button>
        <button
          className="tp"
          onClick={() => onSelect(Math.min(last, selected + 1))}
          title="Step forward"
        >
          <Icon name="fwd" />
        </button>
        <button className="tp" onClick={() => onSelect(last)} title="Skip to end">
          <Icon name="end" />
        </button>
      </div>
      <div className="tp-counter">
        <span className="tp-step mono">
          step <b>{selected + 1}</b> <span className="tp-slash">/</span> {n}
        </span>
        <span className="tp-type">{typeLabel(run.steps[selected]!.type)}</span>
      </div>
    </div>
  );
}
