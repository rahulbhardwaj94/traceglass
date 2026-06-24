import { useMemo } from 'react';
import type { Step } from '../types.js';
import { pretty } from '../format.js';

/** Show the agent's rationale — the nearest llm_reasoning at or before the step. */
export function ReasoningPanel({ steps, selected }: { steps: Step[]; selected: number }) {
  const reasoning = useMemo(() => {
    for (let i = selected; i >= 0; i--) {
      const s = steps[i];
      if (s && s.type === 'llm_reasoning') return s;
    }
    return null;
  }, [steps, selected]);

  return (
    <div className="card reasoning">
      <div className="rz-head">
        <span className="rz-title">Reasoning</span>
        <span className="rz-sub">
          {reasoning ? `from step #${reasoning.index + 1}` : 'agent rationale leading to this step'}
        </span>
      </div>
      {reasoning ? (
        <p className="rz-text">{pretty(reasoning.output)}</p>
      ) : (
        <p className="rz-text empty">No reasoning was recorded before this step.</p>
      )}
    </div>
  );
}
