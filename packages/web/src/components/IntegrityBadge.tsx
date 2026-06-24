import type { Run, VerifyResult } from '../types.js';
import { Icon } from './Icon.js';

/**
 * The integrity verdict — the "money shot". Green shield + "Chain intact" when
 * the hash chain verifies; red alert + "Tampered · step #n" the instant a
 * stored step is altered. Deliberately a separate axis from run status.
 */
export function IntegrityBadge({ run, verify }: { run: Run; verify: VerifyResult | null }) {
  const len = run.steps.length;

  if (!verify) {
    return (
      <div className="integrity" title="Verifying hash-chain integrity…">
        <div className="ig-ico">
          <Icon name="shield" size={18} />
        </div>
        <div className="ig-body">
          <div className="ig-line1">
            <span className="ig-state">Checking…</span>
          </div>
          <div className="ig-line2 mono">
            <Icon name="link" size={12} /> sha256 · {run.runHash.slice(0, 18)}…
          </div>
        </div>
      </div>
    );
  }

  const ok = verify.ok;
  const broken = verify.brokenStepIndex;

  return (
    <div className={'integrity ' + (ok ? 'ok' : 'bad')} title={verify.message}>
      <div className="ig-ico">
        <Icon name={ok ? 'shield' : 'alert'} size={18} />
      </div>
      <div className="ig-body">
        <div className="ig-line1">
          <span className="ig-state">{ok ? 'Chain intact' : 'Tampered'}</span>
          <span className="ig-steps mono">
            {ok
              ? `${len}/${len} verified`
              : broken !== null
                ? `step #${broken + 1} broken`
                : 'chain broken'}
          </span>
        </div>
        <div className="ig-line2 mono">
          <Icon name="link" size={12} /> sha256 · {run.runHash.slice(0, 18)}…
        </div>
      </div>
    </div>
  );
}
