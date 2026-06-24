import type { Run, Step } from '../types.js';
import { commas, ms, money, pretty, typeLabel } from '../format.js';
import { accessOf, isHighCost, payloadSource, payloadView } from '../lib/derive.js';
import { Icon } from './Icon.js';

function Code({ value, className = '' }: { value: unknown; className?: string }) {
  const text = typeof value === 'string' ? value : pretty(value);
  return <pre className={'code mono ' + className}>{text || '—'}</pre>;
}

function Metric({
  k,
  v,
  mono,
  accent,
  dim,
}: {
  k: string;
  v: string;
  mono?: boolean;
  accent?: boolean;
  dim?: boolean;
}) {
  return (
    <div className={'m ' + (dim ? 'dim ' : '') + (accent ? 'accent' : '')}>
      <span className="m-k">{k}</span>
      <span className={'m-v ' + (mono ? 'mono' : '')}>{v}</span>
    </div>
  );
}

export function StepDetail({
  step,
  run,
  median,
  showChain = true,
}: {
  step: Step;
  run: Run;
  median: number;
  showChain?: boolean;
}) {
  const access = accessOf(step);
  const view = payloadView(step);
  const source = payloadSource(step);
  const hasPayload = view !== undefined && view !== null;

  return (
    <div className="card detail">
      <div className="card-head">
        <span className={'typechip ' + step.type}>{typeLabel(step.type)}</span>
        <h2 className="detail-title">{step.label}</h2>
        <span className="detail-idx mono">#{step.index + 1}</span>
      </div>

      <div className="metrics-strip">
        {step.toolName && <Metric k="Tool" v={step.toolName} mono />}
        <Metric k="Latency" v={ms(step.durationMs)} mono />
        <Metric k="Tokens" v={commas(step.tokens)} mono />
        <Metric
          k="Cost"
          v={money(run.currency, step.cost)}
          mono
          accent={isHighCost(step, median)}
        />
        <Metric k="Span" v={step.spanId} mono dim />
      </div>

      <div className="io">
        <div className="io-col">
          <div className="io-label">Input</div>
          <Code value={step.input ?? '—'} />
        </div>
        <div className="io-col">
          <div className="io-label">Output</div>
          <Code value={step.output ?? '—'} />
        </div>
      </div>

      <div className={'payload ' + (hasPayload ? 'has' : 'empty')}>
        <div className="payload-head">
          <span className="payload-title">
            <Icon name="shield" size={14} /> Data read / mutated
          </span>
          {hasPayload && access && (
            <span className={'access ' + access.toLowerCase()}>{access}</span>
          )}
          {hasPayload && source && <span className="payload-note mono">{source}</span>}
        </div>
        {hasPayload ? (
          <Code value={view} className="payload-code" />
        ) : (
          <div className="payload-none mono">No data was read or mutated at this step.</div>
        )}
      </div>

      {showChain && (
        <div className="chain">
          <span className="chain-cell">
            <span className="chain-k mono">prevHash</span>
            <span className="chain-v mono">
              {step.prevHash ? step.prevHash.slice(0, 28) + '…' : '∅ genesis'}
            </span>
          </span>
          <span className="chain-link">
            <Icon name="link" size={13} />
          </span>
          <span className="chain-cell">
            <span className="chain-k mono">hash</span>
            <span className="chain-v mono ok">{step.hash.slice(0, 28)}…</span>
          </span>
          <span className="chain-ok">
            <Icon name="check" size={13} /> link intact
          </span>
        </div>
      )}
    </div>
  );
}
