import type { Run } from '@traceglass/core';
import { spanToStep, type SpanMapOptions } from './map.js';
import { parentSpanIdOf, type RecordableSpan, type SpanProcessorLike } from './span-types.js';
import { RunWriter } from './writer.js';

/**
 * OpenTelemetry span processor that writes traceglass runs.
 *
 * Register it on your existing tracer provider and an application that already
 * emits `gen_ai.*` spans produces signed, hash-chained evidence with no code
 * changes beyond the registration itself:
 *
 *   new NodeTracerProvider({ spanProcessors: [new TraceglassSpanProcessor()] })
 *   // or, on OTel JS 1.x: provider.addSpanProcessor(new TraceglassSpanProcessor())
 *
 * One TRACE becomes one run. Spans are recorded as they END, which is when
 * their duration, status and attributes are final; the chain is fixed in that
 * arrival order and never re-sorted. A trace is finalized when its root span
 * ends, and any still-open trace is finalized on `forceFlush()`/`shutdown()`.
 *
 * The processor never throws into the telemetry pipeline: a failure to record
 * must not take down the application being recorded. Failures are reported
 * through `onError` (default: `process.emitWarning`) so they are loud without
 * being fatal — silence would be the worst outcome for an evidence tool.
 *
 * Zero network egress: everything is written under TRACEGLASS_HOME
 * (default ~/.traceglass). This is not an exporter and talks to no collector.
 */

export interface TraceglassSpanProcessorOptions extends SpanMapOptions {
  /**
   * Run name. A function is called with the first span seen for a trace.
   * Defaults to the resource's `traceglass.run.name`, then `service.name`,
   * then `OpenTelemetry run`.
   */
  name?: string | ((span: RecordableSpan) => string);
  /**
   * Run id for a trace. Defaults to `otel-<traceId>`, which is unique per trace
   * and points straight back at the trace in your tracing backend.
   *
   * Note the resource attribute `traceglass.run.id` — which the offline OTLP
   * ingester honours — is deliberately NOT used here: one processor sees many
   * traces from the same resource, and they must not all claim one run id.
   */
  runId?: (traceId: string, span: RecordableSpan) => string;
  /** Currency for cost fields. Defaults to the resource's, then USD. */
  currency?: string;
  /** traceglass data dir; `null` records in memory only (useful in tests). */
  dir?: string | null;
  /** Per-leaf commitments so payloads can be redacted later (default on). */
  redactable?: boolean;
  /** Built-in redaction patterns applied at capture time, before hashing. */
  redactPatterns?: string[];
  /** Record only the spans this returns true for. Default: every ended span. */
  filter?: (span: RecordableSpan) => boolean;
  /** Finalize a trace's run when its root span ends. Default true. */
  finalizeOnRootEnd?: boolean;
  /** Called with each finalized run. */
  onRun?: (run: Run) => void;
  /** Called when recording a span or finalizing a run fails. */
  onError?: (error: Error) => void;
}

/** How many finalized trace ids to remember for late-span detection. */
const FINALIZED_MEMORY = 512;

function defaultOnError(error: Error): void {
  process.emitWarning(error, 'TraceglassOtelWarning');
}

function toError(value: unknown): Error {
  if (value instanceof Error) return value;
  return new Error(typeof value === 'string' ? value : `non-Error thrown (${typeof value})`);
}

export class TraceglassSpanProcessor implements SpanProcessorLike {
  private readonly opts: TraceglassSpanProcessorOptions;
  private readonly writers = new Map<string, RunWriter>();
  /** traceId -> how many runs have already been finalized for it. */
  private readonly finalized = new Map<string, number>();
  private shutDown = false;

  constructor(opts: TraceglassSpanProcessorOptions = {}) {
    this.opts = opts;
  }

  /** Nothing to do on start: a span's attributes are not final until it ends. */
  onStart(_span: unknown, _parentContext?: unknown): void {
    // intentionally empty
  }

  onEnd(span: RecordableSpan): void {
    try {
      if (this.shutDown) {
        throw new Error(
          `Span "${span.name}" ended after the traceglass processor was shut down; not recorded.`,
        );
      }
      if (this.opts.filter && !this.opts.filter(span)) return;
      const traceId = span.spanContext().traceId;
      // Mapped BEFORE the writer exists, so a span this processor cannot map
      // does not leave an empty journal behind for `traceglass recover`.
      const stepInput = spanToStep(span, this.opts);
      const writer = this.writerFor(traceId, span);
      writer.step(stepInput);
      if (this.opts.finalizeOnRootEnd !== false && parentSpanIdOf(span) === '') {
        this.finalize(traceId);
      }
    } catch (err) {
      this.reportError(toError(err));
    }
  }

  /** Finalize every open run. Returns once they are stored. */
  forceFlush(): Promise<void> {
    for (const traceId of [...this.writers.keys()]) this.finalize(traceId);
    return Promise.resolve();
  }

  /** Finalize every open run and stop recording. */
  shutdown(): Promise<void> {
    const flushed = this.forceFlush();
    this.shutDown = true;
    return flushed;
  }

  /** Finalize one trace's run early (e.g. a session boundary you know about). */
  finalize(traceId: string): Run | null {
    const writer = this.writers.get(traceId);
    if (!writer) return null;
    this.writers.delete(traceId);
    this.rememberFinalized(traceId);
    try {
      const run = writer.end();
      this.opts.onRun?.(run);
      return run;
    } catch (err) {
      this.reportError(toError(err));
      return null;
    }
  }

  /** Run ids currently open, keyed by trace id. Mostly useful in tests. */
  get openRuns(): Map<string, string> {
    return new Map([...this.writers].map(([traceId, w]) => [traceId, w.runId]));
  }

  private writerFor(traceId: string, span: RecordableSpan): RunWriter {
    const existing = this.writers.get(traceId);
    if (existing) return existing;

    const resource = span.resource?.attributes ?? {};
    const resourceName = resource['traceglass.run.name'] ?? resource['service.name'];
    const name =
      typeof this.opts.name === 'function'
        ? this.opts.name(span)
        : (this.opts.name ??
          (typeof resourceName === 'string' ? resourceName : 'OpenTelemetry run'));
    const resourceCurrency = resource['traceglass.run.currency'];
    const currency =
      this.opts.currency ?? (typeof resourceCurrency === 'string' ? resourceCurrency : 'USD');

    // A span arriving after its trace was already finalized (a late child, or a
    // second root) opens a CONTINUATION run rather than being dropped: losing
    // evidence silently is worse than an extra record, and reusing the run id
    // would collide in the store.
    const generation = this.finalized.get(traceId) ?? 0;
    const base = this.opts.runId?.(traceId, span) ?? `otel-${traceId}`;
    const id = generation === 0 ? base : `${base}-${generation + 1}`;

    const writer = new RunWriter({
      id,
      name,
      currency,
      ...(this.opts.dir !== undefined ? { dir: this.opts.dir } : {}),
      ...(this.opts.redactable !== undefined ? { redactable: this.opts.redactable } : {}),
      ...(this.opts.redactPatterns !== undefined
        ? { redactPatterns: this.opts.redactPatterns }
        : {}),
    });
    this.writers.set(traceId, writer);
    return writer;
  }

  private rememberFinalized(traceId: string): void {
    this.finalized.set(traceId, (this.finalized.get(traceId) ?? 0) + 1);
    // Bounded: a long-lived process must not grow a map per trace forever.
    while (this.finalized.size > FINALIZED_MEMORY) {
      const oldest = this.finalized.keys().next();
      if (oldest.done) break;
      this.finalized.delete(oldest.value);
    }
  }

  private reportError(error: Error): void {
    (this.opts.onError ?? defaultOnError)(error);
  }
}

/** Convenience factory, for config files that prefer a function call. */
export function createTraceglassSpanProcessor(
  opts: TraceglassSpanProcessorOptions = {},
): TraceglassSpanProcessor {
  return new TraceglassSpanProcessor(opts);
}
