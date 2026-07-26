/**
 * Structural mirrors of the OpenTelemetry SDK types this processor reads.
 *
 * Nothing from `@opentelemetry/*` is imported. That is a supply-chain decision:
 * the OTel JS SDK is a large, fast-moving dependency tree, and this package
 * exists to make an AUDIT record — so it works against whatever OTel version
 * the host application already installed instead of pinning a second one. The
 * price is that compatibility has to be asserted rather than inferred; that
 * assertion lives in `type-compat.ts` and is checked by `npm run typecheck`.
 *
 * Every member below is a strict subset of the real `ReadableSpan`, so a real
 * span is assignable to `RecordableSpan` without a cast.
 */

/** OTel `HrTime`: [epoch seconds, nanoseconds]. */
export type HrTimeLike = readonly [number, number];

/**
 * Attribute values are `string | number | boolean | Array<...>` in OTel. They
 * are read as `unknown` and narrowed at runtime, which keeps this type a
 * supertype of `Attributes` for every SDK version.
 */
export type AttributesLike = Readonly<Record<string, unknown>>;

/** The subset of `SpanContext` needed to correlate a step with its trace. */
export interface SpanContextLike {
  readonly traceId: string;
  readonly spanId: string;
}

/** The subset of `ReadableSpan` this processor consumes. */
export interface RecordableSpan {
  readonly name: string;
  spanContext(): SpanContextLike;
  readonly startTime: HrTimeLike;
  readonly endTime: HrTimeLike;
  /** Present on real spans; recomputed from start/end when absent. */
  readonly duration?: HrTimeLike;
  readonly attributes: AttributesLike;
  /** `SpanStatusCode`: 0 UNSET, 1 OK, 2 ERROR. */
  readonly status?: { readonly code: number; readonly message?: string };
  /** OTel <= 1.x. Replaced by `parentSpanContext` in later releases. */
  readonly parentSpanId?: string | undefined;
  /** OTel >= 1.30 / 2.x. */
  readonly parentSpanContext?: { readonly spanId: string } | undefined;
  readonly resource?: { readonly attributes?: AttributesLike } | undefined;
}

/** The `SpanProcessor` surface an OTel `TracerProvider` calls. */
export interface SpanProcessorLike {
  onStart(span: unknown, parentContext?: unknown): void;
  onEnd(span: RecordableSpan): void;
  forceFlush(): Promise<void>;
  shutdown(): Promise<void>;
}

/** Milliseconds since the epoch from an OTel `HrTime`. */
export function hrToMs(hr: HrTimeLike | undefined): number {
  if (!hr) return 0;
  const [seconds, nanos] = hr;
  return seconds * 1000 + nanos / 1e6;
}

/** The span's parent id under either OTel spelling; '' for a root span. */
export function parentSpanIdOf(span: RecordableSpan): string {
  return span.parentSpanId ?? span.parentSpanContext?.spanId ?? '';
}
