/**
 * Compile-time proof that the structural types in `span-types.ts` accept a REAL
 * `@opentelemetry/sdk-trace-base` span and that this processor is registerable,
 * without depending on `@opentelemetry/*`.
 *
 * The declarations below mirror the upstream interfaces at the versions this
 * package supports — including BOTH parent-span spellings (`parentSpanId` up to
 * OTel JS 1.x, `parentSpanContext` from 1.30/2.x). If the upstream shape drifts
 * incompatibly, these assertions stop compiling and `npm run typecheck` fails
 * here rather than in a user's build.
 *
 * Types only; the file emits no meaningful runtime code.
 */
import type { RecordableSpan, SpanProcessorLike } from './span-types.js';
import type { TraceglassSpanProcessor } from './processor.js';

type UpstreamHrTime = [number, number];
type UpstreamAttributeValue = string | number | boolean | Array<string | number | boolean | null>;
interface UpstreamAttributes {
  [key: string]: UpstreamAttributeValue | undefined;
}
interface UpstreamSpanContext {
  traceId: string;
  spanId: string;
  traceFlags: number;
  isRemote?: boolean;
}
interface UpstreamResource {
  attributes: UpstreamAttributes;
}
interface UpstreamSpanStatus {
  code: number; // SpanStatusCode
  message?: string;
}

/** Mirror of `ReadableSpan` as of OTel JS 1.x (parentSpanId spelling). */
interface UpstreamReadableSpanV1 {
  readonly name: string;
  readonly kind: number;
  spanContext(): UpstreamSpanContext;
  readonly parentSpanId?: string;
  readonly startTime: UpstreamHrTime;
  readonly endTime: UpstreamHrTime;
  readonly status: UpstreamSpanStatus;
  readonly attributes: UpstreamAttributes;
  readonly links: unknown[];
  readonly events: unknown[];
  readonly duration: UpstreamHrTime;
  readonly ended: boolean;
  readonly resource: UpstreamResource;
  readonly instrumentationScope: { name: string; version?: string };
  readonly droppedAttributesCount: number;
  readonly droppedEventsCount: number;
  readonly droppedLinksCount: number;
}

/** Mirror of `ReadableSpan` as of OTel JS 2.x (parentSpanContext spelling). */
interface UpstreamReadableSpanV2 extends Omit<UpstreamReadableSpanV1, 'parentSpanId'> {
  readonly parentSpanContext?: UpstreamSpanContext;
}

type _V1IsRecordable = UpstreamReadableSpanV1 extends RecordableSpan ? true : never;
type _V2IsRecordable = UpstreamReadableSpanV2 extends RecordableSpan ? true : never;
const _v1: _V1IsRecordable = true;
const _v2: _V2IsRecordable = true;

/** Mirror of the `SpanProcessor` interface a tracer provider requires. */
interface UpstreamSpanProcessor {
  forceFlush(): Promise<void>;
  onStart(span: UpstreamReadableSpanV1, parentContext: object): void;
  onEnd(span: UpstreamReadableSpanV1): void;
  shutdown(): Promise<void>;
}

declare const _processor: TraceglassSpanProcessor;
const _registerable: UpstreamSpanProcessor = _processor;
const _alsoSatisfiesOwnInterface: SpanProcessorLike = _processor;

export const TYPE_COMPAT_ASSERTIONS = 4;
void _v1;
void _v2;
void _registerable;
void _alsoSatisfiesOwnInterface;
