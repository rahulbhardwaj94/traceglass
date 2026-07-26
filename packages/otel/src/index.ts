// Public barrel for @traceglass/otel.
export {
  TraceglassSpanProcessor,
  createTraceglassSpanProcessor,
  type TraceglassSpanProcessorOptions,
} from './processor.js';
export {
  MAPPED_ATTRIBUTES,
  SPAN_STATUS_ERROR,
  attributeSnapshot,
  deriveStepType,
  maybeJson,
  spanToStep,
  tokensFrom,
  type SpanMapOptions,
} from './map.js';
export {
  hrToMs,
  parentSpanIdOf,
  type AttributesLike,
  type HrTimeLike,
  type RecordableSpan,
  type SpanContextLike,
  type SpanProcessorLike,
} from './span-types.js';
export { RunWriter, type RunWriterOptions, type WriterStepInput } from './writer.js';
