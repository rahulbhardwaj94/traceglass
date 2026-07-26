# @traceglass/otel

An OpenTelemetry **span processor** that writes [traceglass](https://www.npmjs.com/package/traceglass)
runs. If your agent already emits `gen_ai.*` spans, this turns them into hash-chained,
signed records from a config change — no code edits, no collector, no network.

```bash
npm install @traceglass/otel
```

## Register it — that is the whole integration

```ts
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { TraceglassSpanProcessor } from '@traceglass/otel';

const provider = new NodeTracerProvider({
  spanProcessors: [new TraceglassSpanProcessor({ currency: 'INR' })],
});
provider.register();

// ...your instrumented agent runs unchanged...

await provider.shutdown(); // finalizes any still-open run
```

One **trace** becomes one run, id `otel-<traceId>`, finalized when its root span ends.
Verify with `npx traceglass verify otel-<traceId>`, replay with `npx traceglass open`.

## Span → step mapping

Same attributes the offline OTLP ingester consumes (`traceglass ingest trace.json`), so a
span records identically whichever path it takes:

| Step field               | Attribute                                                                             |
| ------------------------ | ------------------------------------------------------------------------------------- |
| `type`                   | `traceglass.step.type`, else ERROR status → `error`, else inferred from the span name |
| `label`                  | `traceglass.step.label`, else the span name                                           |
| `toolName`               | `gen_ai.tool.name` / `traceglass.tool.name`                                           |
| `tokens`                 | `gen_ai.usage.total_tokens`, else input + output tokens                               |
| `cost`                   | `traceglass.cost`                                                                     |
| `input`                  | `gen_ai.prompt` / `traceglass.input` (JSON strings are re-inflated)                   |
| `output`                 | `gen_ai.completion` / `traceglass.output`                                             |
| `dataPayload`            | `traceglass.data_payload`; otherwise every remaining attribute under `attributes`     |
| `spanId`, `parentSpanId` | the real OTel ids, so a step points back at its span                                  |

Run name and currency come from the resource (`traceglass.run.name`, `service.name`,
`traceglass.run.currency`) unless you pass `name` / `currency`.

That last payload row is why `gen_ai.request.model` survives into the record. Those keys
are **dotted**, which is exactly the payload shape `tgcanon/2` had to fix — the tests
record real dotted semantic-convention keys and then redact one, leaving the anchor and
the chain intact.

## Options worth knowing

- `filter: (span) => boolean` — record only the spans you care about.
- `recordAttributes: false` — skip the attribute snapshot.
- `redactPatterns: ['email', 'credit-card']` — scrub at capture time, before hashing.
- `dir: null` — record in memory only; `onRun` still receives each finalized run.
- `onError` — recording failures are reported here (default: `process.emitWarning`) and
  never thrown into your telemetry pipeline.

- **Capture order is span-end order** and is never re-sorted; the chain is fixed as it is
  written.
- **Crash-safe:** an interrupted run leaves a journal `npx traceglass recover` finalizes
  into a `failed` run that still verifies up to the crash point.
- **Local-first:** written under `~/.traceglass` (or `TRACEGLASS_HOME`). Zero network
  egress, and no `@opentelemetry/*` production dependency — the processor is structurally
  typed against the SDK interfaces, so it runs against whatever OTel version you have.
