# @traceglass/sdk

Live-capture SDK for [traceglass](https://www.npmjs.com/package/traceglass). Record an
agent run **as it happens**: every step is hash-chained the moment it is recorded and
journaled to disk, so the tamper window closes at capture time — not at ingest.

```bash
npm install @traceglass/sdk
```

## Wrap your agent's tool calls

```ts
import { startRecording } from '@traceglass/sdk';

const rec = startRecording({ name: 'collections agent — acct 4471', currency: 'INR' });

rec.step({ type: 'user_input', label: 'Dun overdue account', input: { account: '4471' } });

const result = await callTool('get_payment_status', { account: '4471' });
rec.step({
  type: 'tool_call',
  toolName: 'get_payment_status',
  label: 'Tool: get_payment_status',
  input: { account: '4471' },
  output: result,
  dataPayload: result, // the data the agent actually saw (compliance-critical)
  tokens: 812,
  cost: 0.4,
});

rec.step({ type: 'final_output', label: 'Sent reminder', output: 'Reminder sent.' });
const run = await rec.end(); // verified, signed (if `traceglass keygen` was run), stored
console.log(run.id, run.runHash);
```

Replay it with `npx traceglass open --id <runId>`, verify with `npx traceglass verify <runId>`,
hand it to an auditor with `npx traceglass export <runId>`.

- **Crash-safe:** if your process dies mid-run, `npx traceglass recover` finalizes the
  journal into a `failed` run whose chain still verifies up to the crash point.
- **Local-first:** everything is written under `~/.traceglass` (or `TRACEGLASS_HOME`).
  Zero network egress. Pass `dir: null` for a memory-only recording.
