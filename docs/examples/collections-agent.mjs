/**
 * The agent behind docs/forensic-walkthrough.md.
 *
 *   node docs/examples/collections-agent.mjs [runId] [--delay <ms>]
 *
 * A collections agent asked to chase an overdue balance. It goes wrong in three
 * ordinary, expensive ways:
 *
 *   1. it gets stuck calling `payments.get_status` with identical arguments,
 *   2. it issues `payments.refund` with no human approval anywhere in the run,
 *   3. it carries the customer's email, phone and PAN through every step.
 *
 * Nothing here is special to traceglass. It is the SDK call an agent already
 * makes, plus `--delay` so `traceglass tail` has something to follow.
 *
 * The run is journaled step by step as it happens, then sealed, signed (if
 * `traceglass keygen` has been run) and stored on `end()`.
 */
import { startRecording } from '@traceglass/sdk';

const args = process.argv.slice(2);
const delayIdx = args.indexOf('--delay');
const delayMs = delayIdx === -1 ? 0 : Number(args[delayIdx + 1]);
const runId = args.find((a) => !a.startsWith('--') && a !== String(delayMs)) ?? 'collections-4471';

const pause = () => (delayMs > 0 ? new Promise((r) => setTimeout(r, delayMs)) : Promise.resolve());

/** The data the agent was handed. Every field here is personal data. */
const customer = {
  accountId: '4471',
  name: 'Priya Nair',
  email: 'priya.nair@example.com',
  phone: '+91 98200 11234',
  pan: 'ABCPN1234K',
};

const rec = startRecording({
  id: runId,
  name: 'collections agent — account 4471',
  currency: 'INR',
  // Per-leaf commitments. This is what makes `traceglass redact` able to erase
  // a value later WITHOUT breaking the chain or the signature. On by default;
  // spelled out because it is the whole point of the walkthrough.
  redactable: true,
});

console.log(`recording ${rec.runId}`);

rec.step({
  type: 'user_input',
  label: 'Chase the overdue balance on account 4471',
  input: { instruction: 'Chase the overdue balance on account 4471', customer },
});
await pause();

rec.step({
  type: 'tool_call',
  toolName: 'crm.lookup_customer',
  label: 'Tool: crm.lookup_customer',
  input: { accountId: customer.accountId },
  output: { ...customer, balanceDue: 18400, daysOverdue: 62 },
  dataPayload: { read: ['crm.customers/4471'] },
  tokens: 420,
  cost: 0.9,
  durationMs: 310,
});
await pause();

// --- the loop. Identical arguments, three times, ~INR 4.7 each. -------------
for (let i = 0; i < 3; i++) {
  rec.step({
    type: 'tool_call',
    toolName: 'payments.get_status',
    label: 'Tool: payments.get_status',
    input: { accountId: '4471', includeHistory: true },
    output: { status: 'pending', updatedAt: '2026-07-24T11:02:00.000Z' },
    dataPayload: { read: ['payments.ledger/4471'] },
    tokens: 800,
    cost: 4.7,
    durationMs: 640,
  });
  await pause();
}

// --- the action nobody signed off on ---------------------------------------
rec.step({
  type: 'tool_call',
  toolName: 'payments.refund',
  label: 'Tool: payments.refund',
  input: { accountId: '4471', amount: 18400, currency: 'INR', reason: 'auto-resolve stale dunning' },
  output: { refundId: 'rfnd_9f21', state: 'submitted' },
  dataPayload: { mutated: ['payments.ledger/4471'] },
  tokens: 260,
  cost: 1.4,
  durationMs: 880,
});
await pause();

rec.step({
  type: 'final_output',
  label: 'Answer',
  output: {
    text: 'Refunded INR 18,400 to account 4471 and closed the dunning case.',
    notifiedAt: customer.email,
  },
  tokens: 180,
  cost: 0.6,
  durationMs: 220,
});
await pause();

const run = await rec.end();
console.log(`sealed ${run.id} — ${run.totals.steps} steps, ${run.currency} ${run.totals.cost.toFixed(2)}`);
console.log(`anchor ${run.runHash}`);
