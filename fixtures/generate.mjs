// Generates the traceglass demo fixtures from a single source of truth, so the
// native and OTel exports of the "same" run are provably equivalent.
//
//   node fixtures/generate.mjs
//
// Produces:
//   fixtures/sample-run-native.json  (clean underwriting run, native format)
//   fixtures/sample-run-otel.json    (the SAME run, OTLP/JSON export)
//   fixtures/sample-run-loop.json    (collections run with a 3x tool loop)

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const BASE_MS = Date.parse('2026-06-20T09:00:00.000Z');

// ---------------------------------------------------------------------------
// Source of truth: an underwriting agent decisioning loan application #8821.
// Timestamps are expressed as ms offsets from BASE_MS.
// ---------------------------------------------------------------------------
const underwriting = {
  id: 'run-underwrite-8821',
  name: 'Underwriting · loan application #8821',
  currency: 'INR',
  status: 'completed',
  steps: [
    {
      type: 'user_input',
      label: 'Underwrite loan application #8821',
      offsetMs: 0,
      durationMs: 5,
      tokens: 0,
      cost: 0,
      input: { applicationId: '8821', product: 'personal_loan', requestedAmount: 450000 },
    },
    {
      type: 'plan',
      label: 'Plan underwriting steps',
      offsetMs: 20,
      durationMs: 380,
      tokens: 240,
      cost: 0.42,
      output: ['fetch applicant profile', 'pull credit bureau score', 'assess affordability', 'decide'],
    },
    {
      type: 'tool_call',
      label: 'Tool: db_query applicant_profile',
      offsetMs: 410,
      durationMs: 64,
      tokens: 0,
      cost: 0,
      toolName: 'db_query',
      input: { sql: 'SELECT * FROM applicants WHERE id = $1', params: ['8821'] },
      output: { rows: 1 },
      dataPayload: {
        applicantId: '8821',
        name: 'R. Iyer',
        pan: 'ABCPI1234K',
        monthlyIncome: 95000,
        existingEmis: 18000,
        accountAgeMonths: 54,
      },
    },
    {
      type: 'llm_reasoning',
      label: 'Assess affordability',
      offsetMs: 480,
      durationMs: 1120,
      tokens: 880,
      cost: 1.58,
      input: { prompt: 'Given income 95000 and EMIs 18000, assess capacity for a 450000 loan.' },
      output:
        'Net disposable income is ~77000/mo. A 450000 personal loan at 14% over 36 months is ~15400/mo EMI, ' +
        'pushing total EMIs to 33400 (35% of income). Within the 40% FOIR policy ceiling.',
    },
    {
      type: 'tool_call',
      label: 'Tool: credit_bureau_api score',
      offsetMs: 1610,
      durationMs: 240,
      tokens: 0,
      cost: 2.0,
      toolName: 'credit_bureau_api',
      input: { bureau: 'CIBIL', pan: 'ABCPI1234K' },
      output: { status: 'ok' },
      dataPayload: { score: 766, openAccounts: 4, dpd30Plus: 0, enquiriesLast6m: 1 },
    },
    {
      type: 'llm_reasoning',
      label: 'Final decision reasoning',
      offsetMs: 1860,
      durationMs: 980,
      tokens: 1020,
      cost: 1.84,
      input: { prompt: 'Decide approve/decline given affordability within FOIR and CIBIL 766.' },
      output:
        'CIBIL 766 (good), zero 30+ DPD, FOIR within policy. Approve at requested amount with standard rate.',
    },
    {
      type: 'final_output',
      label: 'Decision: APPROVE',
      offsetMs: 2840,
      durationMs: 12,
      tokens: 60,
      cost: 0.11,
      output: { decision: 'approve', amount: 450000, apr: 14.0, tenureMonths: 36 },
      dataPayload: {
        applicationId: '8821',
        decision: 'approve',
        approvedAmount: 450000,
        decidedBy: 'agent:underwriter-v3',
      },
    },
  ],
};

// ---------------------------------------------------------------------------
// Loop fixture: a collections agent that gets stuck polling payment status.
// ---------------------------------------------------------------------------
const collectionsLoop = {
  id: 'run-collections-4471',
  name: 'Collections · account #4471 (stuck loop)',
  currency: 'INR',
  status: 'failed',
  steps: [
    {
      type: 'user_input',
      label: 'Collections follow-up for account #4471',
      offsetMs: 0,
      durationMs: 4,
      tokens: 0,
      cost: 0,
      input: { accountId: '4471', bucket: '30-59 DPD' },
    },
    {
      type: 'plan',
      label: 'Plan collections outreach',
      offsetMs: 15,
      durationMs: 300,
      tokens: 210,
      cost: 0.38,
      output: ['check latest payment status', 'draft reminder', 'send'],
    },
    {
      type: 'tool_call',
      label: 'Tool: get_payment_status',
      offsetMs: 320,
      durationMs: 90,
      tokens: 0,
      cost: 0.05,
      toolName: 'get_payment_status',
      input: { accountId: '4471' },
      output: { status: 'pending', settledAt: null },
      dataPayload: { accountId: '4471', outstanding: 22400, lastPaymentAt: null, status: 'pending' },
    },
    {
      type: 'tool_call',
      label: 'Tool: get_payment_status',
      offsetMs: 430,
      durationMs: 88,
      tokens: 0,
      cost: 0.05,
      toolName: 'get_payment_status',
      input: { accountId: '4471' },
      output: { status: 'pending', settledAt: null },
      dataPayload: { accountId: '4471', outstanding: 22400, lastPaymentAt: null, status: 'pending' },
    },
    {
      type: 'tool_call',
      label: 'Tool: get_payment_status',
      offsetMs: 540,
      durationMs: 91,
      tokens: 0,
      cost: 0.05,
      toolName: 'get_payment_status',
      input: { accountId: '4471' },
      output: { status: 'pending', settledAt: null },
      dataPayload: { accountId: '4471', outstanding: 22400, lastPaymentAt: null, status: 'pending' },
    },
    {
      type: 'llm_reasoning',
      label: 'Re-checking payment status before drafting',
      offsetMs: 640,
      durationMs: 9800,
      tokens: 7400,
      cost: 13.6,
      input: { prompt: 'Status still pending; verify once more before drafting the reminder.' },
      output: 'Status appears unchanged. Will confirm payment status again to avoid dunning a paid account.',
    },
    {
      type: 'error',
      label: 'Run aborted: step budget exceeded',
      offsetMs: 10450,
      durationMs: 2,
      tokens: 0,
      cost: 0,
      output: { error: 'max_tool_iterations_exceeded', tool: 'get_payment_status' },
    },
  ],
};

// ---------------------------------------------------------------------------
// Emitters
// ---------------------------------------------------------------------------
function iso(offsetMs) {
  return new Date(BASE_MS + offsetMs).toISOString();
}

function toNative(run) {
  return {
    id: run.id,
    name: run.name,
    currency: run.currency,
    status: run.status,
    steps: run.steps.map((s, i) => {
      const out = {
        type: s.type,
        label: s.label,
        startedAt: iso(s.offsetMs),
        durationMs: s.durationMs,
        tokens: s.tokens,
        cost: s.cost,
        spanId: `${run.id}-span-${i}`,
      };
      if (s.toolName !== undefined) out.toolName = s.toolName;
      if (s.input !== undefined) out.input = s.input;
      if (s.output !== undefined) out.output = s.output;
      if (s.dataPayload !== undefined) out.dataPayload = s.dataPayload;
      return out;
    }),
  };
}

function str(s) {
  return { stringValue: s };
}
function int(n) {
  return { intValue: String(n) };
}
function dbl(n) {
  return { doubleValue: n };
}

function toOtel(run) {
  const spans = run.steps.map((s, i) => {
    const startNano = String((BASE_MS + s.offsetMs) * 1e6);
    const endNano = String((BASE_MS + s.offsetMs + s.durationMs) * 1e6);
    const attributes = [
      { key: 'traceglass.step.type', value: str(s.type) },
      { key: 'traceglass.step.label', value: str(s.label) },
      { key: 'traceglass.cost', value: dbl(s.cost) },
    ];
    if (s.tokens > 0) {
      // Split arbitrarily across input/output to exercise summation.
      const input = Math.round(s.tokens * 0.6);
      attributes.push({ key: 'gen_ai.usage.input_tokens', value: int(input) });
      attributes.push({ key: 'gen_ai.usage.output_tokens', value: int(s.tokens - input) });
    }
    if (s.toolName !== undefined) {
      attributes.push({ key: 'gen_ai.tool.name', value: str(s.toolName) });
    }
    // OTel attribute values are strings: plain strings pass through, structured
    // values are JSON-encoded (and re-parsed on ingest).
    const encode = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
    if (s.input !== undefined) {
      attributes.push({ key: 'traceglass.input', value: str(encode(s.input)) });
    }
    if (s.output !== undefined) {
      attributes.push({ key: 'traceglass.output', value: str(encode(s.output)) });
    }
    if (s.dataPayload !== undefined) {
      attributes.push({ key: 'traceglass.data_payload', value: str(encode(s.dataPayload)) });
    }
    return {
      traceId: '0af7651916cd43dd8448eb211c80319c',
      spanId: `${run.id}-span-${i}`,
      name: s.label,
      kind: 1,
      startTimeUnixNano: startNano,
      endTimeUnixNano: endNano,
      attributes,
      status: { code: s.type === 'error' ? 2 : 1 },
    };
  });

  return {
    resourceSpans: [
      {
        resource: {
          attributes: [
            { key: 'service.name', value: str('underwriter-agent') },
            { key: 'traceglass.run.id', value: str(run.id) },
            { key: 'traceglass.run.name', value: str(run.name) },
            { key: 'traceglass.run.currency', value: str(run.currency) },
            { key: 'traceglass.run.status', value: str(run.status) },
          ],
        },
        scopeSpans: [{ scope: { name: 'traceglass.agent', version: '1.0.0' }, spans }],
      },
    ],
  };
}

function write(name, data) {
  const path = join(here, name);
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
  console.log('wrote', name);
}

write('sample-run-native.json', toNative(underwriting));
write('sample-run-otel.json', toOtel(underwriting));
write('sample-run-loop.json', toNative(collectionsLoop));
