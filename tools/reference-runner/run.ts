#!/usr/bin/env bun
// Runs tests/compatibility/*.cases.json against the READ-ONLY reference
// implementation (../queryknight-ts). No modification to the reference repo:
// it is imported, never edited. Usage:
//   bun tools/reference-runner/run.ts [--file <name>] [--json]
//   bun tools/reference-runner/run.ts --dump [--file <name>]
// --dump prints one JSON object per evaluable case:
//   {"file":..., "name":..., "decision":..., "reason_code":...}
// for differential comparison with the Rust evaluator. Exit: 0 all pass,
// 1 any fail, 2 harness error.
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const REF = join(ROOT, '..', 'queryknight-ts');
const COMPAT = join(ROOT, 'tests', 'compatibility');

const core = await import(join(REF, 'packages', 'core', 'src', 'index.ts'));

interface Case {
  name: string;
  dialect?: string;
  context?: Record<string, string>;
  sql?: string;
  policy?: string;
  policy_yaml?: string | null;
  approval?: string;
  mode?: string;
  max_sql_bytes?: number;
  expected?: { decision?: string; reason_code?: string };
  valid?: boolean;
  error_contains?: string;
  pattern?: string;
  value?: string;
}

function loadPolicy(c: Case) {
  if (c.policy_yaml === null) return undefined; // defaultPolicy path
  if (typeof c.policy_yaml === 'string') return core.parsePolicyFile(c.policy_yaml);
  if (c.policy) return core.parsePolicyFile(readFileSync(join(COMPAT, c.policy), 'utf8'));
  throw new Error(`case "${c.name}" has no policy`);
}

function providerFor(c: Case) {
  switch (c.approval ?? 'none') {
    case 'missing-provider': return undefined;
    case 'approved': return new core.TestApprovalProvider(['approved']);
    case 'denied': return new core.TestApprovalProvider(['denied']);
    case 'throws': return { async request() { throw new Error('paged human, got voicemail'); } };
    default: return new core.TestApprovalProvider(['waiting']);
  }
}

const onlyFile = process.argv.includes('--file') ? process.argv[process.argv.indexOf('--file') + 1] : undefined;
const asJson = process.argv.includes('--json');
const dump = process.argv.includes('--dump');
const files = readdirSync(COMPAT).filter((f) => f.endsWith('.cases.json')).filter((f) => !onlyFile || f.includes(onlyFile));

// --dump: evaluable cases only (expected.decision present); generated SQL
// placeholders (CHAIN_*/NEST_*) are expanded like the Rust harness does.
function expandGenerated(sql: string): string {
  if (sql === 'CHAIN_200') return 'SELECT 1' + ' + 1'.repeat(200);
  if (sql === 'NEST_2000') {
    let s = 'SELECT 1';
    for (let i = 0; i < 2000; i++) s = `SELECT * FROM (${s}) t${i}`;
    return s;
  }
  return sql;
}

if (dump) {
  const rows: Array<Record<string, unknown>> = [];
  for (const file of files) {
    const cases = JSON.parse(readFileSync(join(COMPAT, file), 'utf8')) as Case[];
    for (const c of cases) {
      if (!c.expected?.decision || typeof c.sql !== 'string') continue;
      // Provider-resolution cases need async daemon providers; the dump
      // covers the same provider mapping as the check runner.
      try {
        const policy = loadPolicy(c);
        const ctx = {
          integration: c.context?.integration ?? 'cli',
          environment: (c.context?.environment ?? 'production') as core.AgentContext['environment'],
          database: c.context?.database ?? 'main',
          agent_id: c.context?.agent_id,
          tool: c.context?.tool,
        };
        const result = await core.evaluate(ctx, expandGenerated(c.sql), {
          policy,
          dialect: c.dialect ?? 'postgres',
          mode: (c.mode as 'enforce' | 'observe') ?? 'enforce',
          approvalProvider: providerFor(c),
          ...(c.max_sql_bytes ? { maxSqlBytes: c.max_sql_bytes } : {}),
        });
        rows.push({ file, name: c.name, decision: result.decision, reason_code: result.reason_code });
      } catch (e) {
        rows.push({ file, name: c.name, error: e instanceof Error ? e.message : String(e) });
      }
    }
  }
  console.log(JSON.stringify(rows));
  process.exit(0);
}

let pass = 0, fail = 0;
const failures: Array<Record<string, unknown>> = [];

for (const file of files) {
  const cases = JSON.parse(readFileSync(join(COMPAT, file), 'utf8')) as Case[];
  for (const c of cases) {
    try {
      // Glob-only file: no sql/policy, direct globMatch assert.
      if (c.pattern !== undefined) {
        const got = core.globMatch(c.pattern, (c as unknown as { value: string }).value);
        const want = (c as unknown as { expected: boolean }).expected;
        if (got === want) pass++;
        else { fail++; failures.push({ file, name: c.name, got, want }); }
        continue;
      }
      // Validation-only cases.
      if (c.valid !== undefined) {
        let ok = true, err = '';
        try { core.parsePolicyFile(c.policy_yaml as string); }
        catch (e) { ok = false; err = e instanceof Error ? e.message : String(e); }
        const good = ok === c.valid && (!c.error_contains || err.includes(c.error_contains));
        if (good) pass++;
        else { fail++; failures.push({ file, name: c.name, got: ok ? 'valid' : err, want: c.valid ? 'valid' : c.error_contains }); }
        continue;
      }
      // Contract-doc cases (mcp-daemon-contracts): asserted by code review + daemon tests, not executable here.
      if (c.contract !== undefined || (c as unknown as { assert: unknown }).assert !== undefined) continue;
      const policy = loadPolicy(c);
      const ctx = {
        integration: c.context?.integration ?? 'cli',
        environment: (c.context?.environment ?? 'production') as core.AgentContext['environment'],
        database: c.context?.database ?? 'main',
        agent_id: c.context?.agent_id,
        tool: c.context?.tool,
      };
      const result = await core.evaluate(ctx, c.sql as string, {
        policy,
        dialect: c.dialect ?? 'postgres',
        mode: (c.mode as 'enforce' | 'observe') ?? 'enforce',
        approvalProvider: providerFor(c),
        ...(c.max_sql_bytes ? { maxSqlBytes: c.max_sql_bytes } : {}),
      });
      const dOk = !c.expected?.decision || result.decision === c.expected.decision;
      const rOk = !c.expected?.reason_code || result.reason_code === c.expected.reason_code;
      if (dOk && rOk) pass++;
      else { fail++; failures.push({ file, name: c.name, got: `${result.decision}/${result.reason_code}`, want: `${c.expected?.decision}/${c.expected?.reason_code}`, message: result.message }); }
    } catch (e) {
      fail++;
      failures.push({ file, name: c.name, error: e instanceof Error ? e.message : String(e) });
    }
  }
}

if (asJson) console.log(JSON.stringify({ pass, fail, failures }, null, 2));
else {
  for (const f of failures) console.log(`FAIL ${(f as { file: string }).file} :: ${(f as { name: string }).name} got=${JSON.stringify((f as { got: unknown }).got)} want=${JSON.stringify((f as { want: unknown }).want)}`);
  console.log(`${pass} passed, ${fail} failed`);
}
process.exit(fail > 0 ? 1 : 0);
