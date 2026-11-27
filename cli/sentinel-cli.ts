#!/usr/bin/env node
import { evaluateActionBoundary } from '../server/engine/detector.ts';
import { DEFAULT_AGENT_BASELINES, runAdversarialHarness } from '../server/engine/harness.ts';
import { runPipelineConfigAudit, scanDirectoryForRisks } from './scanner.ts';

function getFlag(args: string[], flag: string, fallback = ''): string {
  const idx = args.indexOf(flag);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
}

function printUsage(): void {
  console.log(`SentinelGate CLI — Pre-Deployment Security & Pipeline Gate

Usage:
  sentinelgate scan [path] [--json]
  sentinelgate harness [--json]
  sentinelgate check-config [--json]
  sentinelgate gate --goal "..." --tool "..." [--payload "..."] [--trust untrusted_external|mixed|trusted] [--json]
`);
}

function main(): void {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const asJson = args.includes('--json');

  if (!cmd || cmd === '--help' || cmd === '-h') {
    printUsage();
    process.exit(0);
  }

  if (cmd === 'scan') {
    const target = args[1] && !args[1].startsWith('--') ? args[1] : process.cwd();
    const report = scanDirectoryForRisks(target);
    if (asJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(
        `SentinelGate Scan: ${report.files_scanned} files scanned at ${report.target_path}`,
      );
      for (const f of report.findings) {
        console.log(`  [${f.severity.toUpperCase()}] ${f.file}:${f.line} (${f.rule}) - ${f.summary}`);
      }
      for (const w of report.config_warnings) {
        console.log(`  [CONFIG] ${w}`);
      }
      console.log(report.passed ? 'PASS: No blocking findings.' : 'FAIL: Blocking risks found.');
    }
    process.exit(report.passed ? 0 : 1);
  }

  if (cmd === 'harness') {
    const results = runAdversarialHarness(DEFAULT_AGENT_BASELINES);
    const passed = results.filter((r) => r.passed).length;
    const allPassed = passed === results.length;
    if (asJson) {
      console.log(JSON.stringify({ total: results.length, passed, results }, null, 2));
    } else {
      console.log(`SentinelGate Adversarial Harness: ${passed}/${results.length} fixtures passed`);
      for (const r of results) {
        console.log(
          `  ${r.passed ? 'PASS' : 'FAIL'} ${r.scenario.id} -> ${r.actual_decision} (risk=${r.combined_risk.toFixed(2)}, ${r.latency_ms}ms)`,
        );
      }
    }
    process.exit(allPassed ? 0 : 1);
  }

  if (cmd === 'check-config') {
    const warnings = runPipelineConfigAudit();
    if (asJson) {
      console.log(JSON.stringify({ ok: warnings.length === 0, warnings }, null, 2));
    } else if (warnings.length === 0) {
      console.log('PASS: Runtime security configuration passed all checks.');
    } else {
      for (const w of warnings) console.log(`WARN: ${w}`);
    }
    process.exit(warnings.length === 0 ? 0 : 1);
  }

  if (cmd === 'gate') {
    const goal = getFlag(args, '--goal', 'Inspect CI pipeline step');
    const tool = getFlag(args, '--tool', 'read_file');
    const payload = getFlag(args, '--payload', '');
    const trustRaw = getFlag(args, '--trust', 'untrusted_external');
    const source_trust =
      trustRaw === 'trusted' || trustRaw === 'mixed' ? trustRaw : 'untrusted_external';
    const target = getFlag(args, '--target', '/workspace');

    const evaluation = evaluateActionBoundary({
      agent_id: 'agent-triage-01',
      session_id: `cli-${Date.now().toString(36)}`,
      trace_id: `cli-trace-${Date.now().toString(36)}`,
      user_goal: goal,
      phase: 'tool_call',
      source_trust,
      provenance_tag: source_trust === 'trusted' ? 'AUTHENTICATED_USER' : 'TOOL_RESULT',
      trigger_source: 'tool_output',
      tool_name: tool,
      target_resource: target,
      record_count: 1,
      prior_tools: [],
      raw_payload: payload,
      baseline: DEFAULT_AGENT_BASELINES[0],
    });

    if (asJson) {
      console.log(JSON.stringify(evaluation, null, 2));
    } else {
      console.log(
        `Decision: ${evaluation.decision} (risk=${evaluation.combined_risk.toFixed(2)}, hash=${evaluation.event.payload_hash.slice(0, 12)})`,
      );
      for (const s of evaluation.signals) {
        console.log(`  - ${s.detector} [${s.severity}]: ${s.summary}`);
      }
    }

    const blocked =
      evaluation.decision === 'HARD_BLOCK_REVOKE' ||
      (args.includes('--fail-on-quarantine') && evaluation.decision === 'STEP_UP_QUARANTINE');
    process.exit(blocked ? 1 : 0);
  }

  printUsage();
  process.exit(1);
}

main();
