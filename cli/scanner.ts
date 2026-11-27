import fs from 'fs';
import path from 'path';
import type { CliScanFinding, CliScanReport } from '../src/types/security.ts';
import { serverConfig } from '../server/config/env.ts';

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', '.next', 'coverage']);
const SCANNABLE_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.mjs',
  '.py',
  '.json',
  '.yaml',
  '.yml',
  '.env',
  '.md',
  '.txt',
]);

const SCAN_RULES: Array<{
  rule: string;
  severity: CliScanFinding['severity'];
  regex: RegExp;
  summary: string;
}> = [
  {
    rule: 'SECRET_API_KEY_EXPOSURE',
    severity: 'critical',
    regex: /\b(AIza[0-9A-Za-z_-]{20,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,})\b/,
    summary: 'Hardcoded API key or personal access token detected in file.',
  },
  {
    rule: 'PRIVATE_KEY_MATERIAL',
    severity: 'critical',
    regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    summary: 'Private cryptographic key material found in workspace file.',
  },
  {
    rule: 'PROMPT_INJECTION_DIRECTIVE',
    severity: 'high',
    regex: /\b(ignore\s+(all\s+)?previous\s+instructions|disregard\s+system|override\s+policy)\b/i,
    summary: 'Prompt override directive detected in artifact or config.',
  },
  {
    rule: 'UNSAFE_DYNAMIC_EXECUTION',
    severity: 'high',
    regex: /\b(shell\s*:\s*true|subprocess\.\w+\([^)]*shell\s*=\s*True)\b/,
    summary: 'Shell-enabled command execution primitive increases command injection risk.',
  },
  {
    rule: 'IMDS_METADATA_PROBE',
    severity: 'critical',
    regex: /169\.254\.169\.254/,
    summary: 'Hardcoded cloud instance metadata endpoint (169.254.169.254) reference.',
  },
  {
    rule: 'CANARY_INDICATOR_HIT',
    severity: 'critical',
    regex: /DECOY_HONEYPOT_KEY_DO_NOT_USE|TRAP_SESSION_9941/,
    summary: 'Honeytoken or canary trap identifier referenced.',
  },
];

function collectFilesSafely(rootDir: string, currentDir: string, out: string[]): void {
  if (out.length >= 400) return;
  const entries = fs.readdirSync(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (out.length >= 400) break;
    if (SKIP_DIRS.has(entry.name)) continue;

    const candidate = path.resolve(currentDir, entry.name);
    if (!candidate.startsWith(rootDir + path.sep)) continue;

    if (entry.isDirectory()) {
      collectFilesSafely(rootDir, candidate, out);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SCANNABLE_EXTENSIONS.has(ext) || entry.name === 'Dockerfile' || entry.name.startsWith('.env')) {
        out.push(candidate);
      }
    }
  }
}

export function runPipelineConfigAudit(): string[] {
  const warnings: string[] = [];
  if (serverConfig.detector.blockThreshold <= serverConfig.detector.trapThreshold) {
    warnings.push(
      `DETECTOR_BLOCK_THRESHOLD (${serverConfig.detector.blockThreshold}) must exceed DETECTOR_TRAP_THRESHOLD (${serverConfig.detector.trapThreshold}).`,
    );
  }
  if (serverConfig.ai.hourlyTokenCap > 500000) {
    warnings.push(`AI_HOURLY_TOKEN_CAP (${serverConfig.ai.hourlyTokenCap}) is unusually high.`);
  }
  if (serverConfig.ai.requestTimeoutMs > 30000) {
    warnings.push(`AI_REQUEST_TIMEOUT_MS (${serverConfig.ai.requestTimeoutMs}ms) exceeds 30s guardrail.`);
  }
  if (serverConfig.edge.allowedUpstreams.length === 0) {
    warnings.push('EDGE_ALLOWED_UPSTREAMS is empty; inline proxy forwarding is disabled.');
  }
  return warnings;
}

export function scanDirectoryForRisks(targetDir: string): CliScanReport {
  const resolvedRoot = path.resolve(targetDir);
  const findings: CliScanFinding[] = [];
  const files: string[] = [];

  if (fs.existsSync(resolvedRoot)) {
    const stat = fs.statSync(resolvedRoot);
    if (stat.isDirectory()) {
      collectFilesSafely(resolvedRoot, resolvedRoot, files);
    } else if (stat.isFile()) {
      files.push(resolvedRoot);
    }
  }

  for (const filePath of files) {
    const relPath = path.relative(resolvedRoot, filePath) || path.basename(filePath);
    // Skip scanning SentinelGate's own detector/scanner definitions or test fixtures when scanning repo root
    if (
      relPath.startsWith(`tests${path.sep}`) ||
      relPath.startsWith(`server${path.sep}engine${path.sep}`) ||
      relPath.startsWith(`server${path.sep}config${path.sep}`) ||
      relPath.startsWith(`agent${path.sep}`) ||
      relPath.startsWith(`cli${path.sep}`) ||
      relPath.startsWith(`docs${path.sep}`)
    ) {
      continue;
    }

    let content = '';
    try {
      const buf = fs.readFileSync(filePath);
      if (buf.length > 256 * 1024) continue;
      content = buf.toString('utf8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Allow explicit defensive IMDS firewall block-host configuration variable
      if (/SANDBOX_IMDS_HOST\s*=/.test(line)) continue;
      for (const rule of SCAN_RULES) {
        if (rule.regex.test(line)) {
          findings.push({
            file: relPath,
            line: i + 1,
            severity: rule.severity,
            rule: rule.rule,
            summary: rule.summary,
          });
        }
      }
    }
  }

  const configWarnings = runPipelineConfigAudit();
  const hasBlocking = findings.some((f) => f.severity === 'critical' || f.severity === 'high');

  return {
    scanned_at: new Date().toISOString(),
    target_path: resolvedRoot,
    files_scanned: files.length,
    passed: !hasBlocking && configWarnings.length === 0,
    findings,
    config_warnings: configWarnings,
  };
}
