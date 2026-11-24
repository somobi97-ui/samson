import crypto from 'crypto';
import type {
  BlockedNetworkAttempt,
  IngressProvenance,
  SandboxPolicy,
  TelemetryEvent,
  TrapExecutionResult,
  TrapSessionRecord,
} from '../../src/types/security.ts';
import { buildAttributionReport, extractIndicators } from './attribution.ts';

export const DEFAULT_SANDBOX_POLICY: SandboxPolicy = {
  cpu_quota: '0.5',
  memory_limit: '256m',
  pids_limit: 64,
  timeout_seconds: 15,
  image: 'python:3.12-slim',
  enable_decoy_workspace: true,
  runtime: 'gvisor-runsc',
  seccomp_enabled: true,
  strip_env_secrets: true,
  host_firewall_drop_imds: true,
};

export function createDecoyWorkspaceFiles(enableDecoys: boolean): Record<string, string> {
  if (!enableDecoys) {
    return {};
  }
  return {
    'README.txt': 'Workspace initialized.\n',
    'fake_config.env': 'API_KEY=DECOY_HONEYPOT_KEY_DO_NOT_USE\nENV=sandbox\n',
    'canary_note.txt': 'HONEYPOT_MARKER=TRAP_SESSION_9941\n',
  };
}

export function buildCustomSeccompProfile(): Record<string, unknown> {
  return {
    defaultAction: 'SCMP_ACT_ALLOW',
    architectures: ['SCMP_ARCH_X86_64', 'SCMP_ARCH_AARCH64'],
    syscalls: [
      {
        names: ['ptrace', 'mount', 'umount2', 'kexec_load', 'kexec_file_load', 'bpf', 'perf_event_open'],
        action: 'SCMP_ACT_ERRNO',
        errnoRet: 1,
        comment: 'Thesis 2/4: Block kernel introspection, mount escapes, and eBPF loading',
      },
      {
        names: ['socket'],
        action: 'SCMP_ACT_ERRNO',
        errnoRet: 1,
        args: [
          { index: 0, value: 17, op: 'SCMP_CMP_EQ' }, // AF_PACKET raw sockets
        ],
        comment: 'Thesis 2/4: Block raw packet sockets',
      },
      {
        names: ['clone'],
        action: 'SCMP_ACT_ERRNO',
        errnoRet: 1,
        args: [
          { index: 0, value: 0x10000000, op: 'SCMP_CMP_MASKED_EQ', valueTwo: 0x10000000 }, // CLONE_NEWUSER
          { index: 0, value: 0x00020000, op: 'SCMP_CMP_MASKED_EQ', valueTwo: 0x00020000 }, // CLONE_NEWNS
        ],
        comment: 'Thesis 2/4: Block nested user/mount namespace creation',
      },
    ],
  };
}

export function buildHardenedDockerCommand(
  sessionId: string,
  policy: SandboxPolicy,
  workspacePath = `/tmp/${sessionId}_ws`,
): string[] {
  const cmd = ['docker', 'run', '--rm', '--name', sessionId];

  if (policy.runtime === 'gvisor-runsc') {
    cmd.push('--runtime=runsc');
  } else if (policy.runtime === 'firecracker-microvm') {
    cmd.push('--runtime=kata-fc');
  }

  cmd.push(
    '--network',
    'none',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges:true',
  );

  if (policy.seccomp_enabled) {
    cmd.push('--security-opt', 'seccomp=./sandbox_seccomp_profile.json');
  }

  cmd.push(
    '--read-only',
    '--tmpfs',
    '/tmp:rw,noexec,nosuid,size=32m',
    '-v',
    `${workspacePath}:/workspace:rw`,
    '-w',
    '/workspace',
    '--cpus',
    policy.cpu_quota,
    '--memory',
    policy.memory_limit,
    '--memory-swap',
    policy.memory_limit,
    '--pids-limit',
    String(policy.pids_limit),
    '--user',
    '65534:65534',
    policy.image,
    'python3',
    '-I',
    '-c',
    '<untrusted_agent_code>',
  );

  return cmd;
}

/**
 * Deterministic, host-safe zero-egress sandbox execution simulator.
 * Never evaluates untrusted code on the host; models exact Thesis 1 & 2
 * container isolation, decoy reads, network blocks, and syscall traps.
 */
export function runTrappedSession(params: {
  agent_id: string;
  reason: string;
  ingress: IngressProvenance;
  prompt: string;
  agent_code: string;
  policy?: Partial<SandboxPolicy>;
}): TrapSessionRecord {
  const sessionId = `trap-${crypto.randomBytes(6).toString('hex')}`;
  const policy: SandboxPolicy = {
    ...DEFAULT_SANDBOX_POLICY,
    ...(params.policy ?? {}),
  };
  const decoyFiles = createDecoyWorkspaceFiles(policy.enable_decoy_workspace);
  const telemetry: TelemetryEvent[] = [];

  const recordEvent = (event_type: string, payload: Record<string, unknown>) => {
    telemetry.push({
      timestamp: new Date().toISOString(),
      session_id: sessionId,
      event_type,
      payload,
    });
  };

  recordEvent('ingress_captured', {
    peer_ip: params.ingress.peer_ip,
    peer_port: params.ingress.peer_port,
    origin_server: params.ingress.origin_server,
    auth_principal: params.ingress.auth_principal,
    user_agent: params.ingress.user_agent,
    protocol: params.ingress.protocol,
  });

  recordEvent('session_created', {
    reason: params.reason,
    policy,
    workspace: `/tmp/${sessionId}_ws`,
    decoys_mounted: Object.keys(decoyFiles),
  });

  recordEvent('exec_attempt', {
    code_preview: params.agent_code.slice(0, 500),
  });

  const stdoutLines: string[] = [];
  const stderrLines: string[] = [];
  const blockedAttempts: BlockedNetworkAttempt[] = [];
  const canaryHits: string[] = [];
  const decoyReads: string[] = [];
  const syscallViolations: string[] = [];

  const code = params.agent_code;

  // Simulate directory listing inside /workspace
  if (/os\.listdir\s*\(\s*["']\/workspace["']\s*\)/.test(code)) {
    stdoutLines.push(`Files in /workspace: ${JSON.stringify(Object.keys(decoyFiles))}`);
  }

  // Detect decoy/canary workspace reads
  for (const [filename, content] of Object.entries(decoyFiles)) {
    if (code.includes(filename)) {
      decoyReads.push(`/workspace/${filename}`);
      stdoutLines.push(`Read file (/workspace/${filename}): ${content.trim().replace(/\n/g, ' | ')}`);
      if (filename === 'fake_config.env' || filename === 'canary_note.txt') {
        canaryHits.push(filename);
        recordEvent('canary_triggered', {
          file: `/workspace/${filename}`,
          marker: content.trim(),
        });
      }
    }
  }

  // Detect blocked sensitive OS paths under read-only non-root container
  if (/\/etc\/shadow/.test(code)) {
    stderrLines.push("PermissionError: [Errno 13] Permission denied: '/etc/shadow'");
    syscallViolations.push('blocked_sensitive_read:/etc/shadow');
  }
  if (/\/etc\/passwd/.test(code)) {
    syscallViolations.push('audited_system_read:/etc/passwd');
  }

  // Detect seccomp-blocked dangerous syscalls / primitives
  if (policy.seccomp_enabled) {
    if (/\b(ptrace|CLONE_NEWUSER|CLONE_NEWNS|kexec_load|bpf)\b/i.test(code)) {
      syscallViolations.push('seccomp_sigsys_or_eperm:privileged_syscall');
      stderrLines.push('OSError: [Errno 1] Operation not permitted (blocked by seccomp profile)');
    }
    if (/AF_PACKET|SOCK_RAW/i.test(code)) {
      syscallViolations.push('seccomp_eperm:raw_socket_creation');
      stderrLines.push('PermissionError: [Errno 1] Operation not permitted (raw socket blocked)');
    }
  }

  // Detect environment secret stripping
  if (/os\.environ/i.test(code) && policy.strip_env_secrets) {
    stdoutLines.push("Environ snapshot: {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/nonexistent'}");
  }

  // Detect IMDS 169.254.169.254 probe
  if (/169\.254\.169\.254/.test(code)) {
    blockedAttempts.push({
      type: 'blocked_imds_probe',
      target_host: '169.254.169.254',
      target_url: 'http://169.254.169.254/latest/meta-data/',
      reason: policy.host_firewall_drop_imds
        ? 'Dropped by --network=none & host IMDS firewall rule'
        : 'Blocked by --network=none',
    });
    stdoutLines.push(
      "Blocked outbound attempt: URLError <urlopen error [Errno 101] Network is unreachable: '169.254.169.254'>",
    );
  }

  // Extract all attempted URLs / hosts from code + prompt
  const indicators = extractIndicators([params.prompt, code]);
  for (const url of indicators.urls) {
    let host = '';
    try {
      host = new URL(url).hostname;
    } catch {
      host = '';
    }
    if (!blockedAttempts.some((b) => b.target_url === url)) {
      blockedAttempts.push({
        type: 'blocked_url_reference',
        target_url: url,
        target_host: host || undefined,
        reason: 'Blocked by zero-egress container boundary (--network=none)',
      });
    }
    if (/urllib|requests|httpx|aiohttp|socket|curl|wget/i.test(code)) {
      stdoutLines.push(
        `Blocked outbound attempt: URLError <urlopen error [Errno -3] Temporary failure in name resolution: ${url}>`,
      );
    }
  }

  for (const ip of indicators.ips) {
    if (ip !== '169.254.169.254' && !blockedAttempts.some((b) => b.target_host === ip)) {
      blockedAttempts.push({
        type: 'blocked_ip_reference',
        target_host: ip,
        reason: 'Blocked by zero-egress container boundary (--network=none)',
      });
    }
  }

  if (blockedAttempts.length > 0) {
    recordEvent('egress_blocked', {
      count: blockedAttempts.length,
      attempts: blockedAttempts,
    });
  }

  const isInfiniteLoop = /while\s+True\s*:/.test(code) && !/\bbreak\b/.test(code);
  const status: TrapExecutionResult['status'] = isInfiniteLoop
    ? 'timeout'
    : syscallViolations.some((v) => v.startsWith('seccomp_'))
      ? 'blocked_syscall'
      : 'completed';

  const durationSec = isInfiniteLoop ? policy.timeout_seconds : 0.18;
  const exitCode = status === 'timeout' ? -1 : status === 'blocked_syscall' ? 1 : 0;

  if (status === 'timeout') {
    stderrLines.push(`Execution exceeded ${policy.timeout_seconds}s limit.`);
    recordEvent('exec_timeout', {
      status: 'timeout',
      exit_code: -1,
      duration_sec: durationSec,
    });
  } else {
    recordEvent('exec_finished', {
      status: 'completed',
      exit_code: exitCode,
      stdout: stdoutLines.join('\n').slice(-4000),
      stderr: stderrLines.join('\n').slice(-4000),
      duration_sec: durationSec,
    });
  }

  const observedTexts = [params.prompt, code, ...stdoutLines, ...stderrLines];
  const attribution = buildAttributionReport({
    session_id: sessionId,
    ingress: params.ingress,
    observed_texts: observedTexts,
    blocked_network_attempts: blockedAttempts,
  });

  recordEvent('attribution_completed', {
    confidence: attribution.confidence,
    extracted_urls: attribution.extracted_urls,
    extracted_domains: attribution.extracted_domains,
    extracted_ips: attribution.extracted_ips,
  });

  recordEvent('session_destroyed', {
    telemetry_path: `./origin_trap_logs/${sessionId}/telemetry.jsonl`,
    ephemeral_workspace_purged: true,
  });

  const dockerCommand = buildHardenedDockerCommand(sessionId, policy);
  const seccompProfile = buildCustomSeccompProfile();

  return {
    session_id: sessionId,
    created_at: new Date().toISOString(),
    agent_id: params.agent_id,
    reason: params.reason,
    status: canaryHits.length > 0 || blockedAttempts.length > 0 ? 'revoked' : 'destroyed',
    ingress: params.ingress,
    policy,
    prompt: params.prompt,
    agent_code: params.agent_code,
    decoy_files: decoyFiles,
    telemetry,
    execution: {
      status,
      exit_code: exitCode,
      stdout: stdoutLines.join('\n').slice(-4000),
      stderr: stderrLines.join('\n').slice(-4000),
      duration_sec: durationSec,
      blocked_attempts: blockedAttempts,
      canary_hits: canaryHits,
      decoy_reads: decoyReads,
      syscall_violations: syscallViolations,
      docker_command: dockerCommand,
      seccomp_profile: seccompProfile,
    },
    attribution,
  };
}
