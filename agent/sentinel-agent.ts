#!/usr/bin/env node
import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

interface AgentCliOptions {
  serverUrl: string;
  endpointId: string;
  watchDir: string;
  quarantineDir: string;
  mode: 'monitor' | 'enforce_contain';
  intervalMs: number;
  once: boolean;
}

const SUSPICIOUS_FILE_PATTERNS = [
  /\.env(\.|$)/i,
  /id_rsa|id_ed25519|\.pem$/i,
  /fake_config\.env|canary_note\.txt/i,
  /credentials\.json/i,
];

const SUSPICIOUS_CONTENT_PATTERN =
  /(169\.254\.169\.254|DECOY_HONEYPOT_KEY_DO_NOT_USE|TRAP_SESSION_9941|\bcurl\s+.*https?:\/\/|\bnc\s+-e|reverse\s*shell)/i;

const SUSPICIOUS_PROCESS_PATTERN =
  /(nc\s+-e|bash\s+-i|169\.254\.169\.254|curl\s+.*(shadow|passwd|token|exfil)|python[3]?\s+-c\s+.*socket)/i;

function parseArgs(argv: string[]): AgentCliOptions {
  const getFlag = (name: string, fallback: string): string => {
    const idx = argv.indexOf(name);
    if (idx !== -1 && argv[idx + 1]) return argv[idx + 1];
    return fallback;
  };

  const rawWatch = getFlag('--watch', process.cwd());
  const watchDir = path.resolve(rawWatch);
  const rawQuarantine = getFlag('--quarantine-dir', path.join(watchDir, '.sentinel-quarantine'));
  const modeRaw = getFlag('--mode', 'enforce_contain');

  return {
    serverUrl: getFlag('--server', 'http://127.0.0.1:3000').replace(/\/+$/, ''),
    endpointId: getFlag('--id', `ep-${os.hostname().replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 32)}`),
    watchDir,
    quarantineDir: path.resolve(rawQuarantine),
    mode: modeRaw === 'monitor' ? 'monitor' : 'enforce_contain',
    intervalMs: Math.max(5000, Number(getFlag('--interval', '15000')) || 15000),
    once: argv.includes('--once'),
  };
}

function sampleSuspiciousProcesses(): Array<{ pid: string; command: string }> {
  try {
    const out = execFileSync('ps', ['-eo', 'pid=,args='], {
      encoding: 'utf8',
      timeout: 2000,
      shell: false,
    });
    const hits: Array<{ pid: string; command: string }> = [];
    for (const line of out.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.includes('sentinel-agent')) continue;
      if (SUSPICIOUS_PROCESS_PATTERN.test(trimmed)) {
        const spaceIdx = trimmed.indexOf(' ');
        if (spaceIdx > 0) {
          hits.push({
            pid: trimmed.slice(0, spaceIdx),
            command: trimmed.slice(spaceIdx + 1).slice(0, 240),
          });
        }
      }
    }
    return hits.slice(0, 10);
  } catch {
    return [];
  }
}

function enforceLocalFileContainment(
  filePath: string,
  quarantineDir: string,
  reason: string,
): string | null {
  try {
    const resolvedFile = path.resolve(filePath);
    const resolvedQuarantine = path.resolve(quarantineDir);
    if (!fs.existsSync(resolvedFile)) return null;
    fs.mkdirSync(resolvedQuarantine, { recursive: true });

    const lockPath = path.resolve(
      resolvedQuarantine,
      `${path.basename(resolvedFile)}.quarantine.lock.json`,
    );
    if (!lockPath.startsWith(resolvedQuarantine + path.sep)) {
      return null;
    }

    fs.writeFileSync(
      lockPath,
      JSON.stringify(
        {
          quarantined_at: new Date().toISOString(),
          original_path: resolvedFile,
          reason,
        },
        null,
        2,
      ),
      'utf8',
    );
    return lockPath;
  } catch {
    return null;
  }
}

async function postJson(url: string, body: unknown): Promise<Record<string, unknown> | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function reportEndpointEvent(
  opts: AgentCliOptions,
  kind: 'file_access' | 'process_spawn' | 'canary_touch',
  subject: string,
  detail: string,
): Promise<void> {
  const response = await postJson(`${opts.serverUrl}/api/endpoints/event`, {
    endpoint_id: opts.endpointId,
    kind,
    subject,
    detail,
  });

  const directive =
    response && typeof response.local_directive === 'string'
      ? response.local_directive
      : 'allow';

  if (
    opts.mode === 'enforce_contain' &&
    directive !== 'allow' &&
    (kind === 'file_access' || kind === 'canary_touch')
  ) {
    const lockFile = enforceLocalFileContainment(subject, opts.quarantineDir, detail);
    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        agent: opts.endpointId,
        action: 'local_containment_enforced',
        directive,
        subject,
        lockFile,
      }),
    );
  }
}

async function scanWatchDirectory(opts: AgentCliOptions): Promise<number> {
  let detected = 0;
  if (!fs.existsSync(opts.watchDir)) return detected;

  const entries = fs.readdirSync(opts.watchDir, { withFileTypes: true });
  for (const entry of entries.slice(0, 200)) {
    if (!entry.isFile()) continue;
    const candidate = path.resolve(opts.watchDir, entry.name);
    if (!candidate.startsWith(opts.watchDir + path.sep)) continue;

    const sensitiveName = SUSPICIOUS_FILE_PATTERNS.some((rx) => rx.test(entry.name));
    let suspiciousContent = false;
    try {
      const stat = fs.statSync(candidate);
      if (stat.size <= 128 * 1024) {
        const txt = fs.readFileSync(candidate, 'utf8');
        suspiciousContent = SUSPICIOUS_CONTENT_PATTERN.test(txt);
      }
    } catch {
      // Ignore unreadable files
    }

    if (sensitiveName || suspiciousContent) {
      detected += 1;
      await reportEndpointEvent(
        opts,
        /fake_config|canary_note/i.test(entry.name) ? 'canary_touch' : 'file_access',
        candidate,
        suspiciousContent
          ? 'Detected suspicious exfiltration/canary pattern in watched file.'
          : 'Sensitive credential or config file observed in watched directory.',
      );
    }
  }

  for (const proc of sampleSuspiciousProcesses()) {
    detected += 1;
    await reportEndpointEvent(
      opts,
      'process_spawn',
      `pid:${proc.pid}`,
      `Suspicious local process signature: ${proc.command}`,
    );
  }

  return detected;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  await postJson(`${opts.serverUrl}/api/endpoints/register`, {
    endpoint_id: opts.endpointId,
    hostname: os.hostname(),
    platform: os.platform(),
    pid: process.pid,
    version: '1.0.0',
    mode: opts.mode,
    watch_paths: [opts.watchDir],
  });

  const initialFindings = await scanWatchDirectory(opts);
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      event: 'sentinel_agent.ready',
      endpoint_id: opts.endpointId,
      mode: opts.mode,
      watch_dir: opts.watchDir,
      initial_findings: initialFindings,
    }),
  );

  if (opts.once) {
    return;
  }

  const watcher = fs.watch(opts.watchDir, (_eventType, filename) => {
    if (!filename) return;
    const target = path.resolve(opts.watchDir, String(filename));
    if (!target.startsWith(opts.watchDir + path.sep)) return;
    if (
      SUSPICIOUS_FILE_PATTERNS.some((rx) => rx.test(String(filename))) ||
      fs.existsSync(target)
    ) {
      void scanWatchDirectory(opts);
    }
  });

  const timer = setInterval(() => {
    void postJson(`${opts.serverUrl}/api/endpoints/register`, {
      endpoint_id: opts.endpointId,
      hostname: os.hostname(),
      platform: os.platform(),
      pid: process.pid,
      version: '1.0.0',
      mode: opts.mode,
      watch_paths: [opts.watchDir],
    });
    void scanWatchDirectory(opts);
  }, opts.intervalMs);

  const shutdown = () => {
    clearInterval(timer);
    watcher.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

void main();
