import { execFileSync } from 'child_process';
import os from 'os';
import type { ApplianceStatus } from '../../src/types/security.ts';
import { serverConfig } from '../config/env.ts';
import { logger } from '../services/logger.ts';

let cachedDockerAvailable: boolean | null = null;

export function isDockerCliAvailable(): boolean {
  if (cachedDockerAvailable !== null) {
    return cachedDockerAvailable;
  }
  try {
    execFileSync('docker', ['--version'], {
      stdio: 'ignore',
      timeout: 1500,
      shell: false,
    });
    cachedDockerAvailable = true;
  } catch {
    cachedDockerAvailable = false;
  }
  return cachedDockerAvailable;
}

export function getApplianceStatus(counts: {
  evaluations: number;
  quarantine_queue: number;
  trap_sessions: number;
  endpoints: number;
  edge_logs: number;
}): ApplianceStatus {
  return {
    mode: 'standalone-appliance',
    node_version: process.version,
    platform: `${os.platform()}/${os.arch()}`,
    uptime_sec: Math.floor(process.uptime()),
    sandbox_execution_mode: serverConfig.sandbox.executionMode,
    docker_cli_available: isDockerCliAvailable(),
    stored_records: {
      ...counts,
      max_cap: serverConfig.limits.maxStoredRecords,
    },
    recent_incidents_count: logger.getRecentIncidents().length,
  };
}
