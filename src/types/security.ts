export type ActionPhase = 'input_ingest' | 'plan' | 'tool_call' | 'memory_write' | 'egress';

export type SourceTrust = 'trusted' | 'untrusted_external' | 'mixed';

export type ProvenanceTag =
  | 'SYSTEM_CONFIG'
  | 'AUTHENTICATED_USER'
  | 'EXTERNAL_WEB'
  | 'VECTOR_DB_DOC'
  | 'TOOL_RESULT';

export type TriggerSource = 'user_prompt' | 'retrieved_doc' | 'tool_output' | 'webhook';

export type GateDecision = 'ALLOW_LOG' | 'STEP_UP_QUARANTINE' | 'HARD_BLOCK_REVOKE';

export type SandboxRuntime = 'gvisor-runsc' | 'firecracker-microvm' | 'docker-runc';

export interface AgentActionEvent {
  timestamp: string;
  agent_id: string;
  session_id: string;
  trace_id: string;
  parent_span_id?: string;
  identity_scope: string;
  trigger_source: TriggerSource;
  provenance_tag: ProvenanceTag;
  phase: ActionPhase;
  source_trust: SourceTrust;
  tool_name: string | null;
  target_resource: string | null;
  payload_hash: string;
  record_count: number;
  metadata: Record<string, unknown>;
}

export interface IngressProvenance {
  peer_ip: string;
  peer_port: number | null;
  origin_server: string | null;
  auth_principal: string | null;
  user_agent: string | null;
  protocol: string;
  extra_headers: Record<string, string>;
}

export interface SandboxPolicy {
  cpu_quota: string;
  memory_limit: string;
  pids_limit: number;
  timeout_seconds: number;
  image: string;
  enable_decoy_workspace: boolean;
  runtime: SandboxRuntime;
  seccomp_enabled: boolean;
  strip_env_secrets: boolean;
  host_firewall_drop_imds: boolean;
}

export interface TelemetryEvent {
  timestamp: string;
  session_id: string;
  event_type: string;
  payload: Record<string, unknown>;
}

export interface AttributionFinding {
  session_id: string;
  generated_at: string;
  upstream_peer_ip: string;
  upstream_peer_is_private_or_loopback: boolean;
  declared_origin_server: string | null;
  auth_principal: string | null;
  extracted_urls: string[];
  extracted_domains: string[];
  extracted_ips: string[];
  confidence: 'low' | 'low-to-medium' | 'medium';
  notes: string[];
}

export interface DetectorSignal {
  detector: string;
  category: 'classifier' | 'injection' | 'behavioral' | 'deception' | 'policy';
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  score: number;
  summary: string;
  evidence: string[];
}

export interface ActionGateEvaluation {
  event: AgentActionEvent;
  classifier: {
    risk_score: number;
    should_trap: boolean;
    matched_patterns: string[];
  };
  action_risk: number;
  anomaly_score: number;
  combined_risk: number;
  decision: GateDecision;
  signals: DetectorSignal[];
  sequence_chain: string[];
  latency_ms: number;
  credential_revoked: boolean;
}

export interface BlockedNetworkAttempt {
  type: string;
  target_url?: string;
  target_host?: string;
  reason: string;
}

export interface TrapExecutionResult {
  status: 'completed' | 'timeout' | 'blocked_syscall';
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_sec: number;
  blocked_attempts: BlockedNetworkAttempt[];
  canary_hits: string[];
  decoy_reads: string[];
  syscall_violations: string[];
  docker_command: string[];
  seccomp_profile: Record<string, unknown>;
}

export interface TrapSessionRecord {
  session_id: string;
  created_at: string;
  agent_id: string;
  reason: string;
  status: 'quarantined' | 'destroyed' | 'revoked' | 'active';
  ingress: IngressProvenance;
  policy: SandboxPolicy;
  prompt: string;
  agent_code: string;
  decoy_files: Record<string, string>;
  telemetry: TelemetryEvent[];
  execution: TrapExecutionResult;
  attribution: AttributionFinding;
}

export interface QuarantineQueueItem {
  id: string;
  created_at: string;
  status: 'pending_review' | 'routed_to_trap' | 'approved_once' | 'revoked';
  user_goal: string;
  raw_payload: string;
  ingress: IngressProvenance;
  evaluation: ActionGateEvaluation;
  operator_note?: string;
  linked_trap_session_id?: string;
}

export interface AgentBaseline {
  agent_id: string;
  role: string;
  avg_records_per_call: number;
  normal_tools: string[];
  allowed_egress_domains: string[];
  error_rate: number;
  known_transitions: string[];
}

export interface HarnessScenario {
  id: string;
  name: string;
  thesis_focus: string;
  expected_decision: GateDecision;
  expected_should_trap: boolean;
  user_goal: string;
  agent_id: string;
  phase: ActionPhase;
  source_trust: SourceTrust;
  provenance_tag: ProvenanceTag;
  trigger_source: TriggerSource;
  tool_name: string;
  target_resource: string;
  record_count: number;
  prior_tools: string[];
  raw_payload: string;
  agent_code: string;
  ingress: IngressProvenance;
}

export interface HarnessTestResult {
  scenario: HarnessScenario;
  passed: boolean;
  actual_decision: GateDecision;
  actual_should_trap: boolean;
  combined_risk: number;
  triggered_detectors: string[];
  canary_triggered: boolean;
  attribution_confidence: string;
  latency_ms: number;
}

export interface SemanticAuditResult {
  model_id: string;
  thinking_level: string;
  intent_divergence_score: number;
  hidden_directive_detected: boolean;
  classification: 'ALIGNED' | 'SUSPICIOUS_DRIFT' | 'HIJACKED_INTENT';
  rationale: string;
  latency_ms: number;
}

export interface PublicRuntimeConfig {
  intentModel: string;
  thinkingLevel: string;
  aiConfigured: boolean;
  detectorThresholds: {
    trapThreshold: number;
    blockThreshold: number;
    classifierPatternWeight?: number;
  };
  defaultPolicy: SandboxPolicy;
  imdsHost: string;
  sandboxExecutionMode?: 'deterministic' | 'docker';
  edge?: {
    allowedUpstreams: string[];
    forwardTimeoutMs: number;
  };
  limits?: {
    aiMaxPerMinute: number;
    mutationMaxPerMinute: number;
    maxAiInputChars: number;
    maxAiOutputTokens: number;
    hourlyTokenCap: number;
  };
}

export type EndpointContainmentMode = 'monitor' | 'enforce_contain';

export interface EndpointAgentRecord {
  endpoint_id: string;
  hostname: string;
  platform: string;
  pid: number | null;
  version: string;
  mode: EndpointContainmentMode;
  watch_paths: string[];
  status: 'online' | 'contained' | 'stale';
  last_heartbeat: string;
  local_alerts_count: number;
  contained_actions_count: number;
}

export interface EndpointActivityEvent {
  event_id: string;
  endpoint_id: string;
  hostname: string;
  timestamp: string;
  kind: 'file_access' | 'process_spawn' | 'network_probe' | 'canary_touch';
  subject: string;
  detail: string;
  decision: GateDecision;
  combined_risk: number;
  containment_action: 'logged' | 'quarantined_file' | 'blocked_process' | 'revoked_local_token';
  payload_hash: string;
}

export type EdgeTransitAction =
  | 'FORWARD_UPSTREAM'
  | 'REROUTED_TO_TRAP'
  | 'BLOCKED_IN_TRANSIT';

export interface EdgeInspectionRecord {
  inspection_id: string;
  timestamp: string;
  method: string;
  path: string;
  upstream_host: string | null;
  upstream_allowed: boolean;
  forwarded: boolean;
  upstream_status: number | null;
  edge_action: EdgeTransitAction;
  evaluation: ActionGateEvaluation;
  linked_trap_session_id?: string;
  attribution?: AttributionFinding;
}

export interface ApplianceStatus {
  mode: 'standalone-appliance';
  node_version: string;
  platform: string;
  uptime_sec: number;
  sandbox_execution_mode: 'deterministic' | 'docker';
  docker_cli_available: boolean;
  stored_records: {
    evaluations: number;
    quarantine_queue: number;
    trap_sessions: number;
    endpoints: number;
    edge_logs: number;
    max_cap: number;
  };
  recent_incidents_count: number;
}

export interface CliScanFinding {
  file: string;
  line: number;
  severity: 'medium' | 'high' | 'critical';
  rule: string;
  summary: string;
}

export interface CliScanReport {
  scanned_at: string;
  target_path: string;
  files_scanned: number;
  passed: boolean;
  findings: CliScanFinding[];
  config_warnings: string[];
}
