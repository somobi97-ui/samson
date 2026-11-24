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
