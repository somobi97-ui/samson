import crypto from 'crypto';
import type {
  ActionGateEvaluation,
  ActionPhase,
  AgentActionEvent,
  AgentBaseline,
  DetectorSignal,
  GateDecision,
  ProvenanceTag,
  SourceTrust,
  TriggerSource,
} from '../../src/types/security.ts';
import { serverConfig } from '../config/env.ts';

// Exact SUSPICIOUS_PATTERNS from Thesis 2 (AgentRiskClassifier)
const SUSPICIOUS_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'network_cli_tools', regex: /\b(curl|wget|nc|netcat|ssh|scp|ftp)\b/i },
  { label: 'attack_intent_keywords', regex: /\b(reverse\s*shell|exfiltrat\w*|privilege\s*escalat\w*)\b/i },
  { label: 'sensitive_os_or_imds', regex: /\/etc\/shadow|\/etc\/passwd|169\.254\.169\.254/i },
  { label: 'python_network_libs', regex: /\b(socket|urllib|requests|httpx|aiohttp)\b/i },
];

const INJECTION_PATTERNS: Array<{ label: string; regex: RegExp; weight: number }> = [
  { label: 'role_override_imperative', regex: /\b(ignore\s+(all\s+)?previous|disregard\s+system|new\s+priority|override\s+policy|you\s+are\s+now)\b/i, weight: 0.35 },
  { label: 'hidden_markup_directive', regex: /<!--[\s\S]*?(execute|curl|post|exfil|token|secret|http)[\s\S]*?-->/i, weight: 0.4 },
  { label: 'encoded_payload_marker', regex: /\b(base64\s*-d|atob\(|fromCharCode|exec\(|eval\(|__import__)\b/i, weight: 0.35 },
  { label: 'system_prompt_probe', regex: /\b(reveal\s+system\s+prompt|print\s+env|dump\s+secrets|os\.environ)\b/i, weight: 0.35 },
];

const DANGEROUS_TOOL_NGRAMS: string[][] = [
  ['read_sensitive_doc', 'list_external_webhooks', 'http_post'],
  ['query_secrets', 'create_token'],
  ['read_file', 'http_post'],
  ['query_secrets', 'http_post'],
  ['retriever_query', 'memory_write'],
];

const CANARY_INDICATORS = [
  'DECOY_HONEYPOT_KEY_DO_NOT_USE',
  'TRAP_SESSION_9941',
  'fake_config.env',
  'canary_note.txt',
  '/api/v1/internal/canary-secrets',
  'honeytoken_',
];

const HIGH_BLAST_TOOLS = new Set([
  'http_post',
  'http_request',
  'shell_exec',
  'python_exec',
  'create_token',
  'rotate_key',
  'memory_write',
  'write_config',
  'update_manifest',
]);

const MEDIUM_BLAST_TOOLS = new Set([
  'query_secrets',
  'read_sensitive_doc',
  'list_external_webhooks',
  'read_file',
]);

export function makeAgentActionEvent(params: {
  agent_id: string;
  session_id: string;
  trace_id: string;
  parent_span_id?: string;
  identity_scope?: string;
  trigger_source: TriggerSource;
  provenance_tag: ProvenanceTag;
  phase: ActionPhase;
  source_trust: SourceTrust;
  raw_payload: unknown;
  tool_name?: string | null;
  target_resource?: string | null;
  record_count?: number;
  metadata?: Record<string, unknown>;
}): AgentActionEvent {
  const canonical = JSON.stringify(params.raw_payload, (_key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return Object.keys(value as Record<string, unknown>)
        .sort()
        .reduce<Record<string, unknown>>((acc, k) => {
          acc[k] = (value as Record<string, unknown>)[k];
          return acc;
        }, {});
    }
    return value;
  });

  const digest = crypto.createHash('sha256').update(canonical ?? '', 'utf8').digest('hex');

  return {
    timestamp: new Date().toISOString(),
    agent_id: params.agent_id,
    session_id: params.session_id,
    trace_id: params.trace_id,
    parent_span_id: params.parent_span_id,
    identity_scope: params.identity_scope ?? 'least-privilege-readonly',
    trigger_source: params.trigger_source,
    provenance_tag: params.provenance_tag,
    phase: params.phase,
    source_trust: params.source_trust,
    tool_name: params.tool_name ?? null,
    target_resource: params.target_resource ?? null,
    payload_hash: digest,
    record_count: params.record_count ?? 0,
    metadata: params.metadata ?? {},
  };
}

export function classifyAgentRisk(text: string): {
  risk_score: number;
  should_trap: boolean;
  matched_patterns: string[];
} {
  const matched: string[] = [];
  for (const pat of SUSPICIOUS_PATTERNS) {
    if (pat.regex.test(text)) {
      matched.push(pat.label);
    }
  }
  const risk_score = Math.min(
    1.0,
    Number((matched.length * serverConfig.detector.classifierPatternWeight).toFixed(2)),
  );
  return {
    risk_score,
    should_trap: risk_score >= serverConfig.detector.trapThreshold,
    matched_patterns: matched,
  };
}

export interface EvaluateActionInput {
  agent_id: string;
  session_id: string;
  trace_id: string;
  user_goal: string;
  phase: ActionPhase;
  source_trust: SourceTrust;
  provenance_tag: ProvenanceTag;
  trigger_source: TriggerSource;
  tool_name: string;
  target_resource: string;
  record_count: number;
  prior_tools: string[];
  raw_payload: string;
  baseline: AgentBaseline;
}

export function evaluateActionBoundary(input: EvaluateActionInput): ActionGateEvaluation {
  const startedAt = performance.now();
  const combinedInspectText = [
    input.user_goal,
    input.tool_name,
    input.target_resource,
    input.raw_payload,
  ].join('\n');

  const event = makeAgentActionEvent({
    agent_id: input.agent_id,
    session_id: input.session_id,
    trace_id: input.trace_id,
    trigger_source: input.trigger_source,
    provenance_tag: input.provenance_tag,
    phase: input.phase,
    source_trust: input.source_trust,
    raw_payload: {
      user_goal: input.user_goal,
      tool_name: input.tool_name,
      target_resource: input.target_resource,
      payload: input.raw_payload,
    },
    tool_name: input.tool_name,
    target_resource: input.target_resource,
    record_count: input.record_count,
    metadata: {
      user_goal: input.user_goal,
      prior_tools: input.prior_tools,
    },
  });

  // 1. AgentRiskClassifier (Thesis 2)
  const classifier = classifyAgentRisk(combinedInspectText);
  const signals: DetectorSignal[] = [];

  if (classifier.matched_patterns.length > 0) {
    signals.push({
      detector: 'AgentRiskClassifier',
      category: 'classifier',
      severity: classifier.risk_score >= 0.7 ? 'high' : 'medium',
      score: classifier.risk_score,
      summary: `Matched ${classifier.matched_patterns.length} sandbox trap heuristic pattern(s).`,
      evidence: classifier.matched_patterns,
    });
  }

  // 2. Instruction-in-Data Collision (Thesis 3 - 2A)
  const isUntrustedSpan =
    input.source_trust !== 'trusted' ||
    input.provenance_tag === 'EXTERNAL_WEB' ||
    input.provenance_tag === 'VECTOR_DB_DOC' ||
    input.provenance_tag === 'TOOL_RESULT';

  const injectionHits: string[] = [];
  let injectionScore = 0;
  for (const pat of INJECTION_PATTERNS) {
    if (pat.regex.test(input.raw_payload)) {
      injectionHits.push(pat.label);
      injectionScore += pat.weight;
    }
  }
  if (isUntrustedSpan && injectionHits.length > 0) {
    const score = Math.min(1.0, Number((injectionScore + 0.15).toFixed(2)));
    signals.push({
      detector: 'InstructionInDataCollision',
      category: 'injection',
      severity: score >= 0.7 ? 'critical' : 'high',
      score,
      summary: `Imperative or obfuscated directives detected inside ${input.provenance_tag} (${input.source_trust}) span.`,
      evidence: injectionHits,
    });
  } else if (injectionHits.length > 0) {
    const score = Math.min(0.85, Number(injectionScore.toFixed(2)));
    signals.push({
      detector: 'InstructionInDataCollision',
      category: 'injection',
      severity: 'medium',
      score,
      summary: 'Suspicious imperative/encoding syntax detected in payload.',
      evidence: injectionHits,
    });
  }

  // 3. Goal Drift / Intent Divergence (Thesis 3 - 2A)
  const goalIsBenignReadOnly = /\b(summariz\w*|triage|classify|format|translate|draft|report)\b/i.test(
    input.user_goal,
  );
  const proposedIsPrivilegedOrEgress =
    HIGH_BLAST_TOOLS.has(input.tool_name) ||
    MEDIUM_BLAST_TOOLS.has(input.tool_name) ||
    /https?:\/\/|169\.254\.169\.254|\/etc\/(shadow|passwd)|\.env/i.test(
      `${input.target_resource} ${input.raw_payload}`,
    );

  if (goalIsBenignReadOnly && proposedIsPrivilegedOrEgress) {
    const driftScore = HIGH_BLAST_TOOLS.has(input.tool_name) ? 0.85 : 0.65;
    signals.push({
      detector: 'GoalDriftIntentDivergence',
      category: 'injection',
      severity: driftScore >= 0.8 ? 'high' : 'medium',
      score: driftScore,
      summary: `Proposed action (${input.tool_name}) diverges from initial benign user goal.`,
      evidence: [`goal="${input.user_goal.slice(0, 64)}"`, `proposed_tool=${input.tool_name}`],
    });
  }

  // 4. Memory & Config Mutation Attempts (Thesis 3 - 2A)
  const configTarget = /(\.claude|\.cursor|system_prompt|tool_manifest|agent_config|memory|vector_store)/i.test(
    `${input.tool_name} ${input.target_resource}`,
  );
  if ((input.phase === 'memory_write' || configTarget) && input.source_trust !== 'trusted') {
    signals.push({
      detector: 'MemoryConfigMutationGuard',
      category: 'injection',
      severity: 'critical',
      score: 0.9,
      summary: 'Attempted persistent memory or agent configuration mutation from untrusted provenance.',
      evidence: [`phase=${input.phase}`, `provenance=${input.provenance_tag}`, `target=${input.target_resource}`],
    });
  }

  // 5. Sequence & Graph Anomalies (Thesis 3 - 2B)
  const sequenceChain = [...input.prior_tools, input.tool_name].filter(Boolean);
  const matchedNgram = DANGEROUS_TOOL_NGRAMS.find((ngram) => {
    if (sequenceChain.length < ngram.length) return false;
    const tail = sequenceChain.slice(-ngram.length);
    return ngram.every((step, idx) => tail[idx] === step);
  });

  if (matchedNgram) {
    signals.push({
      detector: 'SequenceGraphAnomaly',
      category: 'behavioral',
      severity: 'critical',
      score: 0.92,
      summary: `High-risk tool call state transition detected: ${matchedNgram.join(' -> ')}.`,
      evidence: matchedNgram,
    });
  } else if (
    input.tool_name &&
    !input.baseline.normal_tools.includes(input.tool_name) &&
    HIGH_BLAST_TOOLS.has(input.tool_name)
  ) {
    signals.push({
      detector: 'SequenceGraphAnomaly',
      category: 'behavioral',
      severity: 'medium',
      score: 0.55,
      summary: `Tool "${input.tool_name}" is outside ${input.agent_id} rolling baseline.`,
      evidence: [`baseline_tools=${input.baseline.normal_tools.join(',')}`],
    });
  }

  // 6. Volumetric, Egress & Reconnaissance Pivot Spikes (Thesis 3 - 2B)
  const volumeRatio =
    input.baseline.avg_records_per_call > 0
      ? input.record_count / input.baseline.avg_records_per_call
      : 1;
  const externalUrlMatch = `${input.target_resource} ${input.raw_payload}`.match(/https?:\/\/([a-z0-9.-]+)/i);
  const targetDomain = externalUrlMatch?.[1]?.toLowerCase() ?? null;
  const domainNotAllowlisted =
    targetDomain !== null && !input.baseline.allowed_egress_domains.includes(targetDomain);

  if (volumeRatio >= 5 || domainNotAllowlisted || /169\.254\.169\.254|port_scan|sweep/i.test(combinedInspectText)) {
    const spikeEvidence: string[] = [];
    let spikeScore = 0;
    if (volumeRatio >= 5) {
      spikeEvidence.push(`record_count=${input.record_count} (${volumeRatio.toFixed(1)}x baseline)`);
      spikeScore += 0.45;
    }
    if (domainNotAllowlisted && targetDomain) {
      spikeEvidence.push(`unfamiliar_egress_domain=${targetDomain}`);
      spikeScore += 0.5;
    }
    if (/169\.254\.169\.254|port_scan|sweep/i.test(combinedInspectText)) {
      spikeEvidence.push('adaptive_recon_or_imds_probe');
      spikeScore += 0.45;
    }
    const capped = Math.min(1.0, Number(spikeScore.toFixed(2)));
    signals.push({
      detector: 'VolumetricAndEgressSpike',
      category: 'behavioral',
      severity: capped >= 0.8 ? 'high' : 'medium',
      score: capped,
      summary: 'Anomalous data volume, unfamiliar egress target, or reconnaissance fanout.',
      evidence: spikeEvidence,
    });
  }

  // 7. Canary / Deception Tripwire (Thesis 1, 2, 3)
  const canaryMatches = CANARY_INDICATORS.filter((marker) =>
    combinedInspectText.toLowerCase().includes(marker.toLowerCase()),
  );
  if (canaryMatches.length > 0) {
    signals.push({
      detector: 'CanaryDeceptionTripwire',
      category: 'deception',
      severity: 'critical',
      score: 1.0,
      summary: 'Agent interacted with synthetic honeytoken, canary file, or decoy API route.',
      evidence: canaryMatches,
    });
  }

  // Action Risk (Blast Radius + Provenance)
  let blastRadius = 0.15;
  if (HIGH_BLAST_TOOLS.has(input.tool_name) || input.phase === 'egress' || input.phase === 'memory_write') {
    blastRadius = 0.8;
  } else if (MEDIUM_BLAST_TOOLS.has(input.tool_name)) {
    blastRadius = 0.5;
  }
  const provenancePenalty =
    input.source_trust === 'untrusted_external' ? 0.2 : input.source_trust === 'mixed' ? 0.1 : 0;
  const action_risk = Math.min(1.0, Number((blastRadius + provenancePenalty).toFixed(2)));

  // Anomaly Score = max signal weighted with signal density
  const maxSignal = signals.reduce((m, s) => Math.max(m, s.score), 0);
  const avgSignal =
    signals.length > 0 ? signals.reduce((sum, s) => sum + s.score, 0) / signals.length : 0;
  const anomaly_score = Math.min(1.0, Number((0.7 * maxSignal + 0.3 * avgSignal).toFixed(2)));

  const combined_risk = Math.min(
    1.0,
    Number((0.4 * action_risk + 0.6 * anomaly_score).toFixed(2)),
  );

  let decision: GateDecision = 'ALLOW_LOG';
  const hasCritical = signals.some((s) => s.severity === 'critical');

  if (
    hasCritical ||
    combined_risk >= serverConfig.detector.blockThreshold ||
    canaryMatches.length > 0
  ) {
    decision = 'HARD_BLOCK_REVOKE';
  } else if (
    combined_risk >= serverConfig.detector.trapThreshold ||
    classifier.should_trap ||
    signals.length > 0
  ) {
    decision = 'STEP_UP_QUARANTINE';
  }

  const latency_ms = Number((performance.now() - startedAt).toFixed(2));

  return {
    event,
    classifier,
    action_risk,
    anomaly_score,
    combined_risk,
    decision,
    signals,
    sequence_chain: sequenceChain,
    latency_ms,
    credential_revoked: decision === 'HARD_BLOCK_REVOKE',
  };
}
