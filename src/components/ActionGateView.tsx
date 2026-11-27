import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ShieldX,
  ArrowUpRight,
} from 'lucide-react';
import type {
  ActionGateEvaluation,
  ActionPhase,
  AgentBaseline,
  HarnessScenario,
  IngressProvenance,
  ProvenanceTag,
  PublicRuntimeConfig,
  SemanticAuditResult,
  SourceTrust,
  TriggerSource,
} from '../types/security';
import type { EvaluateActionRequest, SemanticAuditRequest } from '../services/sentinelService';

interface ActionGateViewProps {
  baselines: AgentBaseline[];
  scenarios: HarnessScenario[];
  selectedScenario?: HarnessScenario | null;
  latestEvaluation: ActionGateEvaluation | null;
  runtimeConfig: PublicRuntimeConfig | null;
  onEvaluate: (payload: EvaluateActionRequest) => Promise<ActionGateEvaluation>;
  onSemanticAudit: (payload: SemanticAuditRequest) => Promise<SemanticAuditResult>;
  onSendToTrap: (params: {
    agent_id: string;
    prompt: string;
    agent_code: string;
    ingress: IngressProvenance;
  }) => void;
}

export const ActionGateView: React.FC<ActionGateViewProps> = ({
  baselines,
  scenarios,
  selectedScenario,
  latestEvaluation,
  runtimeConfig,
  onEvaluate,
  onSemanticAudit,
  onSendToTrap,
}) => {
  const initial = scenarios[0];
  const [agentId, setAgentId] = useState(initial?.agent_id ?? 'agent-triage-01');
  const [userGoal, setUserGoal] = useState(
    initial?.user_goal ?? 'Summarize customer support ticket #4812 for weekly triage',
  );
  const [phase, setPhase] = useState<ActionPhase>(initial?.phase ?? 'tool_call');
  const [sourceTrust, setSourceTrust] = useState<SourceTrust>(
    initial?.source_trust ?? 'untrusted_external',
  );
  const [provenanceTag, setProvenanceTag] = useState<ProvenanceTag>(
    initial?.provenance_tag ?? 'VECTOR_DB_DOC',
  );
  const [triggerSource, setTriggerSource] = useState<TriggerSource>(
    initial?.trigger_source ?? 'retrieved_doc',
  );
  const [toolName, setToolName] = useState(initial?.tool_name ?? 'http_post');
  const [targetResource, setTargetResource] = useState(
    initial?.target_resource ?? 'https://drop.evil-relay.test/exfil',
  );
  const [recordCount, setRecordCount] = useState(initial?.record_count ?? 140);
  const [priorToolsInput, setPriorToolsInput] = useState(
    (initial?.prior_tools ?? ['retriever_query', 'read_sensitive_doc', 'list_external_webhooks']).join(', '),
  );
  const [rawPayload, setRawPayload] = useState(initial?.raw_payload ?? '');
  const [linkedAgentCode, setLinkedAgentCode] = useState(initial?.agent_code ?? '');
  const [ingress, setIngress] = useState<IngressProvenance>(
    initial?.ingress ?? {
      peer_ip: '198.51.100.42',
      peer_port: 54122,
      origin_server: 'relay-node-07.partner.internal',
      auth_principal: 'agent-key-8841',
      user_agent: 'AgentRunner/2.4',
      protocol: 'https',
      extra_headers: {},
    },
  );
  const [result, setResult] = useState<ActionGateEvaluation | null>(latestEvaluation);
  const [evaluateError, setEvaluateError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [semanticAudit, setSemanticAudit] = useState<SemanticAuditResult | null>(null);
  const [semanticError, setSemanticError] = useState<string | null>(null);
  const [auditingSemantic, setAuditingSemantic] = useState(false);

  const loadPreset = (scenario: HarnessScenario) => {
    setAgentId(scenario.agent_id);
    setUserGoal(scenario.user_goal);
    setPhase(scenario.phase);
    setSourceTrust(scenario.source_trust);
    setProvenanceTag(scenario.provenance_tag);
    setTriggerSource(scenario.trigger_source);
    setToolName(scenario.tool_name);
    setTargetResource(scenario.target_resource);
    setRecordCount(scenario.record_count);
    setPriorToolsInput(scenario.prior_tools.join(', '));
    setRawPayload(scenario.raw_payload);
    setLinkedAgentCode(scenario.agent_code);
    setIngress(scenario.ingress);
  };

  React.useEffect(() => {
    if (selectedScenario) {
      loadPreset(selectedScenario);
    }
  }, [selectedScenario?.id]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setEvaluateError(null);
    try {
      const prior_tools = priorToolsInput
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const evaluation = await onEvaluate({
        agent_id: agentId,
        user_goal: userGoal,
        phase,
        source_trust: sourceTrust,
        provenance_tag: provenanceTag,
        trigger_source: triggerSource,
        tool_name: toolName,
        target_resource: targetResource,
        record_count: Number(recordCount) || 0,
        prior_tools,
        raw_payload: rawPayload,
        ingress,
      });
      setResult(evaluation);
    } catch (err) {
      setEvaluateError(
        err instanceof Error ? err.message : 'Unable to evaluate action boundary.',
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleSemanticAudit = async () => {
    setAuditingSemantic(true);
    setSemanticError(null);
    try {
      const audit = await onSemanticAudit({
        user_goal: userGoal,
        tool_name: toolName,
        target_resource: targetResource,
        provenance_tag: provenanceTag,
        source_trust: sourceTrust,
        raw_payload: rawPayload,
      });
      setSemanticAudit(audit);
    } catch (err) {
      setSemanticError(err instanceof Error ? err.message : 'Semantic audit failed');
    } finally {
      setAuditingSemantic(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Preset Scenario Selector Bar */}
      <section className="bg-white border border-slate-200 rounded-xl p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
          <div>
            <h1 className="font-display text-lg font-semibold text-slate-900">
              Action-Boundary Interceptor & Hybrid Scorer
            </h1>
            <p className="text-xs text-slate-500 mt-0.5">
              Deterministic policy gating around llm.invoke(), retriever.query(), tool.execute(), and memory.write().
            </p>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-slate-500 mr-1">Load Thesis Fixture:</span>
          {scenarios.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => loadPreset(s)}
              className="px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {s.name}
            </button>
          ))}
        </div>
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left Form: Interceptor Context */}
        <form
          onSubmit={handleSubmit}
          className="xl:col-span-6 bg-white border border-slate-200 rounded-xl p-6 space-y-4"
        >
          <h2 className="text-sm font-semibold text-slate-900 pb-3 border-b border-slate-100">
            01. Execution Span & Provenance Payload
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <label className="block">
              <span className="text-xs font-medium text-slate-700">Agent ID (Rolling Baseline)</span>
              <select
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-mono"
              >
                {baselines.map((b) => (
                  <option key={b.agent_id} value={b.agent_id}>
                    {b.agent_id} ({b.role})
                  </option>
                ))}
              </select>
            </label>

            <label className="block">
              <span className="text-xs font-medium text-slate-700">Execution Phase</span>
              <select
                value={phase}
                onChange={(e) => setPhase(e.target.value as ActionPhase)}
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-mono"
              >
                <option value="input_ingest">input_ingest</option>
                <option value="plan">plan</option>
                <option value="tool_call">tool_call</option>
                <option value="memory_write">memory_write</option>
                <option value="egress">egress</option>
              </select>
            </label>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <label className="block">
              <span className="text-xs font-medium text-slate-700">Source Trust</span>
              <select
                value={sourceTrust}
                onChange={(e) => setSourceTrust(e.target.value as SourceTrust)}
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-mono"
              >
                <option value="trusted">trusted</option>
                <option value="mixed">mixed</option>
                <option value="untrusted_external">untrusted_external</option>
              </select>
            </label>

            <label className="block">
              <span className="text-xs font-medium text-slate-700">Provenance Tag</span>
              <select
                value={provenanceTag}
                onChange={(e) => setProvenanceTag(e.target.value as ProvenanceTag)}
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-mono"
              >
                <option value="AUTHENTICATED_USER">AUTHENTICATED_USER</option>
                <option value="SYSTEM_CONFIG">SYSTEM_CONFIG</option>
                <option value="VECTOR_DB_DOC">VECTOR_DB_DOC</option>
                <option value="EXTERNAL_WEB">EXTERNAL_WEB</option>
                <option value="TOOL_RESULT">TOOL_RESULT</option>
              </select>
            </label>

            <label className="block">
              <span className="text-xs font-medium text-slate-700">Trigger Source</span>
              <select
                value={triggerSource}
                onChange={(e) => setTriggerSource(e.target.value as TriggerSource)}
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-mono"
              >
                <option value="user_prompt">user_prompt</option>
                <option value="retrieved_doc">retrieved_doc</option>
                <option value="tool_output">tool_output</option>
                <option value="webhook">webhook</option>
              </select>
            </label>
          </div>

          <label className="block">
            <span className="text-xs font-medium text-slate-700">Initial User Goal (Intent Anchor)</span>
            <input
              type="text"
              value={userGoal}
              onChange={(e) => setUserGoal(e.target.value)}
              className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
            />
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <label className="block">
              <span className="text-xs font-medium text-slate-700">Proposed Tool</span>
              <input
                type="text"
                value={toolName}
                onChange={(e) => setToolName(e.target.value)}
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-mono"
              />
            </label>

            <label className="block sm:col-span-2">
              <span className="text-xs font-medium text-slate-700">Target Resource / URL</span>
              <input
                type="text"
                value={targetResource}
                onChange={(e) => setTargetResource(e.target.value)}
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-mono"
              />
            </label>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <label className="block sm:col-span-2">
              <span className="text-xs font-medium text-slate-700">
                Prior Tool Sequence (Comma-Separated N-Gram)
              </span>
              <input
                type="text"
                value={priorToolsInput}
                onChange={(e) => setPriorToolsInput(e.target.value)}
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-mono"
              />
            </label>

            <label className="block">
              <span className="text-xs font-medium text-slate-700">Record Count</span>
              <input
                type="number"
                min={0}
                value={recordCount}
                onChange={(e) => setRecordCount(Number(e.target.value))}
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-mono tabular-nums"
              />
            </label>
          </div>

          <label className="block">
            <span className="text-xs font-medium text-slate-700">
              Observed Context / Tool Argument Payload
            </span>
            <textarea
              rows={4}
              value={rawPayload}
              onChange={(e) => setRawPayload(e.target.value)}
              className="mt-1 w-full px-3 py-2 text-xs bg-slate-900 text-slate-100 border border-slate-800 rounded-lg font-mono"
            />
          </label>

          <div className="pt-2 flex flex-wrap items-center justify-between gap-3">
            <span className="text-xs text-slate-500">
              Ingress Peer: <span className="font-mono">{ingress.peer_ip}</span>
              {runtimeConfig && (
                <>
                  {' '}
                  <span aria-hidden="true">·</span> Model:{' '}
                  <span className="font-mono">{runtimeConfig.intentModel}</span>
                </>
              )}
            </span>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={handleSemanticAudit}
                disabled={auditingSemantic}
                className="px-3.5 py-2 text-xs font-medium text-slate-800 bg-slate-100 hover:bg-slate-200 disabled:opacity-60 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                {auditingSemantic ? 'Auditing Intent...' : 'Semantic Intent Audit'}
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="px-4 py-2 text-sm font-medium text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-60 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                {submitting ? 'Evaluating...' : 'Evaluate Action Boundary'}
              </button>
            </div>
          </div>
          {evaluateError && (
            <p className="p-3 rounded-lg border border-red-200 bg-red-50 text-xs text-red-700">
              {evaluateError}
            </p>
          )}
        </form>

        {/* Right Panel: Deterministic Decision & Detector Signals */}
        <div className="xl:col-span-6 bg-white border border-slate-200 rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h2 className="text-sm font-semibold text-slate-900">
              02. Hybrid Scorer Verdict & Telemetry Hash
            </h2>
            {result && (
              <span className="font-mono text-xs text-slate-500 tabular-nums">
                {result.latency_ms} ms
              </span>
            )}
          </div>

          {!result ? (
            <p className="py-12 text-center text-sm text-slate-500">
              Submit an action payload to inspect real-time behavioral scoring and gate enforcement.
            </p>
          ) : (
            <>
              {/* Verdict Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg bg-slate-50 border border-slate-200">
                <div>
                  <div className="text-xs text-slate-500">Boundary Enforcement Decision</div>
                  <div className="mt-1 flex items-center gap-2">
                    {result.decision === 'ALLOW_LOG' && (
                      <>
                        <CheckCircle2 className="w-5 h-5 text-emerald-700" aria-hidden="true" />
                        <span className="text-base font-semibold text-emerald-800">
                          Allow + Log
                        </span>
                      </>
                    )}
                    {result.decision === 'STEP_UP_QUARANTINE' && (
                      <>
                        <AlertTriangle className="w-5 h-5 text-amber-700" aria-hidden="true" />
                        <span className="text-base font-semibold text-amber-800">
                          Step-Up Quarantine / Trap Dry-Run
                        </span>
                      </>
                    )}
                    {result.decision === 'HARD_BLOCK_REVOKE' && (
                      <>
                        <ShieldX className="w-5 h-5 text-red-700" aria-hidden="true" />
                        <span className="text-base font-semibold text-red-800">
                          Hard Block + Credential Revocation
                        </span>
                      </>
                    )}
                  </div>
                </div>

                {result.decision !== 'ALLOW_LOG' && (
                  <button
                    type="button"
                    onClick={() =>
                      onSendToTrap({
                        agent_id: result.event.agent_id,
                        prompt: `${userGoal}\n${rawPayload}`,
                        agent_code:
                          linkedAgentCode ||
                          `import urllib.request\ntry:\n    urllib.request.urlopen("${targetResource}", timeout=2)\nexcept Exception as exc:\n    print("Blocked outbound attempt:", type(exc).__name__, exc)`,
                        ingress,
                      })
                    }
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <span>Isolate in Trap Sandbox</span>
                    <ArrowUpRight className="w-3.5 h-3.5" aria-hidden="true" />
                  </button>
                )}
              </div>

              {/* Numeric Risk Breakdown */}
              <div className="grid grid-cols-3 divide-x divide-slate-200 border border-slate-200 rounded-lg py-3">
                <div className="px-4">
                  <div className="text-xs text-slate-500">Action Risk</div>
                  <div className="mt-0.5 font-mono text-lg font-semibold text-slate-900 tabular-nums">
                    {result.action_risk.toFixed(2)}
                  </div>
                </div>
                <div className="px-4">
                  <div className="text-xs text-slate-500">Anomaly Score</div>
                  <div className="mt-0.5 font-mono text-lg font-semibold text-slate-900 tabular-nums">
                    {result.anomaly_score.toFixed(2)}
                  </div>
                </div>
                <div className="px-4">
                  <div className="text-xs text-slate-500">Combined Risk</div>
                  <div className="mt-0.5 font-mono text-lg font-semibold text-slate-900 tabular-nums">
                    {result.combined_risk.toFixed(2)}
                  </div>
                </div>
              </div>

              {/* AgentRiskClassifier & Trace Metadata */}
              <div className="text-xs space-y-1.5 font-mono text-slate-600 bg-slate-50 p-3.5 rounded-lg border border-slate-200">
                <div>
                  <span className="text-slate-500">payload_hash:</span>{' '}
                  <span className="text-slate-900 break-all">{result.event.payload_hash}</span>
                </div>
                <div>
                  <span className="text-slate-500">tool_sequence:</span>{' '}
                  <span className="text-slate-900">
                    {result.sequence_chain.join(' -> ') || 'none'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">classifier.should_trap:</span>{' '}
                  <span className="text-slate-900">
                    {String(result.classifier.should_trap)} (score{' '}
                    {result.classifier.risk_score.toFixed(2)})
                  </span>
                </div>
              </div>

              {/* Detector Signals */}
              <div>
                <h3 className="text-xs font-semibold text-slate-900 mb-2">
                  Triggered Detection Signals ({result.signals.length})
                </h3>
                {result.signals.length === 0 ? (
                  <p className="text-xs text-slate-500 py-3">
                    No injection, sequence, volumetric, or canary anomalies triggered. Action matches agent baseline.
                  </p>
                ) : (
                  <div className="divide-y divide-slate-200 border border-slate-200 rounded-lg">
                    {result.signals.map((sig, i) => (
                      <div key={`${sig.detector}-${i}`} className="p-3.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-slate-900">
                            {sig.detector}
                          </span>
                          <span className="font-mono text-xs text-slate-600 tabular-nums">
                            {sig.severity} · score {sig.score.toFixed(2)}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-slate-600">{sig.summary}</p>
                        <div className="mt-1.5 font-mono text-[11px] text-slate-500 break-all">
                          evidence: {sig.evidence.join(' | ')}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              {/* Optional Semantic Intent Audit Escalation (Configured Server Model) */}
              {(semanticAudit || semanticError) && (
                <div className="pt-4 border-t border-slate-200">
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <h3 className="text-xs font-semibold text-slate-900">
                      Semantic Intent Escalation
                    </h3>
                    {semanticAudit && (
                      <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                        {semanticAudit.model_id} · {semanticAudit.latency_ms} ms
                      </span>
                    )}
                  </div>

                  {semanticError ? (
                    <p className="p-3 rounded-lg border border-red-200 bg-red-50 text-xs text-red-700">
                      {semanticError}
                    </p>
                  ) : (
                    semanticAudit && (
                      <div className="p-3.5 rounded-lg border border-slate-200 bg-slate-50 space-y-1.5 text-xs">
                        <div className="flex items-center justify-between font-mono">
                          <span className="font-semibold text-slate-900">
                            {semanticAudit.classification}
                          </span>
                          <span className="text-slate-700 tabular-nums">
                            divergence {semanticAudit.intent_divergence_score.toFixed(2)} · hidden_directive:{' '}
                            {String(semanticAudit.hidden_directive_detected)}
                          </span>
                        </div>
                        <p className="text-slate-600">{semanticAudit.rationale}</p>
                      </div>
                    )
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};
