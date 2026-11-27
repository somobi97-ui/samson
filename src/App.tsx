import { useCallback, useEffect, useState } from 'react';
import { TopNav, type WorkspaceView } from './components/TopNav';
import { SidebarRail } from './components/SidebarRail';
import { OverviewView } from './components/OverviewView';
import { ActionGateView } from './components/ActionGateView';
import { TrapSandboxView } from './components/TrapSandboxView';
import { OriginAttributionView } from './components/OriginAttributionView';
import { HarnessView } from './components/HarnessView';
import {
  sentinelService,
  type EvaluateActionRequest,
  type SemanticAuditRequest,
} from './services/sentinelService';
import type {
  ActionGateEvaluation,
  AgentBaseline,
  AttributionFinding,
  HarnessScenario,
  HarnessTestResult,
  IngressProvenance,
  PublicRuntimeConfig,
  QuarantineQueueItem,
  SandboxPolicy,
  SemanticAuditResult,
  TrapSessionRecord,
} from './types/security';

export default function App() {
  const [activeView, setActiveView] = useState<WorkspaceView>('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [baselines, setBaselines] = useState<AgentBaseline[]>([]);
  const [evaluations, setEvaluations] = useState<ActionGateEvaluation[]>([]);
  const [quarantineQueue, setQuarantineQueue] = useState<QuarantineQueueItem[]>([]);
  const [trapSessions, setTrapSessions] = useState<TrapSessionRecord[]>([]);
  const [scenarios, setScenarios] = useState<HarnessScenario[]>([]);
  const [defaultPolicy, setDefaultPolicy] = useState<SandboxPolicy | null>(null);
  const [runtimeConfig, setRuntimeConfig] = useState<PublicRuntimeConfig | null>(null);

  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedScenario, setSelectedScenario] = useState<HarnessScenario | null>(null);
  const [sandboxDraft, setSandboxDraft] = useState<{
    agent_id: string;
    prompt: string;
    agent_code: string;
    ingress: IngressProvenance;
  } | null>(null);

  const [harnessResults, setHarnessResults] = useState<HarnessTestResult[] | null>(null);
  const [runningHarness, setRunningHarness] = useState(false);

  const loadPlatformState = useCallback(async () => {
    setLoading(true);
    try {
      const data = await sentinelService.fetchState();
      if (
        !data ||
        !Array.isArray(data.baselines) ||
        !Array.isArray(data.evaluations) ||
        !Array.isArray(data.quarantineQueue) ||
        !Array.isArray(data.trapSessions) ||
        !Array.isArray(data.scenarios)
      ) {
        throw new Error('Received incomplete state payload from security backend.');
      }

      setBaselines(data.baselines);
      setEvaluations(data.evaluations);
      setQuarantineQueue(data.quarantineQueue);
      setTrapSessions(data.trapSessions);
      setScenarios(data.scenarios);
      setDefaultPolicy(data.defaultPolicy ?? null);
      setRuntimeConfig(data.runtimeConfig ?? null);
      if (data.trapSessions.length > 0) {
        setSelectedSessionId((prev) => prev ?? data.trapSessions[0].session_id);
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to reach security backend');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPlatformState();
  }, [loadPlatformState]);

  const safeTrapSessions = Array.isArray(trapSessions) ? trapSessions : [];
  const activeSession =
    safeTrapSessions.find((s) => s.session_id === selectedSessionId) ??
    safeTrapSessions[0] ??
    null;

  const handleEvaluate = async (payload: EvaluateActionRequest): Promise<ActionGateEvaluation> => {
    const data = await sentinelService.evaluateAction(payload);
    setEvaluations((prev) => [data.evaluation, ...prev]);
    if (data.queueItem) {
      setQuarantineQueue((prev) => [data.queueItem!, ...prev]);
    }
    return data.evaluation;
  };

  const handleSemanticAudit = async (
    payload: SemanticAuditRequest,
  ): Promise<SemanticAuditResult> => {
    const data = await sentinelService.runSemanticAudit(payload);
    return data.audit;
  };

  const handleResolveQuarantine = async (
    id: string,
    action: 'route_to_trap' | 'approve_once' | 'revoke',
  ) => {
    const data = await sentinelService.resolveQuarantine(id, action);
    setQuarantineQueue((prev) => prev.map((q) => (q.id === id ? data.item : q)));
    if (data.trapSession) {
      setTrapSessions((prev) => [data.trapSession!, ...prev]);
      setSelectedSessionId(data.trapSession.session_id);
    }
  };

  const handleRunSandbox = async (params: {
    agent_id: string;
    reason: string;
    prompt: string;
    agent_code: string;
    ingress: IngressProvenance;
    policy: SandboxPolicy;
  }): Promise<TrapSessionRecord> => {
    const data = await sentinelService.runSandbox(params);
    setSandboxDraft(null);
    setTrapSessions((prev) => [data.session, ...prev]);
    setSelectedSessionId(data.session.session_id);
    return data.session;
  };

  const handleAnalyzeAttribution = async (params: {
    session_id: string;
    ingress: IngressProvenance;
    observed_texts: string[];
  }): Promise<AttributionFinding> => {
    const data = await sentinelService.analyzeAttribution(params);
    return data.finding;
  };

  const handleRunHarness = async () => {
    setRunningHarness(true);
    try {
      const data = await sentinelService.runHarness();
      setHarnessResults(data.results);
      setError(null);
      setActiveView('regression-harness');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to run adversarial regression harness.');
    } finally {
      setRunningHarness(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
      <TopNav
        activeView={activeView}
        onSelectView={setActiveView}
        onPrimaryAction={handleRunHarness}
        isSimulating={runningHarness}
      />

      <main className="flex-1 max-w-[1440px] w-full mx-auto px-6 py-8">
        {loading ? (
          <div className="bg-white border border-slate-200 rounded-xl p-8 space-y-4">
            <div className="h-6 w-64 bg-slate-100 rounded" />
            <div className="h-24 w-full bg-slate-100 rounded" />
            <div className="h-48 w-full bg-slate-100 rounded" />
          </div>
        ) : error ? (
          <div className="bg-white border border-red-200 rounded-xl p-6 text-sm text-red-700">
            <p className="font-medium">Unable to load security engine state: {error}</p>
            <button
              type="button"
              onClick={loadPlatformState}
              className="mt-3 px-4 py-2 text-xs font-medium text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
            >
              Retry Connection
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {runtimeConfig?.limits && (
              <div className="flex flex-wrap items-center justify-between gap-4 px-4 py-2.5 bg-white border border-slate-200 rounded-xl text-xs text-slate-600">
                <span className="font-mono tabular-nums">
                  Policy Limits: {runtimeConfig.limits.aiMaxPerMinute} AI/min ·{' '}
                  {runtimeConfig.limits.mutationMaxPerMinute} mutations/min ·{' '}
                  {runtimeConfig.limits.maxAiOutputTokens} max out tokens ·{' '}
                  {runtimeConfig.limits.hourlyTokenCap} tok/hr
                </span>
              </div>
            )}

            <div className="flex flex-col lg:flex-row gap-6 items-start">
              <SidebarRail
                trapSessions={trapSessions}
                selectedSessionId={activeSession?.session_id ?? null}
                onSelectSession={(id) => {
                  setSelectedSessionId(id);
                  setSandboxDraft(null);
                  if (activeView === 'overview' || activeView === 'regression-harness') {
                    setActiveView('trap-sandbox');
                  }
                }}
                baselines={baselines}
              />

              <div className="flex-1 min-w-0 w-full">
                {activeView === 'overview' && (
                  <OverviewView
                    evaluations={evaluations}
                    quarantineQueue={quarantineQueue}
                    trapSessions={trapSessions}
                    onNavigate={setActiveView}
                    onSelectSession={(id) => {
                      setSelectedSessionId(id);
                      setSandboxDraft(null);
                    }}
                    onResolveQuarantine={handleResolveQuarantine}
                  />
                )}

                {activeView === 'action-gate' && (
                  <ActionGateView
                    baselines={baselines}
                    scenarios={scenarios}
                    selectedScenario={selectedScenario}
                    latestEvaluation={evaluations[0] ?? null}
                    runtimeConfig={runtimeConfig}
                    onEvaluate={handleEvaluate}
                    onSemanticAudit={handleSemanticAudit}
                    onSendToTrap={(draft) => {
                      setSandboxDraft(draft);
                      setActiveView('trap-sandbox');
                    }}
                  />
                )}

                {activeView === 'trap-sandbox' && defaultPolicy && (
                  <TrapSandboxView
                    defaultPolicy={defaultPolicy}
                    runtimeConfig={runtimeConfig}
                    activeSession={activeSession}
                    draftInput={sandboxDraft}
                    onRunSandbox={handleRunSandbox}
                    onInspectAttribution={(id) => {
                      setSelectedSessionId(id);
                      setActiveView('origin-attribution');
                    }}
                  />
                )}

                {activeView === 'origin-attribution' && (
                  <OriginAttributionView
                    activeSession={activeSession}
                    onAnalyzeAttribution={handleAnalyzeAttribution}
                  />
                )}

                {activeView === 'regression-harness' && (
                  <HarnessView
                    scenarios={scenarios}
                    results={harnessResults}
                    running={runningHarness}
                    onRunHarness={handleRunHarness}
                    onLoadScenarioInGate={(sc) => {
                      setSelectedScenario(sc);
                      setActiveView('action-gate');
                    }}
                  />
                )}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
