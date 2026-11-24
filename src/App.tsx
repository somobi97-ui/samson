import { useCallback, useEffect, useState } from 'react';
import { TopNav, type WorkspaceView } from './components/TopNav';
import { SidebarRail } from './components/SidebarRail';
import { OverviewView } from './components/OverviewView';
import { ActionGateView } from './components/ActionGateView';
import { TrapSandboxView } from './components/TrapSandboxView';
import { OriginAttributionView } from './components/OriginAttributionView';
import { HarnessView } from './components/HarnessView';
import type {
  ActionGateEvaluation,
  ActionPhase,
  AgentBaseline,
  AttributionFinding,
  HarnessScenario,
  HarnessTestResult,
  IngressProvenance,
  ProvenanceTag,
  QuarantineQueueItem,
  SandboxPolicy,
  SourceTrust,
  TrapSessionRecord,
  TriggerSource,
} from './types/security';

interface AppStateResponse {
  baselines: AgentBaseline[];
  evaluations: ActionGateEvaluation[];
  quarantineQueue: QuarantineQueueItem[];
  trapSessions: TrapSessionRecord[];
  scenarios: HarnessScenario[];
  defaultPolicy: SandboxPolicy;
}

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

  const fetchState = useCallback(async () => {
    try {
      const res = await fetch('/api/state');
      if (!res.ok) {
        throw new Error(`Failed to load telemetry state (${res.status})`);
      }
      const data: AppStateResponse = await res.json();
      setBaselines(data.baselines);
      setEvaluations(data.evaluations);
      setQuarantineQueue(data.quarantineQueue);
      setTrapSessions(data.trapSessions);
      setScenarios(data.scenarios);
      setDefaultPolicy(data.defaultPolicy);
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
    fetchState();
  }, [fetchState]);

  const activeSession =
    trapSessions.find((s) => s.session_id === selectedSessionId) ?? trapSessions[0] ?? null;

  const handleEvaluate = async (payload: {
    agent_id: string;
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
    ingress: IngressProvenance;
  }): Promise<ActionGateEvaluation> => {
    const res = await fetch('/api/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error('Action boundary evaluation failed');
    }
    const data: { evaluation: ActionGateEvaluation; queueItem: QuarantineQueueItem | null } =
      await res.json();
    setEvaluations((prev) => [data.evaluation, ...prev]);
    if (data.queueItem) {
      setQuarantineQueue((prev) => [data.queueItem!, ...prev]);
    }
    return data.evaluation;
  };

  const handleResolveQuarantine = async (
    id: string,
    action: 'route_to_trap' | 'approve_once' | 'revoke',
  ) => {
    const res = await fetch(`/api/quarantine/${encodeURIComponent(id)}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
    if (!res.ok) {
      throw new Error('Failed to resolve quarantine item');
    }
    const data: { item: QuarantineQueueItem; trapSession?: TrapSessionRecord } = await res.json();
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
    const res = await fetch('/api/sandbox/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    if (!res.ok) {
      throw new Error('Trap sandbox execution failed');
    }
    const data: { session: TrapSessionRecord } = await res.json();
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
    const res = await fetch('/api/attribution/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    if (!res.ok) {
      throw new Error('Attribution correlation failed');
    }
    const data: { finding: AttributionFinding } = await res.json();
    return data.finding;
  };

  const handleRunHarness = async () => {
    setRunningHarness(true);
    try {
      const res = await fetch('/api/harness/run', { method: 'POST' });
      if (!res.ok) {
        throw new Error('Regression suite execution failed');
      }
      const data: { results: HarnessTestResult[] } = await res.json();
      setHarnessResults(data.results);
      setActiveView('regression-harness');
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
              onClick={fetchState}
              className="mt-3 px-4 py-2 text-xs font-medium text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
            >
              Retry Connection
            </button>
          </div>
        ) : (
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
                  onEvaluate={handleEvaluate}
                  onSendToTrap={(draft) => {
                    setSandboxDraft(draft);
                    setActiveView('trap-sandbox');
                  }}
                />
              )}

              {activeView === 'trap-sandbox' && defaultPolicy && (
                <TrapSandboxView
                  defaultPolicy={defaultPolicy}
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
        )}
      </main>
    </div>
  );
}
