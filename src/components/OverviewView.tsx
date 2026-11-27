import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Search,
  ShieldX,
} from 'lucide-react';
import type {
  ActionGateEvaluation,
  GateDecision,
  QuarantineQueueItem,
  TrapSessionRecord,
} from '../types/security';
import type { WorkspaceView } from './TopNav';

interface OverviewViewProps {
  evaluations: ActionGateEvaluation[];
  quarantineQueue: QuarantineQueueItem[];
  trapSessions: TrapSessionRecord[];
  onNavigate: (view: WorkspaceView) => void;
  onSelectSession: (sessionId: string) => void;
  onResolveQuarantine: (
    id: string,
    action: 'route_to_trap' | 'approve_once' | 'revoke',
  ) => Promise<void>;
}

const DECISION_LABELS: Record<GateDecision, string> = {
  ALLOW_LOG: 'Allow + Log',
  STEP_UP_QUARANTINE: 'Step-Up Quarantine',
  HARD_BLOCK_REVOKE: 'Hard Block + Revoke',
};

function renderDecisionState(decision: GateDecision) {
  if (decision === 'ALLOW_LOG') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 whitespace-nowrap">
        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        <span>Allow + Log</span>
      </span>
    );
  }
  if (decision === 'STEP_UP_QUARANTINE') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-700 whitespace-nowrap">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        <span>Step-Up Quarantine</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700 whitespace-nowrap">
      <ShieldX className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      <span>Hard Block + Revoke</span>
    </span>
  );
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  evaluations,
  quarantineQueue,
  trapSessions,
  onNavigate,
  onSelectSession,
  onResolveQuarantine,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [decisionFilter, setDecisionFilter] = useState<'ALL' | GateDecision>('ALL');
  const [busyId, setBusyId] = useState<string | null>(null);
  const [resolveError, setResolveError] = useState<string | null>(null);

  const metrics = useMemo(() => {
    const blockedCount = evaluations.filter((e) => e.decision !== 'ALLOW_LOG').length;
    const canaryHits = trapSessions.reduce(
      (sum, s) => sum + s.execution.canary_hits.length,
      0,
    );
    const blockedEgress = trapSessions.reduce(
      (sum, s) => sum + s.execution.blocked_attempts.length,
      0,
    );
    return {
      totalInspected: evaluations.length,
      containedCount: blockedCount,
      canaryHits,
      blockedEgress,
    };
  }, [evaluations, trapSessions]);

  const filteredEvaluations = useMemo(() => {
    return evaluations.filter((ev) => {
      if (decisionFilter !== 'ALL' && ev.decision !== decisionFilter) {
        return false;
      }
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        ev.event.agent_id.toLowerCase().includes(q) ||
        (ev.event.tool_name ?? '').toLowerCase().includes(q) ||
        (ev.event.target_resource ?? '').toLowerCase().includes(q) ||
        ev.event.provenance_tag.toLowerCase().includes(q) ||
        ev.event.payload_hash.toLowerCase().includes(q)
      );
    });
  }, [evaluations, decisionFilter, searchQuery]);

  const handleResolve = async (
    id: string,
    action: 'route_to_trap' | 'approve_once' | 'revoke',
  ) => {
    setBusyId(id);
    setResolveError(null);
    try {
      await onResolveQuarantine(id, action);
    } catch (err) {
      setResolveError(
        err instanceof Error ? err.message : 'Unable to update quarantine item.',
      );
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header & Unified Defense-in-Depth Architecture Strip */}
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-6 border-b border-slate-200">
          <div>
            <p className="text-xs font-medium text-slate-500">
              Defense-in-Depth Agent Containment Architecture
            </p>
            <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight text-slate-900 text-balance">
              Early Detection, Zero-Egress Trap & Origin Attribution
            </h1>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('action-gate')}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-slate-900 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>Inspect Action Boundary</span>
            <ArrowRight className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>

        {/* 4-Stage Pipeline Flow */}
        <div className="mt-6 grid grid-cols-1 md:grid-cols-4 gap-4">
          <button
            type="button"
            onClick={() => onNavigate('origin-attribution')}
            className="text-left p-4 rounded-lg border border-slate-200 hover:border-slate-300 bg-slate-50/50 transition-colors cursor-pointer"
          >
            <div className="text-xs font-medium text-slate-500">01. Gateway Edge</div>
            <div className="mt-1 text-sm font-semibold text-slate-900">
              Ingress Provenance Collector
            </div>
            <p className="mt-1.5 text-xs text-slate-600 leading-relaxed">
              Binds peer IP, ASN/relay headers, auth principal, and origin server by session ID.
            </p>
          </button>

          <button
            type="button"
            onClick={() => onNavigate('action-gate')}
            className="text-left p-4 rounded-lg border border-slate-200 hover:border-slate-300 bg-slate-50/50 transition-colors cursor-pointer"
          >
            <div className="text-xs font-medium text-slate-500">02. Inline Interceptor</div>
            <div className="mt-1 text-sm font-semibold text-slate-900">
              Behavioral Scorer & Gate
            </div>
            <p className="mt-1.5 text-xs text-slate-600 leading-relaxed">
              Scores injection collisions, goal drift, graph n-grams, and volume spikes before commit.
            </p>
          </button>

          <button
            type="button"
            onClick={() => onNavigate('trap-sandbox')}
            className="text-left p-4 rounded-lg border border-slate-200 hover:border-slate-300 bg-slate-50/50 transition-colors cursor-pointer"
          >
            <div className="text-xs font-medium text-slate-500">03. Air-Gapped MicroVM</div>
            <div className="mt-1 text-sm font-semibold text-slate-900">
              Zero-Egress Trap Sandbox
            </div>
            <p className="mt-1.5 text-xs text-slate-600 leading-relaxed">
              Enforces --network=none, seccomp blocks, and decoy files while logging JSONL telemetry.
            </p>
          </button>

          <button
            type="button"
            onClick={() => onNavigate('origin-attribution')}
            className="text-left p-4 rounded-lg border border-slate-200 hover:border-slate-300 bg-slate-50/50 transition-colors cursor-pointer"
          >
            <div className="text-xs font-medium text-slate-500">04. Forensic Correlator</div>
            <div className="mt-1 text-sm font-semibold text-slate-900">
              Origin Attribution Engine
            </div>
            <p className="mt-1.5 text-xs text-slate-600 leading-relaxed">
              Joins upstream metadata with extracted C2 URLs, domains, and IPs with confidence caveats.
            </p>
          </button>
        </div>

        {/* 4-Column Quantitative Strip with Hairline Dividers */}
        <div className="mt-6 pt-6 border-t border-slate-200 grid grid-cols-2 md:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-slate-200">
          <div className="py-2 md:pr-6">
            <div className="text-xs text-slate-500">Inspected Actions</div>
            <div className="mt-1 font-mono text-2xl font-semibold text-slate-900 tabular-nums">
              {metrics.totalInspected}
            </div>
            <div className="mt-0.5 text-xs text-slate-500">SHA-256 hashed spans</div>
          </div>

          <div className="py-2 md:px-6">
            <div className="text-xs text-slate-500">Contained / Revoked</div>
            <div className="mt-1 font-mono text-2xl font-semibold text-slate-900 tabular-nums">
              {metrics.containedCount}
            </div>
            <div className="mt-0.5 text-xs text-slate-500">Quarantined or blocked</div>
          </div>

          <div className="py-2 md:px-6">
            <div className="text-xs text-slate-500">Canary Tripwires Fired</div>
            <div className="mt-1 font-mono text-2xl font-semibold text-red-700 tabular-nums">
              {metrics.canaryHits}
            </div>
            <div className="mt-0.5 text-xs text-slate-500">Decoy file or key reads</div>
          </div>

          <div className="py-2 md:pl-6">
            <div className="text-xs text-slate-500">Blocked Egress Attempts</div>
            <div className="mt-1 font-mono text-2xl font-semibold text-slate-900 tabular-nums">
              {metrics.blockedEgress}
            </div>
            <div className="mt-0.5 text-xs text-slate-500">Intercepted at boundary</div>
          </div>
        </div>
      </section>

      {/* Human-in-the-Loop Quarantine Queue */}
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-200">
          <div>
            <h2 className="text-base font-semibold text-slate-900">
              Human-in-the-Loop Quarantine Queue
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Actions held by deterministic boundary enforcement awaiting operator routing or credential revocation.
            </p>
          </div>
          <span className="font-mono text-xs text-slate-600 tabular-nums">
            {quarantineQueue.filter((q) => q.status === 'pending_review').length} pending review
          </span>
        </div>

        {resolveError && (
          <p className="mt-4 p-3 rounded-lg border border-red-200 bg-red-50 text-xs text-red-700">
            {resolveError}
          </p>
        )}

        {quarantineQueue.length === 0 ? (
          <div className="py-10 text-center">
            <p className="text-sm text-slate-600">No held or quarantined actions in queue.</p>
            <button
              type="button"
              onClick={() => onNavigate('action-gate')}
              className="mt-3 px-4 py-2 text-xs font-medium text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
            >
              Evaluate an Agent Action
            </button>
          </div>
        ) : (
          <div className="divide-y divide-slate-200">
            {quarantineQueue.map((item) => (
              <div
                key={item.id}
                className="py-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    {renderDecisionState(item.evaluation.decision)}
                    <span aria-hidden="true">·</span>
                    <span className="font-mono text-slate-900">{item.evaluation.event.agent_id}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono">{item.evaluation.event.tool_name}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono tabular-nums">
                      risk {item.evaluation.combined_risk.toFixed(2)}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span>status: {item.status.replace(/_/g, ' ')}</span>
                  </div>
                  <p className="mt-1.5 text-sm font-medium text-slate-900 truncate">
                    {item.user_goal}
                  </p>
                  <p className="mt-0.5 font-mono text-xs text-slate-500 truncate">
                    {item.evaluation.event.target_resource} · signals:{' '}
                    {item.evaluation.signals.map((s) => s.detector).join(', ') || 'policy_threshold'}
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  {item.linked_trap_session_id ? (
                    <button
                      type="button"
                      onClick={() => {
                        onSelectSession(item.linked_trap_session_id!);
                        onNavigate('trap-sandbox');
                      }}
                      className="px-3 py-1.5 text-xs font-medium text-slate-900 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Inspect {item.linked_trap_session_id}
                    </button>
                  ) : (
                    <>
                      <button
                        type="button"
                        disabled={busyId === item.id || item.status === 'revoked'}
                        onClick={() => handleResolve(item.id, 'route_to_trap')}
                        className="px-3 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-50 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Route to Trap
                      </button>
                      <button
                        type="button"
                        disabled={busyId === item.id || item.status === 'approved_once'}
                        onClick={() => handleResolve(item.id, 'approve_once')}
                        className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-200 hover:bg-slate-50 disabled:opacity-50 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Approve Once
                      </button>
                      <button
                        type="button"
                        disabled={busyId === item.id || item.status === 'revoked'}
                        onClick={() => handleResolve(item.id, 'revoke')}
                        className="px-3 py-1.5 text-xs font-medium text-red-700 bg-white border border-red-200 hover:bg-red-50 disabled:opacity-50 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Revoke Credentials
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Immutable Audit & Telemetry Event Table */}
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <h2 className="text-base font-semibold text-slate-900">
              Immutable Telemetry & Action Audit Sink
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Append-only AgentActionEvent records with provenance tags and SHA-256 payload digests.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search
                className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2"
                aria-hidden="true"
              />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter agent, tool, hash..."
                aria-label="Filter telemetry stream"
                className="pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-slate-400"
              />
            </div>

            <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
              {(['ALL', 'ALLOW_LOG', 'STEP_UP_QUARANTINE', 'HARD_BLOCK_REVOKE'] as const).map(
                (opt) => (
                  <button
                    key={opt}
                    type="button"
                    onClick={() => setDecisionFilter(opt)}
                    className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      decisionFilter === opt
                        ? 'bg-white text-slate-900 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {opt === 'ALL' ? 'All' : DECISION_LABELS[opt]}
                  </button>
                ),
              )}
            </div>
          </div>
        </div>

        <div className="mt-2 overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-medium text-slate-500">
                <th className="py-2.5 pr-4">Agent / Phase</th>
                <th className="py-2.5 pr-4">Provenance</th>
                <th className="py-2.5 pr-4">Tool & Target</th>
                <th className="py-2.5 pr-4 text-right">Records</th>
                <th className="py-2.5 pr-4 text-right">Risk</th>
                <th className="py-2.5 pr-4">Gate Decision</th>
                <th className="py-2.5 text-right">SHA-256 Digest</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {filteredEvaluations.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No telemetry events match the active filter.
                  </td>
                </tr>
              ) : (
                filteredEvaluations.map((ev) => (
                  <tr key={ev.event.trace_id} className="hover:bg-slate-50/70">
                    <td className="py-2.5 pr-4">
                      <div className="font-mono font-medium text-slate-900">
                        {ev.event.agent_id}
                      </div>
                      <div className="text-slate-500 font-mono">{ev.event.phase}</div>
                    </td>
                    <td className="py-2.5 pr-4">
                      <div className="font-mono text-slate-800">{ev.event.provenance_tag}</div>
                      <div className="text-slate-500">{ev.event.source_trust}</div>
                    </td>
                    <td className="py-2.5 pr-4 max-w-[260px]">
                      <div className="font-mono font-medium text-slate-900 truncate">
                        {ev.event.tool_name}
                      </div>
                      <div className="font-mono text-slate-500 truncate">
                        {ev.event.target_resource}
                      </div>
                    </td>
                    <td className="py-2.5 pr-4 text-right font-mono tabular-nums text-slate-700">
                      {ev.event.record_count}
                    </td>
                    <td className="py-2.5 pr-4 text-right font-mono tabular-nums font-medium text-slate-900">
                      {ev.combined_risk.toFixed(2)}
                    </td>
                    <td className="py-2.5 pr-4">{renderDecisionState(ev.decision)}</td>
                    <td className="py-2.5 text-right font-mono tabular-nums text-slate-500">
                      {ev.event.payload_hash.slice(0, 12)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
