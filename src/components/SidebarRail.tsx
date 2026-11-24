import React from 'react';
import { ShieldAlert, Terminal, Activity } from 'lucide-react';
import type { AgentBaseline, TrapSessionRecord } from '../types/security';

interface SidebarRailProps {
  trapSessions: TrapSessionRecord[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  baselines: AgentBaseline[];
}

export const SidebarRail: React.FC<SidebarRailProps> = ({
  trapSessions,
  selectedSessionId,
  onSelectSession,
  baselines,
}) => {
  return (
    <aside className="w-full lg:w-[272px] shrink-0 bg-white border border-slate-200 rounded-xl p-4 h-fit">
      <div>
        <div className="flex items-center justify-between pb-3 border-b border-slate-100">
          <h2 className="text-sm font-semibold text-slate-900">Trap Sessions</h2>
          <span className="font-mono text-xs text-slate-500 tabular-nums">
            {trapSessions.length}
          </span>
        </div>

        <div className="mt-2 divide-y divide-slate-100 max-h-[340px] overflow-y-auto">
          {trapSessions.length === 0 ? (
            <p className="py-4 text-xs text-slate-500">No trap sessions recorded yet.</p>
          ) : (
            trapSessions.map((session) => {
              const isSelected = selectedSessionId === session.session_id;
              const hasCanary = session.execution.canary_hits.length > 0;
              return (
                <button
                  key={session.session_id}
                  type="button"
                  onClick={() => onSelectSession(session.session_id)}
                  className={`w-full text-left py-2.5 px-2.5 rounded-lg transition-colors duration-150 cursor-pointer focus-visible:outline-2 focus-visible:outline-blue-600 ${
                    isSelected ? 'bg-slate-100' : 'hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-medium text-slate-900 truncate">
                      {session.session_id}
                    </span>
                    {hasCanary ? (
                      <ShieldAlert className="w-3.5 h-3.5 text-red-600 shrink-0" aria-label="Canary triggered" />
                    ) : (
                      <Terminal className="w-3.5 h-3.5 text-slate-400 shrink-0" aria-label="Trap session" />
                    )}
                  </div>
                  <div className="mt-1 flex items-center gap-1.5 text-xs text-slate-500 truncate">
                    <span className="truncate">{session.agent_id}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono">{session.attribution.confidence}</span>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>

      <div className="mt-6 pt-5 border-t border-slate-200">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100">
          <h2 className="text-sm font-semibold text-slate-900">Agent Baselines</h2>
          <Activity className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
        </div>

        <div className="mt-2 divide-y divide-slate-100">
          {baselines.map((base) => (
            <div key={base.agent_id} className="py-2.5">
              <div className="text-xs font-medium text-slate-900 truncate">{base.agent_id}</div>
              <div className="text-xs text-slate-500 truncate">{base.role}</div>
              <div className="mt-1 flex items-center gap-1.5 text-xs text-slate-500 font-mono tabular-nums">
                <span>avg {base.avg_records_per_call} rec</span>
                <span aria-hidden="true">·</span>
                <span>{base.normal_tools.length} tools</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
};
