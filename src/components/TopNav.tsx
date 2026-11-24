import React from 'react';

export type WorkspaceView =
  | 'overview'
  | 'action-gate'
  | 'trap-sandbox'
  | 'origin-attribution'
  | 'regression-harness';

interface TopNavProps {
  activeView: WorkspaceView;
  onSelectView: (view: WorkspaceView) => void;
  onPrimaryAction: () => void;
  isSimulating: boolean;
}

const NAV_ITEMS: Array<{ id: WorkspaceView; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'action-gate', label: 'Action Gate' },
  { id: 'trap-sandbox', label: 'Trap Sandbox' },
  { id: 'origin-attribution', label: 'Origin Attribution' },
  { id: 'regression-harness', label: 'Regression Harness' },
];

export const TopNav: React.FC<TopNavProps> = ({
  activeView,
  onSelectView,
  onPrimaryAction,
  isSimulating,
}) => {
  return (
    <header className="sticky top-0 z-30 bg-white border-b border-slate-200">
      <div className="max-w-[1440px] mx-auto px-6 h-16 flex items-center justify-between gap-8">
        <a
          href="#overview"
          onClick={(e) => {
            e.preventDefault();
            onSelectView('overview');
          }}
          className="font-display text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
        >
          SentinelGate
        </a>

        <nav
          aria-label="Primary navigation"
          className="hidden md:flex items-center gap-6 overflow-x-auto"
        >
          {NAV_ITEMS.map((item) => {
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectView(item.id)}
                className={`relative py-5 text-sm font-medium transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 ${
                  isActive
                    ? 'text-slate-900'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {item.label}
                {isActive && (
                  <span
                    aria-hidden="true"
                    className="absolute inset-x-0 bottom-0 h-0.5 bg-slate-900"
                  />
                )}
              </button>
            );
          })}
        </nav>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={onPrimaryAction}
            disabled={isSimulating}
            className="px-4 py-2 text-sm font-medium text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-60 rounded-lg transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
          >
            {isSimulating ? 'Running Suite...' : 'Run Simulation'}
          </button>
        </div>
      </div>

      {/* Compact mobile navigation row */}
      <nav
        aria-label="Mobile navigation"
        className="flex md:hidden items-center gap-4 px-4 py-2 border-t border-slate-100 overflow-x-auto"
      >
        {NAV_ITEMS.map((item) => {
          const isActive = activeView === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelectView(item.id)}
              className={`text-xs font-medium py-1 whitespace-nowrap shrink-0 ${
                isActive ? 'text-slate-900 underline underline-offset-4' : 'text-slate-600'
              }`}
            >
              {item.label}
            </button>
          );
        })}
      </nav>
    </header>
  );
};
