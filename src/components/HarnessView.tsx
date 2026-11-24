import React from 'react';
import { CheckCircle2, XCircle, Play } from 'lucide-react';
import type { HarnessScenario, HarnessTestResult } from '../types/security';

interface HarnessViewProps {
  scenarios: HarnessScenario[];
  results: HarnessTestResult[] | null;
  running: boolean;
  onRunHarness: () => Promise<void>;
  onLoadScenarioInGate: (scenario: HarnessScenario) => void;
}

export const HarnessView: React.FC<HarnessViewProps> = ({
  scenarios,
  results,
  running,
  onRunHarness,
  onLoadScenarioInGate,
}) => {
  const passedCount = results ? results.filter((r) => r.passed).length : 0;

  return (
    <div className="space-y-6">
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <h1 className="font-display text-lg font-semibold text-slate-900">
              Adversarial & Regression Detection Harness
            </h1>
            <p className="text-xs text-slate-500 mt-0.5">
              Continuous verification of indirect injection fixtures, tool-chaining exploits, canary tripwires, and benign baseline precision.
            </p>
          </div>

          <button
            type="button"
            onClick={onRunHarness}
            disabled={running}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-60 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" aria-hidden="true" />
            <span>{running ? 'Running Suite...' : 'Run Regression Suite'}</span>
          </button>
        </div>

        {results && (
          <div className="mt-4 pt-4 border-b border-slate-200 pb-4 grid grid-cols-2 sm:grid-cols-4 divide-x divide-slate-200">
            <div className="pr-4">
              <div className="text-xs text-slate-500">Fixtures Executed</div>
              <div className="mt-0.5 font-mono text-xl font-semibold text-slate-900 tabular-nums">
                {results.length}
              </div>
            </div>
            <div className="px-4">
              <div className="text-xs text-slate-500">Assertions Passed</div>
              <div className="mt-0.5 font-mono text-xl font-semibold text-emerald-700 tabular-nums">
                {passedCount} / {results.length}
              </div>
            </div>
            <div className="px-4">
              <div className="text-xs text-slate-500">Canary Tripwires Verified</div>
              <div className="mt-0.5 font-mono text-xl font-semibold text-slate-900 tabular-nums">
                {results.filter((r) => r.canary_triggered).length}
              </div>
            </div>
            <div className="pl-4">
              <div className="text-xs text-slate-500">Mean Scorer Latency</div>
              <div className="mt-0.5 font-mono text-xl font-semibold text-slate-900 tabular-nums">
                {(
                  results.reduce((s, r) => s + r.latency_ms, 0) / Math.max(1, results.length)
                ).toFixed(2)}{' '}
                ms
              </div>
            </div>
          </div>
        )}

        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-medium text-slate-500">
                <th className="py-2.5 pr-4">Test Fixture</th>
                <th className="py-2.5 pr-4">Expected Gate</th>
                <th className="py-2.5 pr-4">Actual Gate</th>
                <th className="py-2.5 pr-4 text-right">Risk</th>
                <th className="py-2.5 pr-4">Triggered Detectors</th>
                <th className="py-2.5 pr-4">Result</th>
                <th className="py-2.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {(results ?? scenarios.map((s) => ({ scenario: s }))).map((row) => {
                const evaluated = 'passed' in row ? (row as HarnessTestResult) : null;
                const sc = row.scenario;
                return (
                  <tr key={sc.id} className="hover:bg-slate-50/70">
                    <td className="py-3 pr-4">
                      <div className="font-medium text-slate-900">{sc.name}</div>
                      <div className="text-slate-500 mt-0.5">{sc.thesis_focus}</div>
                    </td>
                    <td className="py-3 pr-4 font-mono text-slate-700">
                      {sc.expected_decision}
                    </td>
                    <td className="py-3 pr-4 font-mono text-slate-900">
                      {evaluated ? evaluated.actual_decision : '—'}
                    </td>
                    <td className="py-3 pr-4 text-right font-mono tabular-nums text-slate-900">
                      {evaluated ? evaluated.combined_risk.toFixed(2) : '—'}
                    </td>
                    <td className="py-3 pr-4 font-mono text-[11px] text-slate-600 max-w-[240px]">
                      {evaluated
                        ? evaluated.triggered_detectors.join(', ') || 'none (baseline)'
                        : 'Pending run'}
                    </td>
                    <td className="py-3 pr-4">
                      {evaluated ? (
                        evaluated.passed ? (
                          <span className="inline-flex items-center gap-1 font-medium text-emerald-700 whitespace-nowrap">
                            <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                            <span>Pass</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 font-medium text-red-700 whitespace-nowrap">
                            <XCircle className="w-3.5 h-3.5" aria-hidden="true" />
                            <span>Fail</span>
                          </span>
                        )
                      ) : (
                        <span className="text-slate-400">Not run</span>
                      )}
                    </td>
                    <td className="py-3 text-right">
                      <button
                        type="button"
                        onClick={() => onLoadScenarioInGate(sc)}
                        className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
