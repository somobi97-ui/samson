import net from 'net';
import type {
  AttributionFinding,
  BlockedNetworkAttempt,
  IngressProvenance,
} from '../../src/types/security.ts';

// Exact regexes from Thesis 1 (IndicatorExtractor)
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const URL_REGEX = /\bhttps?:\/\/[^\s"'<>()]+/gi;
const DOMAIN_REGEX = /\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b/g;

export const COMMON_NON_C2_DOMAINS = new Set([
  'python.org',
  'pypi.org',
  'github.com',
  'example.com',
  'localhost',
]);

export function isPrivateOrLoopbackIp(ip: string): boolean {
  const trimmed = ip.trim();
  const family = net.isIP(trimmed);
  if (family === 4) {
    const parts = trimmed.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return false;
    }
    const [a, b] = parts;
    // 10.0.0.0/8, 127.0.0.0/8 (loopback), 169.254.0.0/16 (link-local), 172.16.0.0/12, 192.168.0.0/16
    if (a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    return false;
  }
  if (family === 6) {
    const lower = trimmed.toLowerCase();
    return (
      lower === '::1' ||
      lower.startsWith('fe80:') ||
      lower.startsWith('fc') ||
      lower.startsWith('fd')
    );
  }
  return false;
}

export function extractIndicators(textBlobs: string[]): {
  urls: string[];
  domains: string[];
  ips: string[];
} {
  const combined = textBlobs.join('\n');

  const urls = Array.from(new Set(combined.match(URL_REGEX) ?? [])).sort();
  const rawIps = Array.from(new Set(combined.match(IPV4_REGEX) ?? [])).sort();
  const validIps = rawIps.filter((candidate) => net.isIP(candidate) !== 0);

  const rawDomains = Array.from(
    new Set((combined.match(DOMAIN_REGEX) ?? []).map((d) => d.toLowerCase().replace(/^\.+|\.+$/g, ''))),
  ).sort();

  const domains = rawDomains.filter(
    (d) =>
      !COMMON_NON_C2_DOMAINS.has(d) &&
      !d.endsWith('.py') &&
      !d.endsWith('.txt') &&
      !d.endsWith('.env') &&
      !d.endsWith('.json'),
  );

  return {
    urls,
    domains,
    ips: validIps,
  };
}

export function buildAttributionReport(params: {
  session_id: string;
  ingress: IngressProvenance;
  observed_texts: string[];
  blocked_network_attempts: BlockedNetworkAttempt[];
}): AttributionFinding {
  const indicators = extractIndicators(params.observed_texts);

  const urlSet = new Set(indicators.urls);
  const ipSet = new Set(indicators.ips);
  const domainSet = new Set(indicators.domains);

  for (const attempt of params.blocked_network_attempts) {
    if (attempt.target_url) {
      urlSet.add(attempt.target_url);
    }
    if (attempt.target_host) {
      const host = attempt.target_host.toLowerCase();
      if (net.isIP(host) !== 0) {
        ipSet.add(host);
      } else if (!COMMON_NON_C2_DOMAINS.has(host)) {
        domainSet.add(host);
      }
    }
  }

  const urls = Array.from(urlSet).sort();
  const ips = Array.from(ipSet).sort();
  const domains = Array.from(domainSet).sort();

  const isPrivate = isPrivateOrLoopbackIp(params.ingress.peer_ip);

  const notes: string[] = [
    'Sandbox ran with zero outbound internet access; live external callbacks were blocked.',
    'Upstream peer IP reflects the immediate network client/proxy, not necessarily the final threat actor behind VPNs or relays.',
  ];

  if (params.ingress.origin_server) {
    notes.push(
      `Declared origin_server '${params.ingress.origin_server}' should be verified via mTLS/signed tokens rather than trusted blindly.`,
    );
  }
  if (isPrivate) {
    notes.push(
      'Immediate peer IP is private/loopback; inspect upstream reverse proxy or internal relay logs for the external hop.',
    );
  }

  const hasStrongUpstream =
    Boolean(params.ingress.auth_principal || params.ingress.origin_server) && !isPrivate;
  const hasEmbeddedTargets = urls.length > 0 || domains.length > 0 || ips.length > 0;

  let confidence: 'low' | 'low-to-medium' | 'medium' = 'low';
  if (hasStrongUpstream && hasEmbeddedTargets) {
    confidence = 'medium';
  } else if (hasStrongUpstream || hasEmbeddedTargets) {
    confidence = 'low-to-medium';
  }

  return {
    session_id: params.session_id,
    generated_at: new Date().toISOString(),
    upstream_peer_ip: params.ingress.peer_ip,
    upstream_peer_is_private_or_loopback: isPrivate,
    declared_origin_server: params.ingress.origin_server,
    auth_principal: params.ingress.auth_principal,
    extracted_urls: urls,
    extracted_domains: domains,
    extracted_ips: ips,
    confidence,
    notes,
  };
}
