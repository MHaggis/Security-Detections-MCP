// Simple class name merger (avoids needing clsx/tailwind-merge)
export function cn(...inputs: (string | undefined | null | false)[]) {
  return inputs.filter(Boolean).join(' ');
}

// Format large numbers with commas
export function formatNumber(num: number): string {
  return num.toLocaleString();
}

// Truncate text with ellipsis
export function truncate(str: string, length: number): string {
  if (str.length <= length) return str;
  return str.slice(0, length) + '...';
}

// Get severity color class
export function severityColor(severity: string | null): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'text-red';
    case 'high': return 'text-orange';
    case 'medium': return 'text-amber';
    case 'low': return 'text-blue';
    case 'informational': return 'text-text-dim';
    default: return 'text-text-dim';
  }
}

// Get source display name
export function sourceDisplayName(source: string): string {
  const names: Record<string, string> = {
    sigma: 'Sigma',
    splunk_escu: 'Splunk ESCU',
    elastic: 'Elastic',
    kql: 'Microsoft KQL',
    sublime: 'Sublime',
    crowdstrike_cql: 'CrowdStrike CQL',
  };
  return names[source] || source;
}

// Get source badge color
export function sourceBadgeColor(source: string): string {
  const colors: Record<string, string> = {
    sigma: 'bg-blue/10 text-blue border-blue/30',
    splunk_escu: 'bg-green/10 text-green border-green/30',
    elastic: 'bg-orange/10 text-orange border-orange/30',
    kql: 'bg-amber/10 text-amber border-amber/30',
    sublime: 'bg-red/10 text-red border-red/30',
    crowdstrike_cql: 'bg-amber/10 text-amber border-amber/30',
  };
  return colors[source] || 'bg-text-dim/10 text-text-dim border-text-dim/30';
}

// Rate limiting helper
export function isRateLimited(
  chatCountToday: number,
  resetAt: string,
  tier: string
): boolean {
  const now = new Date();
  const reset = new Date(resetAt);

  // Reset counter if it's a new day
  if (now.toDateString() !== reset.toDateString()) {
    return false;
  }

  const limit = tier === 'pro' ? 500 : 20;
  return chatCountToday >= limit;
}
