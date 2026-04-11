import { NextRequest } from 'next/server';
import { createClient, createServiceClient } from '@/lib/supabase/server';

export async function POST(request: NextRequest) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { title, content, source_url, is_public } = body as {
      title?: string;
      content?: string;
      source_url?: string;
      is_public?: boolean;
    };

    // Must have either content or a URL
    if (!content && !source_url) {
      return Response.json({ error: 'Provide report content or a URL to analyze' }, { status: 400 });
    }

    // Validate lengths
    if (content && content.length > 100000) {
      return Response.json({ error: 'Content exceeds 100K character limit' }, { status: 400 });
    }
    if (title && title.length > 500) {
      return Response.json({ error: 'Title exceeds 500 character limit' }, { status: 400 });
    }

    const serviceClient = await createServiceClient();

    // If URL provided but no content, fetch it
    let reportText = content || '';
    let reportTitle = title || '';
    const finalUrl = source_url || null;

    if (source_url && !content) {
      // SSRF protection
      try {
        const parsed = new URL(source_url);
        const hostname = parsed.hostname.toLowerCase();
        const BLOCKED_HOSTS = /^(localhost|127\.\d|10\.\d|172\.(1[6-9]|2\d|3[01])\.\d|192\.168\.\d|169\.254\.\d|0\.0\.0\.0|\[::1\]|metadata\.google\.internal)/;
        if (BLOCKED_HOSTS.test(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
          return Response.json({ error: 'Internal/private URLs cannot be fetched' }, { status: 400 });
        }
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          return Response.json({ error: 'Only HTTP/HTTPS URLs are supported' }, { status: 400 });
        }
      } catch {
        return Response.json({ error: 'Invalid URL' }, { status: 400 });
      }

      const response = await fetch(source_url, {
        headers: { 'User-Agent': 'SecurityDetections/1.0 (Threat Report Analyzer)' },
        signal: AbortSignal.timeout(15000),
        redirect: 'follow',
      });

      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > 5 * 1024 * 1024) {
        return Response.json({ error: 'Document too large (max 5MB)' }, { status: 400 });
      }

      if (!response.ok) {
        return Response.json({ error: `Could not fetch URL (HTTP ${response.status})` }, { status: 400 });
      }

      const html = await response.text();

      // Extract title from HTML
      const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
      if (!reportTitle) {
        reportTitle = titleMatch?.[1]?.trim() || source_url;
      }

      // Strip HTML to plain text
      reportText = html
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&[a-z]+;/gi, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    }

    if (!reportTitle) {
      reportTitle = reportText.substring(0, 80).trim() + (reportText.length > 80 ? '...' : '');
    }

    // Create the report row (status: analyzing)
    const { data: report, error: insertError } = await serviceClient
      .from('threat_reports')
      .insert({
        user_id: user.id,
        title: reportTitle,
        content: reportText.substring(0, 100000),
        source_url: finalUrl,
        status: 'analyzing',
        is_public: is_public || false,
      })
      .select('id')
      .single();

    if (insertError || !report) {
      console.error('Failed to create report:', insertError);
      return Response.json({ error: 'Failed to create report' }, { status: 500 });
    }

    // Run analysis
    try {
      const analysis = await analyzeReport(reportText, serviceClient);

      // Update the report with results
      await serviceClient
        .from('threat_reports')
        .update({
          extracted_techniques: analysis.techniques,
          extracted_actors: analysis.actors,
          extracted_iocs: analysis.iocs,
          analysis_result: analysis.result,
          status: 'complete',
        })
        .eq('id', report.id);

      return Response.json({ id: report.id, status: 'complete' });
    } catch (err) {
      console.error('Analysis failed:', err);
      await serviceClient
        .from('threat_reports')
        .update({ status: 'failed' })
        .eq('id', report.id);

      return Response.json({ id: report.id, status: 'failed', error: 'Analysis failed' }, { status: 500 });
    }
  } catch (error) {
    console.error('Report API error:', error);
    return Response.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    );
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ServiceClient = any;

interface AnalysisResult {
  techniques: Array<{ id: string; name: string; covered: boolean; detection_count: number; sources: string[] }>;
  actors: string[];
  iocs: { ips: string[]; hashes: string[]; domains: string[]; cves: string[] };
  result: {
    summary: string;
    total_techniques: number;
    covered_count: number;
    gap_count: number;
    coverage_pct: number;
    gap_techniques: Array<{ id: string; name: string }>;
    covered_techniques: Array<{ id: string; name: string; detection_count: number; sources: string[] }>;
    cve_detections: Array<{ cve: string; detection_count: number }>;
  };
}

async function analyzeReport(text: string, sb: ServiceClient): Promise<AnalysisResult> {
  // Extract MITRE techniques
  const techniqueIds = [...new Set(
    (text.match(/T\d{4}(?:\.\d{3})?/g) || []).map((t: string) => t.toUpperCase())
  )];

  // Extract CVEs
  const cves = [...new Set(
    (text.match(/CVE-\d{4}-\d{4,}/gi) || []).map((c: string) => c.toUpperCase())
  )];

  // Extract IPs (filter private/loopback)
  const ips = [...new Set(
    (text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])
      .filter((ip: string) => !ip.startsWith('0.') && !ip.startsWith('127.') && !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('172.'))
  )];

  // Extract hashes (MD5 + SHA256)
  const md5s = [...new Set(text.match(/\b[a-f0-9]{32}\b/gi) || [])];
  const sha256s = [...new Set(text.match(/\b[a-f0-9]{64}\b/gi) || [])];
  const hashes = [...md5s, ...sha256s];

  // Extract domains (basic pattern)
  const domains = [...new Set(
    (text.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|top|ru|cn|tk|info|biz|cc|pw|ws)\b/gi) || [])
      .filter((d: string) => !d.includes('github.com') && !d.includes('microsoft.com') && !d.includes('mitre.org'))
  )];

  // Extract actor names from text (match known patterns)
  const actorPatterns = text.match(/\b(?:APT|FIN|UNC|DEV|TEMP)\s*-?\d+\b/gi) || [];
  const namedActors = text.match(/\b(?:Lazarus|Kimsuky|Turla|Sandworm|Cozy Bear|Fancy Bear|Charming Kitten|Wizard Spider|Evil Corp|Scattered Spider|BlackCat|LockBit|ALPHV|Volt Typhoon|Salt Typhoon|Midnight Blizzard|Star Blizzard|Forest Blizzard|Emerald Sleet|Diamond Sleet|Citrine Sleet|Sapphire Sleet|Ruby Sleet|Jade Sleet|Onyx Sleet|Peach Sandstorm|Mint Sandstorm|Mango Sandstorm|Pumpkin Sandstorm|Cotton Sandstorm|Crimson Sandstorm|Caramel Tsunami|Silk Typhoon|Flax Typhoon|Raspberry Typhoon|Circle Typhoon|Granite Typhoon|Mulberry Typhoon)\b/gi) || [];
  const actors = [...new Set([...actorPatterns, ...namedActors].map((a: string) => a.trim()))];

  // Query coverage for each technique
  const techniques: AnalysisResult['techniques'] = [];
  for (const tid of techniqueIds.slice(0, 30)) {
    const { data: techIntel } = await sb.rpc('get_technique_intelligence', { p_technique_id: tid }) as {
      data: { technique_name?: string; total_detections?: number; sources_with_coverage?: string[] } | null;
    };
    if (techIntel) {
      techniques.push({
        id: tid,
        name: techIntel.technique_name || 'Unknown',
        covered: (techIntel.total_detections || 0) > 0,
        detection_count: techIntel.total_detections || 0,
        sources: techIntel.sources_with_coverage || [],
      });
    } else {
      techniques.push({ id: tid, name: 'Unknown', covered: false, detection_count: 0, sources: [] });
    }
  }

  // Query CVE detections
  const cveDetections: Array<{ cve: string; detection_count: number }> = [];
  for (const cve of cves.slice(0, 15)) {
    const { data: cveData } = await sb.rpc('search_detections_by_filter', {
      p_filter_type: 'cve',
      p_filter_value: cve,
      p_limit: 5,
    }) as { data: { total?: number } | null };
    cveDetections.push({ cve, detection_count: cveData?.total || 0 });
  }

  const coveredTechniques = techniques.filter(t => t.covered);
  const gapTechniques = techniques.filter(t => !t.covered);
  const totalTechniques = techniques.length;
  const coveragePct = totalTechniques > 0 ? Math.round((coveredTechniques.length / totalTechniques) * 100) : 0;

  // Build summary
  const summaryParts: string[] = [];
  summaryParts.push(`Analyzed report with ${totalTechniques} MITRE ATT&CK techniques identified.`);
  summaryParts.push(`Coverage: ${coveredTechniques.length}/${totalTechniques} techniques (${coveragePct}%) have detections.`);
  if (gapTechniques.length > 0) {
    summaryParts.push(`${gapTechniques.length} gap techniques need detection development.`);
  }
  if (cves.length > 0) summaryParts.push(`${cves.length} CVEs referenced.`);
  if (actors.length > 0) summaryParts.push(`Threat actors mentioned: ${actors.join(', ')}.`);
  if (ips.length > 0 || hashes.length > 0 || domains.length > 0) {
    summaryParts.push(`IOCs extracted: ${ips.length} IPs, ${hashes.length} hashes, ${domains.length} domains.`);
  }

  return {
    techniques,
    actors,
    iocs: { ips, hashes, domains, cves },
    result: {
      summary: summaryParts.join(' '),
      total_techniques: totalTechniques,
      covered_count: coveredTechniques.length,
      gap_count: gapTechniques.length,
      coverage_pct: coveragePct,
      gap_techniques: gapTechniques.map(t => ({ id: t.id, name: t.name })),
      covered_techniques: coveredTechniques.map(t => ({
        id: t.id,
        name: t.name,
        detection_count: t.detection_count,
        sources: t.sources,
      })),
      cve_detections: cveDetections,
    },
  };
}
