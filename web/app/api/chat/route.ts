import { NextRequest } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { createServiceClient } from '@/lib/supabase/server';
import { getModelConfig, getModelRoutingInfo, getRateLimit } from '@/lib/ai/router';
import { buildSystemPrompt } from '@/lib/ai/system-prompt';
import { AI_TOOLS } from '@/lib/ai/tools';
import { executeToolCall } from '@/lib/ai/tool-executor';

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const serviceClient = await createServiceClient();
    const { data: profile } = await serviceClient
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .single();

    const modelInfo = getModelRoutingInfo(profile);
    return Response.json({
      provider: modelInfo.provider,
      source: modelInfo.source,
      model: modelInfo.model,
      label: modelInfo.modelLabel,
      note: modelInfo.note,
      fallback_models: modelInfo.fallbackModels ?? [],
    });
  } catch (error) {
    return Response.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return new Response('Unauthorized', { status: 401 });
    }

    // Use service client for profile operations (bypasses RLS — user already verified above)
    const serviceClient = await createServiceClient();

    // Get profile
    const { data: profile } = await serviceClient
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .single();

    // Check if user is blocked
    if (profile?.tier === 'blocked') {
      return new Response(
        JSON.stringify({ error: 'Your account has been suspended. Contact support.' }),
        { status: 403, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Check OpenRouter monthly usage limit for pro users
    if (profile?.tier === 'pro') {
      const usageResetAt = profile?.openrouter_usage_reset_at ? new Date(profile.openrouter_usage_reset_at) : new Date();
      const now = new Date();
      const monthChanged = now.getMonth() !== usageResetAt.getMonth() || now.getFullYear() !== usageResetAt.getFullYear();

      if (monthChanged) {
        // Reset monthly usage
        await serviceClient.from('profiles').update({
          openrouter_usage_usd: 0,
          openrouter_usage_reset_at: now.toISOString(),
        }).eq('id', user.id);
      } else {
        const currentUsage = profile?.openrouter_usage_usd || 0;
        const limit = profile?.openrouter_usage_limit_usd || 25.0;
        if (currentUsage >= limit) {
          return new Response(
            JSON.stringify({
              error: `Monthly usage limit reached ($${currentUsage.toFixed(2)}/$${limit.toFixed(2)}). Your usage resets next month. Contact support if you need a higher limit.`,
            }),
            { status: 429, headers: { 'Content-Type': 'application/json' } }
          );
        }
      }
    }

    // Atomic rate limit check + increment (prevents race condition bypass)
    const rateLimit = getRateLimit(profile?.tier || 'free');
    const { data: newCount } = await serviceClient.rpc('increment_chat_count', {
      p_user_id: user.id,
      p_limit: rateLimit,
    });

    if (newCount === -1) {
      return new Response(
        JSON.stringify({
          error: `Rate limit exceeded. ${profile?.tier === 'pro' ? '500' : '20'} messages/day. Upgrade to Pro for more.`,
        }),
        { status: 429, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const body = await request.json();
    const { messages } = body;

    // Validate messages array
    if (!Array.isArray(messages) || messages.length === 0 || messages.length > 50) {
      return new Response(JSON.stringify({ error: 'Messages must be an array of 1-50 items' }), { status: 400 });
    }
    for (const msg of messages) {
      if (typeof msg.content !== 'string' || msg.content.length > 20000) {
        return new Response(JSON.stringify({ error: 'Invalid message content' }), { status: 400 });
      }
    }

    const modelInfo = getModelRoutingInfo(profile);
    const modelConfig = getModelConfig(profile);
    let modelUsed = modelInfo.model;
    const hasByokKeys = !!(profile?.claude_api_key_encrypted || profile?.openai_api_key_encrypted || profile?.openrouter_api_key_encrypted);
    const useFreeModelPool = modelInfo.model.endsWith(':free') && !hasByokKeys;

    // For free tier: pre-fetch relevant data and inject into context (free models don't support tool calling)
    // For pro/BYOK: use tool calling for dynamic data lookup
    let systemPrompt = buildSystemPrompt();
    let content: string;

    if (useFreeModelPool) {
      const lastUserMsg = messages[messages.length - 1]?.content || '';

      // For data-heavy queries, build the response with REAL DATA first,
      // then ask the AI only for analysis/recommendations
      const { dataReport } = await buildDataDrivenResponse(lastUserMsg, user.id);

      if (dataReport) {
        // We have structured data — ask AI for brief analysis only
        console.log(`[Chat] Built data report (${dataReport.length} chars)`);

        const analysisPrompt = `You are a concise security analyst. The user asked: "${lastUserMsg}"

Here is the EXACT data from our detection database:

${dataReport}

Write a brief 2-3 sentence analysis of this data. Focus on: what looks good, what the biggest gaps are, and one actionable recommendation. Do NOT repeat the data — it will be shown to the user separately. Do NOT make up any numbers or rule names. Be specific and reference technique IDs.`;

        const { FREE_MODELS } = await import('@/lib/ai/router');
        let aiAnalysis = '';
        for (const freeModel of FREE_MODELS) {
          const config = { ...modelConfig, model: freeModel };
          const response = await callLLMWithRetry(config, [
            { role: 'system', content: 'You are a brief, data-driven security analyst. Only reference data that was provided. Never fabricate numbers.' },
            { role: 'user', content: analysisPrompt },
          ], []);
          const data = await response.json();
          if (!data.error && data.choices?.[0]?.message?.content) {
            aiAnalysis = data.choices[0].message.content;
            modelUsed = freeModel;
            break;
          }
        }

        // Combine: data report first (always accurate), then AI analysis
        content = dataReport + (aiAnalysis ? `\n\n---\n\n**Analysis**\n\n${aiAnalysis}` : '');
        if (!aiAnalysis) {
          modelUsed = 'db-only';
        }
      } else {
        // General/conversational query — use AI with context
        const contextData = await prefetchContext(lastUserMsg);
        if (contextData) {
          systemPrompt += `\n\n--- DATABASE CONTEXT (USE THIS DATA TO ANSWER) ---\n${contextData}\n--- END DATABASE CONTEXT ---`;
        }

        const apiMessages = [
          { role: 'system', content: systemPrompt },
          ...messages,
        ];

        const { FREE_MODELS } = await import('@/lib/ai/router');
        let responseData = null;
        for (const freeModel of FREE_MODELS) {
          const config = { ...modelConfig, model: freeModel };
          const response = await callLLMWithRetry(config, apiMessages, []);
          const data = await response.json();
          if (!data.error) {
            responseData = data;
            modelUsed = freeModel;
            break;
          }
        }

        if (!responseData || responseData.error) {
          const isProOrAdmin = profile?.tier === 'pro' || profile?.tier === 'admin';
          const busyMessage = isProOrAdmin
            ? 'Your Auto setting is using the free model pool, and those models are busy right now. Try again in a moment, or choose a specific model (Claude/GPT) in Account Settings.'
            : 'The free AI models are currently busy. Please try again in a moment, or upgrade to Pro: https://github.com/sponsors/MHaggis';
          return new Response(
            busyMessage,
            { status: 429 }
          );
        }

        content = responseData.choices?.[0]?.message?.content || 'I was unable to generate a response.';
      }
    } else {
      // Pro/Admin/BYOK: use tool calling
      const apiMessages = [
        { role: 'system', content: systemPrompt },
        ...messages,
      ];

      let response = await callLLMWithRetry(modelConfig, apiMessages, AI_TOOLS);
      let responseData = await response.json();

      if (responseData.error) {
        const errMsg = responseData.error?.message || String(responseData.error);
        return new Response(`AI error: ${errMsg}`, { status: 500 });
      }

      // Normalize Anthropic Messages API response to OpenAI format
      if (modelConfig.provider === 'anthropic') {
        responseData = normalizeAnthropicResponse(responseData);
      }

      // Handle tool calls (loop up to 5 times)
      let iterations = 0;
      while (responseData.choices?.[0]?.message?.tool_calls && iterations < 5) {
        const toolCalls = responseData.choices[0].message.tool_calls;
        apiMessages.push(responseData.choices[0].message);

        for (const toolCall of toolCalls) {
          let args: Record<string, string>;
          try {
            args = JSON.parse(toolCall.function.arguments);
          } catch {
            args = {};
          }
          const result = await executeToolCall(toolCall.function.name, args);
          apiMessages.push({
            role: 'tool',
            tool_call_id: toolCall.id,
            content: result,
          });
        }

        response = await callLLMWithRetry(modelConfig, apiMessages, AI_TOOLS);
        responseData = await response.json();
        if (modelConfig.provider === 'anthropic') {
          responseData = normalizeAnthropicResponse(responseData);
        }
        iterations++;
      }

      content = responseData.choices?.[0]?.message?.content || 'I was unable to generate a response.';

      // Track usage cost for pro users
      if (modelConfig.provider === 'openrouter' && profile?.tier === 'pro') {
        const usage = responseData.usage;
        if (usage) {
          const estimatedCost = ((usage.prompt_tokens || 0) * 3 + (usage.completion_tokens || 0) * 15) / 1_000_000;
          const currentUsage = profile?.openrouter_usage_usd || 0;
          await serviceClient.from('profiles').update({
            openrouter_usage_usd: currentUsage + estimatedCost,
          }).eq('id', user.id);
        }
      }
    }

    // Stream the response
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        // Send the full response as a single chunk
        controller.enqueue(encoder.encode(content));
        controller.close();
      },
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-cache',
        'X-Model-Provider': modelInfo.provider,
        'X-Model-Source': modelInfo.source,
        'X-Model-Selected': modelInfo.model,
        'X-Model-Used': modelUsed,
        'X-Model-Label': modelInfo.modelLabel,
      },
    });
  } catch (error) {
    console.error('Chat API error:', error);
    return new Response(
      `Error: ${error instanceof Error ? error.message : 'Internal server error'}`,
      { status: 500 }
    );
  }
}

async function callLLM(
  config: { provider: string; model: string; apiKey: string; baseUrl: string },
  messages: Array<{ role: string; content?: string; tool_call_id?: string; tool_calls?: unknown[] }>,
  tools: { type: string; function: { name: string; description: string; parameters: object } }[]
): Promise<Response> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (config.provider === 'anthropic') {
    headers['x-api-key'] = config.apiKey;
    headers['anthropic-version'] = '2023-06-01';
  } else {
    headers['Authorization'] = `Bearer ${config.apiKey}`;
  }

  if (config.provider === 'openrouter') {
    headers['HTTP-Referer'] = process.env.NEXT_PUBLIC_APP_URL || 'https://securitydetections.com';
    headers['X-Title'] = 'Security Detections';
  }

  const endpoint = config.provider === 'anthropic'
    ? `${config.baseUrl}/messages`
    : `${config.baseUrl}/chat/completions`;

  // For Anthropic, transform to their Messages API format
  if (config.provider === 'anthropic') {
    const systemMsg = messages.find(m => m.role === 'system');
    const nonSystemMsgs = messages.filter(m => m.role !== 'system');

    // Convert OpenAI-style messages to Anthropic format
    const anthropicMessages = nonSystemMsgs.map(m => {
      // Convert tool_calls (assistant response with tool_use)
      if (m.role === 'assistant' && m.tool_calls) {
        const content: Array<{ type: string; text?: string; id?: string; name?: string; input?: unknown }> = [];
        if (m.content) content.push({ type: 'text', text: m.content as string });
        for (const tc of m.tool_calls as Array<{ id: string; function: { name: string; arguments: string } }>) {
          content.push({
            type: 'tool_use',
            id: tc.id,
            name: tc.function.name,
            input: JSON.parse(tc.function.arguments),
          });
        }
        return { role: 'assistant', content };
      }
      // Convert tool results
      if (m.role === 'tool') {
        return {
          role: 'user',
          content: [{ type: 'tool_result', tool_use_id: m.tool_call_id, content: m.content }],
        };
      }
      return { role: m.role, content: m.content };
    });

    const body: Record<string, unknown> = {
      model: config.model,
      max_tokens: 4096,
      system: systemMsg?.content || '',
      messages: anthropicMessages,
    };
    // Only include tools if there are any
    if (tools.length > 0) {
      body.tools = tools.map(t => ({
        name: t.function.name,
        description: t.function.description,
        input_schema: t.function.parameters,
      }));
    }

    return fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(body) });
  }

  // OpenAI / OpenRouter format
  const body: Record<string, unknown> = {
    model: config.model,
    messages,
    max_tokens: 4096,
  };
  // Only include tools if there are any (free models don't support them)
  if (tools.length > 0) {
    body.tools = tools;
  }
  return fetch(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

// Retry wrapper for 429/503 errors (exponential backoff, up to 3 attempts)
async function callLLMWithRetry(
  config: { provider: string; model: string; apiKey: string; baseUrl: string },
  messages: Array<{ role: string; content?: string; tool_call_id?: string; tool_calls?: unknown[] }>,
  tools: { type: string; function: { name: string; description: string; parameters: object } }[],
  maxRetries = 3
): Promise<Response> {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const response = await callLLM(config, messages, tools);

    if (response.status === 429 || response.status === 503) {
      if (attempt < maxRetries - 1) {
        // Exponential backoff: 1s, 2s, 4s
        const delay = Math.pow(2, attempt) * 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
    }

    return response;
  }

  // Should never reach here, but just in case
  return callLLM(config, messages, tools);
}

// Normalize Anthropic Messages API response to OpenAI chat completions format
// so the rest of the code can handle both providers uniformly
function normalizeAnthropicResponse(data: Record<string, unknown>): Record<string, unknown> {
  if (!data.content) return data; // Already OpenAI format or error

  const contentBlocks = data.content as Array<{ type: string; text?: string; id?: string; name?: string; input?: unknown }>;
  const textParts = contentBlocks.filter(b => b.type === 'text').map(b => b.text).join('');
  const toolUseBlocks = contentBlocks.filter(b => b.type === 'tool_use');

  const message: Record<string, unknown> = {
    role: 'assistant',
    content: textParts || null,
  };

  if (toolUseBlocks.length > 0) {
    message.tool_calls = toolUseBlocks.map(b => ({
      id: b.id,
      type: 'function',
      function: { name: b.name, arguments: JSON.stringify(b.input) },
    }));
  }

  return {
    choices: [{ message }],
    usage: data.usage,
  };
}

// Strip HTML tags and ATT&CK citations from descriptions
function cleanDescription(desc: string | null | undefined, maxLen = 300): string {
  if (!desc) return '';
  return desc
    .replace(/<[^>]+>/g, '')               // Strip HTML tags
    .replace(/\(Citation:[^)]+\)/g, '')     // Strip ATT&CK citations
    .replace(/\s+/g, ' ')                   // Collapse whitespace
    .trim()
    .substring(0, maxLen);
}

// Build structured data reports directly from DB — no AI hallucination possible
async function buildDataDrivenResponse(userMessage: string, userId?: string): Promise<{ dataReport: string | null }> {
  const { createClient } = await import('@supabase/supabase-js');
  const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  const msg = userMessage.toLowerCase();

  // URL/Threat report analysis: "analyze https://...", or any message with a URL
  const urlMatch = msg.match(/https?:\/\/[^\s]+/i);
  if (urlMatch) {
    const url = urlMatch[0].replace(/[)}\].,;]+$/, ''); // Clean trailing punctuation

    // SSRF protection: block private/internal IPs and domains
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const BLOCKED_HOSTS = /^(localhost|127\.\d|10\.\d|172\.(1[6-9]|2\d|3[01])\.\d|192\.168\.\d|169\.254\.\d|0\.0\.0\.0|\[::1\]|metadata\.google\.internal)/;
      if (BLOCKED_HOSTS.test(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
        return { dataReport: `## Security\n\nInternal/private URLs cannot be fetched.` };
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return { dataReport: `## Security\n\nOnly HTTP/HTTPS URLs are supported.` };
      }
    } catch {
      return { dataReport: `## Error\n\nInvalid URL: ${url}` };
    }

    try {
      const response = await fetch(url, {
        headers: { 'User-Agent': 'SecurityDetections/1.0 (Threat Report Analyzer)' },
        signal: AbortSignal.timeout(10000),
        redirect: 'follow',
      });

      // Validate response size (max 5MB)
      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > 5 * 1024 * 1024) {
        return { dataReport: `## Error\n\nDocument too large (max 5MB).` };
      }

      if (!response.ok) {
        return { dataReport: `## URL Fetch Error\n\nCould not fetch ${url} (HTTP ${response.status}). Try pasting the report text directly.` };
      }

      const html = await response.text();
      // Strip HTML to plain text
      const text = html
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&[a-z]+;/gi, ' ')
        .replace(/\s+/g, ' ')
        .trim();

      // Extract MITRE techniques
      const techniques = [...new Set(
        (text.match(/T\d{4}(?:\.\d{3})?/g) || []).map((t: string) => t.toUpperCase())
      )];

      // Extract CVEs
      const cves = [...new Set(
        text.match(/CVE-\d{4}-\d{4,}/gi) || []
      )].map(c => c.toUpperCase());

      // Extract IOCs (basic patterns)
      const ips = [...new Set(
        text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []
      )].filter(ip => !ip.startsWith('0.') && !ip.startsWith('127.') && !ip.startsWith('10.'));

      const hashes = [...new Set(
        text.match(/\b[a-f0-9]{32}\b/gi) || [] // MD5
      )].concat([...new Set(
        text.match(/\b[a-f0-9]{64}\b/gi) || [] // SHA256
      )]);

      // Extract title from the text (first meaningful sentence)
      const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
      const title = titleMatch?.[1]?.trim() || url;

      let report = `## Threat Report Analysis\n\n`;
      report += `**Source:** [${title}](${url})\n\n`;

      // Query coverage for all techniques
      const techniqueData: Record<string, {name: string; detections: number; sources: string[]}> = {};

      // MITRE Techniques found
      if (techniques.length > 0) {
        report += `### MITRE ATT&CK Techniques Found (${techniques.length})\n\n`;
        for (const tid of techniques.slice(0, 20)) {
          const { data: techIntel } = await sb.rpc('get_technique_intelligence', { p_technique_id: tid });
          if (techIntel) {
            techniqueData[tid] = {
              name: techIntel.technique_name || 'Unknown',
              detections: techIntel.total_detections || 0,
              sources: techIntel.sources_with_coverage || [],
            };
          } else {
            techniqueData[tid] = { name: 'Unknown', detections: 0, sources: [] };
          }
        }

        // Build table
        report += `| Technique | Name | Detections | Sources |\n|-----------|------|------------|--------|\n`;
        for (const [tid, data] of Object.entries(techniqueData)) {
          report += `| **${tid}** | ${data.name} | ${data.detections} | ${data.sources.join(', ') || 'None'} |\n`;
        }
        report += '\n';

        const coveredTechniques = Object.entries(techniqueData).filter(([, d]) => d.detections > 0).map(([t]) => t);
        const gapTechniques = Object.entries(techniqueData).filter(([, d]) => d.detections === 0).map(([t]) => t);

        report += `### Coverage Summary\n\n`;
        report += `- **Techniques in report:** ${techniques.length}\n`;
        report += `- **Covered by detections:** ${coveredTechniques.length}\n`;
        report += `- **Gaps (no detections):** ${gapTechniques.length}\n`;
        report += `- **Coverage:** ${techniques.length > 0 ? Math.round((coveredTechniques.length / techniques.length) * 100) : 0}%\n\n`;

        if (gapTechniques.length > 0) {
          report += `**Gap Techniques:** ${gapTechniques.join(', ')}\n\n`;
        }
      } else {
        report += `*No MITRE ATT&CK technique IDs found in the report text.*\n\n`;
      }

      // CVEs found
      if (cves.length > 0) {
        report += `### CVEs Found (${cves.length})\n\n`;
        for (const cve of cves.slice(0, 10)) {
          const { data: cveIntel } = await sb.rpc('search_detections_by_filter', { p_filter_type: 'cve', p_filter_value: cve, p_limit: 5 });
          report += `- **${cve}**: ${cveIntel?.total || 0} detections\n`;
        }
        report += '\n';
      }

      // IOCs
      if (ips.length > 0 || hashes.length > 0) {
        report += `### IOCs Extracted\n\n`;
        if (ips.length > 0) report += `**IPs:** ${ips.slice(0, 10).join(', ')}\n`;
        if (hashes.length > 0) report += `**Hashes:** ${hashes.slice(0, 10).join(', ')}\n`;
        report += '\n*Note: IOC-based detection is complementary to behavioral/TTP-based detection above.*\n';
      }

      // Auto-save to threat_reports so it appears in /reports
      if (userId) {
        try {
          const coveredTechs = Object.entries(techniqueData).filter(([, d]) => d.detections > 0);
          const gapTechs = Object.entries(techniqueData).filter(([, d]) => d.detections === 0);
          const coveragePctVal = techniques.length > 0 ? Math.round((coveredTechs.length / techniques.length) * 100) : 0;

          await sb.from('threat_reports').insert({
            user_id: userId,
            title: title,
            content: text.substring(0, 100000),
            source_url: url,
            status: 'complete',
            is_public: false,
            extracted_techniques: techniques.map((tid: string) => ({
              id: tid,
              name: techniqueData[tid]?.name || 'Unknown',
              covered: (techniqueData[tid]?.detections || 0) > 0,
              detection_count: techniqueData[tid]?.detections || 0,
              sources: techniqueData[tid]?.sources || [],
            })),
            extracted_actors: [],
            extracted_iocs: { ips, hashes, domains: [], cves },
            analysis_result: {
              summary: `Auto-analyzed from chat. ${techniques.length} techniques found, ${coveragePctVal}% coverage.`,
              total_techniques: techniques.length,
              covered_count: coveredTechs.length,
              gap_count: gapTechs.length,
              coverage_pct: coveragePctVal,
              gap_techniques: gapTechs.map(([t]) => ({ id: t, name: techniqueData[t]?.name || 'Unknown' })),
              covered_techniques: coveredTechs.map(([t, d]) => ({ id: t, name: d.name, detection_count: d.detections, sources: d.sources })),
              cve_detections: cves.map((c: string) => ({ cve: c, detection_count: 0 })),
            },
          });
        } catch (saveErr) {
          console.error('Failed to auto-save report from chat:', saveErr);
        }
      }

      report += `\n---\n*This analysis has been saved to your [Reports](/reports).*\n`;

      return { dataReport: report };
    } catch (err) {
      return { dataReport: `## URL Fetch Error\n\nCould not fetch ${url}: ${err instanceof Error ? err.message : 'Unknown error'}. Try pasting the report text directly.` };
    }
  }

  // Actor coverage query
  const actorMatch = msg.match(/(?:coverage|detect|protect).*(?:against|for|from)\s+(\w[\w\s.@-]*?)(?:\?|$|\.|\sin\s)/i)
    || msg.match(/(?:apt|actor|group)\s*[-:]?\s*(\w[\w\s.@-]*?)(?:\?|$|\.)/i);

  if (actorMatch) {
    const searchTerm = actorMatch[1].trim();
    const { data: intel } = await sb.rpc('get_actor_intelligence', { p_actor_name: searchTerm });
    if (intel?.actor_name) {
      let report = `## Coverage Against ${intel.actor_name}\n\n`;
      report += `**Aliases:** ${(intel.aliases || []).join(', ')}\n\n`;
      report += `> ${cleanDescription(intel.description)}\n\n`;
      report += `### Coverage Summary\n\n`;
      report += `| Metric | Value |\n|--------|-------|\n`;
      report += `| Total Techniques | **${intel.total_techniques}** |\n`;
      report += `| Covered | **${intel.covered}** |\n`;
      report += `| Gaps | **${intel.gaps}** |\n`;
      report += `| Coverage | **${intel.coverage_pct}%** |\n\n`;

      if (intel.tactic_breakdown?.length) {
        report += `### Tactic Breakdown\n\n`;
        report += `| Tactic | Covered/Total |\n|--------|---------------|\n`;
        for (const t of intel.tactic_breakdown) {
          const bar = t.covered === t.total ? '**FULL**' : t.covered === 0 ? '**NONE**' : `${t.covered}/${t.total}`;
          report += `| ${t.tactic} | ${bar} |\n`;
        }
        report += '\n';
      }

      if (intel.gap_techniques?.length) {
        report += `### Gap Techniques (${intel.gaps} — No Detections)\n\n`;
        for (const t of intel.gap_techniques.slice(0, 20)) {
          report += `- **${t.id}** ${t.name}\n`;
        }
        if (intel.gap_techniques.length > 20) report += `- ... and ${intel.gap_techniques.length - 20} more\n`;
        report += '\n';
      }

      if (intel.covered_techniques?.length) {
        report += `### Covered Techniques (Top ${Math.min(intel.covered_techniques.length, 15)})\n\n`;
        report += `| Technique | Name | Detections | Sources |\n|-----------|------|------------|--------|\n`;
        for (const t of intel.covered_techniques.slice(0, 15)) {
          report += `| ${t.id} | ${t.name} | ${t.detection_count} | ${(t.sources || []).join(', ')} |\n`;
        }
        report += '\n';
      }

      return { dataReport: report };
    }
  }

  // Technique query (T1xxx)
  const techMatch = msg.match(/T\d{4}(?:\.\d{3})?/gi);
  if (techMatch) {
    const parts: string[] = [];
    for (const tid of techMatch.slice(0, 3)) {
      const techniqueId = tid.toUpperCase();
      const { data: intel } = await sb.rpc('get_technique_intelligence', { p_technique_id: techniqueId });
      if (intel) {
        let report = `## ${techniqueId} — ${intel.technique_name || 'Unknown'}\n\n`;
        report += `> ${cleanDescription(intel.description, 400)}\n\n`;
        report += `**Platforms:** ${JSON.stringify(intel.platforms)}\n`;
        report += `**Total Detections:** ${intel.total_detections}\n\n`;

        if (intel.by_source?.length) {
          report += `### Detections by Source\n\n`;
          report += `| Source | Count | Example Detections |\n|--------|-------|-------------------|\n`;
          for (const s of intel.by_source) {
            const examples = s.detections?.slice(0, 3).map((d: { name: string; severity: string }) => `${d.name} (${d.severity})`).join('; ') || '';
            report += `| ${s.source} | ${s.count} | ${examples} |\n`;
          }
          report += '\n';
        }

        report += `**Sources WITH coverage:** ${intel.sources_with_coverage?.join(', ') || 'None'}\n`;
        report += `**Sources WITHOUT coverage (gaps):** ${intel.sources_without_coverage?.join(', ') || 'All sources covered'}\n\n`;

        if (intel.actors_using?.length) {
          report += `### Threat Actors Using This Technique\n\n`;
          for (const a of intel.actors_using.slice(0, 10)) {
            report += `- ${a.name}\n`;
          }
          if (intel.actors_using.length > 10) report += `- ... and ${intel.actors_using.length - 10} more\n`;
        }

        parts.push(report);
      }
    }
    if (parts.length) return { dataReport: parts.join('\n---\n\n') };
  }

  // Source name mapping (shared by all detection search patterns)
  const sourceNames: Record<string, string> = {
    sigma: 'sigma', splunk: 'splunk_escu', escu: 'splunk_escu',
    elastic: 'elastic', kql: 'kql', sublime: 'sublime',
    crowdstrike: 'crowdstrike_cql', cql: 'crowdstrike_cql',
  };
  const sourceKeys = Object.keys(sourceNames).join('|');

  // Flexible search pattern: "search for X in Splunk", "find X in sigma",
  // "search X splunk", "X detections in Splunk", "Splunk detections for X",
  // "show me Splunk rules for X", "X in splunk detections"
  const searchInSourceMatch =
    // "search (for) TOPIC in SOURCE", "find (me) TOPIC in SOURCE"
    msg.match(new RegExp(`(?:search|find)\\s+(?:for\\s+|me\\s+)?(.+?)\\s+(?:in\\s+)(${sourceKeys})(?:\\s|$|\\?)`, 'i'))
    // "search TOPIC SOURCE" (no preposition)
    || msg.match(new RegExp(`(?:search|find)\\s+(?:for\\s+|me\\s+)?(.+?)\\s+(${sourceKeys})(?:\\s|$|\\?)`, 'i'))
    // "TOPIC detections/rules in SOURCE", "TOPIC in SOURCE detections/rules"
    || msg.match(new RegExp(`^(.+?)\\s+(?:detections?|rules?|queries)\\s+(?:in|from)\\s+(${sourceKeys})`, 'i'))
    || msg.match(new RegExp(`^(.+?)\\s+(?:in|from)\\s+(${sourceKeys})\\s+(?:detections?|rules?|queries)`, 'i'))
    // "SOURCE detections/rules for TOPIC", "show me SOURCE rules for TOPIC"
    || msg.match(new RegExp(`(?:show|give|get|list)?\\s*(?:me\\s+)?(${sourceKeys})\\s+(?:detections?|rules?|queries)\\s+(?:for|on|about|covering)\\s+(.+?)(?:\\?|$)`, 'i'));

  if (searchInSourceMatch && !msg.match(/T\d{4}/i)) {
    // Determine capture group order: last pattern has source first, topic second
    const lastPatternTest = msg.match(new RegExp(`(?:show|give|get|list)?\\s*(?:me\\s+)?(${sourceKeys})\\s+(?:detections?|rules?|queries)\\s+(?:for|on|about|covering)\\s+(.+?)(?:\\?|$)`, 'i'));
    let searchTopic: string;
    let searchSourceKey: string;
    if (lastPatternTest && lastPatternTest[0] === searchInSourceMatch[0]) {
      searchSourceKey = searchInSourceMatch[1].toLowerCase();
      searchTopic = searchInSourceMatch[2].trim().replace(/[?!.,]+$/, '');
    } else {
      searchTopic = searchInSourceMatch[1].trim().replace(/[?!.,]+$/, '');
      searchSourceKey = searchInSourceMatch[2].toLowerCase();
    }
    const searchSourceType = sourceNames[searchSourceKey];

    if (searchSourceType && searchTopic) {
      const limit = 10;

      // 1) Try full-text search first
      const ftsTerms = searchTopic.replace(/[?!.,]/g, '').split(/\s+/).filter((w: string) => w.length > 2).join(' & ');
      let dets: Array<{ name: string; source_type: string; severity: string; query: string; mitre_ids: string[]; description: string }> | null = null;

      if (ftsTerms) {
        const { data } = await sb.from('detections')
          .select('name, source_type, severity, query, mitre_ids, description')
          .eq('source_type', searchSourceType)
          .textSearch('search_vector', ftsTerms)
          .order('name')
          .limit(limit);
        dets = data;
      }

      // 2) Fallback: ILIKE query on name, description, query columns
      if (!dets?.length) {
        const ilikePattern = `%${searchTopic}%`;
        const { data } = await sb.from('detections')
          .select('name, source_type, severity, query, mitre_ids, description')
          .eq('source_type', searchSourceType)
          .or(`name.ilike.${ilikePattern},description.ilike.${ilikePattern},query.ilike.${ilikePattern}`)
          .order('name')
          .limit(limit);
        dets = data;
      }

      if (dets?.length) {
        let report = `## ${searchSourceType.replace('_', ' ').toUpperCase()} Detections for "${searchTopic}" (${dets.length} shown)\n\n`;
        for (const d of dets) {
          report += `### ${d.name}\n`;
          report += `**Source:** ${d.source_type} | **Severity:** ${d.severity || 'N/A'} | **Techniques:** ${JSON.stringify(d.mitre_ids)}\n\n`;
          if (d.description) report += `${cleanDescription(d.description, 200)}\n\n`;
          if (d.query) {
            const queryPreview = d.query.substring(0, 500);
            report += '```\n' + queryPreview + (d.query.length > 500 ? '\n...' : '') + '\n```\n\n';
          }
        }
        return { dataReport: report };
      }
    }
  }

  // Detection listing query: "give me X detections/queries/rules from [source] for [topic]"
  const listMatch = msg.match(/(?:give|show|list|find|get|search)\s+(?:me\s+)?(?:for\s+)?(\d+)?\s*(?:detections?|rules?|queries|quer[yi])\s+(?:from\s+)?(\w+)?\s*(?:for|on|about|covering|in)?\s*(.*)/i);

  if (listMatch) {
    const limit = Math.min(parseInt(listMatch[1] || '10'), 25);
    const sourceKey = listMatch[2]?.toLowerCase();
    const topic = listMatch[3]?.trim() || '';
    const sourceType = sourceKey ? sourceNames[sourceKey] : null;

    let query = sb.from('detections').select('name, source_type, severity, query, mitre_ids, description');

    if (sourceType) {
      query = query.eq('source_type', sourceType);
    }

    // Try technique ID match first
    const topicTechMatch = topic.match(/T\d{4}(?:\.\d{3})?/i);
    if (topicTechMatch) {
      const techId = topicTechMatch[0].toUpperCase();
      const { data: detIds } = await sb.from('detection_techniques').select('detection_id').eq('technique_id', techId).limit(limit);
      if (detIds?.length) {
        const { data: dets } = await sb.from('detections').select('name, source_type, severity, query, mitre_ids, description')
          .in('id', detIds.map(d => d.detection_id))
          .order('name')
          .limit(limit);

        if (dets?.length) {
          let report = `## ${sourceType || 'All Sources'} Detections for ${techId} (${dets.length} shown)\n\n`;
          for (const d of dets) {
            if (sourceType && d.source_type !== sourceType) continue;
            report += `### ${d.name}\n`;
            report += `**Source:** ${d.source_type} | **Severity:** ${d.severity || 'N/A'} | **Techniques:** ${JSON.stringify(d.mitre_ids)}\n\n`;
            if (d.description) report += `${cleanDescription(d.description, 200)}\n\n`;
            if (d.query) {
              const queryPreview = d.query.substring(0, 500);
              report += '```\n' + queryPreview + (d.query.length > 500 ? '\n...' : '') + '\n```\n\n';
            }
          }
          return { dataReport: report };
        }
      }
    }

    // Text search
    if (topic) {
      const searchTerms = topic.replace(/[?!.,]/g, '').split(/\s+/).filter((w: string) => w.length > 2).join(' & ');
      if (searchTerms) {
        query = query.textSearch('search_vector', searchTerms);
      }
    }

    if (sourceType) {
      query = query.eq('source_type', sourceType);
    }

    const { data: dets } = await query.order('name').limit(limit);
    if (dets?.length) {
      let report = `## ${sourceType ? sourceType.replace('_', ' ').toUpperCase() : 'All'} Detections${topic ? ` for "${topic}"` : ''} (${dets.length} shown)\n\n`;
      for (const d of dets) {
        report += `### ${d.name}\n`;
        report += `**Source:** ${d.source_type} | **Severity:** ${d.severity || 'N/A'} | **Techniques:** ${JSON.stringify(d.mitre_ids)}\n\n`;
        if (d.description) report += `${cleanDescription(d.description, 200)}\n\n`;
        if (d.query) {
          const queryPreview = d.query.substring(0, 500);
          report += '```\n' + queryPreview + (d.query.length > 500 ? '\n...' : '') + '\n```\n\n';
        }
      }
      return { dataReport: report };
    }
  }

  // Gap analysis: "what are our gaps", "biggest gaps", "gap analysis for ransomware/apt"
  const gapMatch = msg.match(/(?:gaps?|weak|missing|uncovered|blind spot).*(?:for\s+)?(ransomware|apt|initial.?access|credential|defense.?evasion|exfiltration)?/i);
  if (gapMatch || msg.includes('gap') || msg.includes('weak')) {
    const profile = gapMatch?.[1]?.toLowerCase().replace(/[^a-z]/g, '-') || 'apt';
    const profileMap: Record<string, string> = {
      'ransomware': 'ransomware', 'apt': 'apt',
      'initial-access': 'initial-access', 'credential': 'credential-access',
      'defense-evasion': 'defense-evasion', 'exfiltration': 'exfiltration',
    };
    const profileKey = profileMap[profile] || 'apt';
    const { data: intel } = await sb.rpc('get_threat_profile_gaps', { p_profile: profileKey });
    if (intel) {
      let report = `## Gap Analysis — ${profileKey.toUpperCase()} Profile\n\n`;
      report += `| Metric | Value |\n|--------|-------|\n`;
      report += `| Relevant Techniques | **${intel.total_techniques}** |\n`;
      report += `| Covered | **${intel.covered}** |\n`;
      report += `| Gaps | **${intel.gaps}** |\n`;
      report += `| Coverage | **${intel.coverage_pct}%** |\n\n`;

      if (intel.by_tactic) {
        report += `### By Tactic\n\n`;
        report += `| Tactic | Covered | Total | Gaps |\n|--------|---------|-------|------|\n`;
        for (const t of intel.by_tactic) {
          report += `| ${t.tactic} | ${t.covered} | ${t.total} | ${t.gaps} |\n`;
        }
        report += '\n';
      }

      if (intel.top_gaps?.length) {
        report += `### Top Gap Techniques (No Detections)\n\n`;
        for (const g of intel.top_gaps) {
          report += `- **${g.technique_id}** ${g.name} *(${g.tactic})*\n`;
        }
      }
      return { dataReport: report };
    }
  }

  // Compare actors: "compare APT29 vs APT28", "compare lazarus and fin7"
  const compareMatch = msg.match(/compare\s+([\w\s.@-]+?)(?:\s+(?:vs|versus|and|with|,)\s+)([\w\s.@-]+)/i);
  if (compareMatch) {
    const actors = [compareMatch[1].trim(), compareMatch[2].trim()];
    const { data: intel } = await sb.rpc('compare_actors', { p_actor_names: actors });
    if (intel?.actors?.length) {
      let report = `## Actor Comparison\n\n`;
      report += `| Actor | Techniques | Covered | Gaps | Coverage |\n|-------|-----------|---------|------|----------|\n`;
      for (const a of intel.actors) {
        report += `| **${a.name}** | ${a.total_techniques} | ${a.covered} | ${a.gaps} | ${a.coverage_pct}% |\n`;
      }
      report += '\n';

      if (intel.shared_gaps?.length) {
        report += `### Shared Gaps (${intel.shared_gaps.length} techniques both actors use, no detections)\n\n`;
        for (const g of intel.shared_gaps.slice(0, 15)) {
          report += `- **${g.technique_id}** ${g.name}\n`;
        }
        if (intel.shared_gaps.length > 15) report += `- ... and ${intel.shared_gaps.length - 15} more\n`;
      } else {
        report += `*No shared gap techniques found.*\n`;
      }
      return { dataReport: report };
    }
  }

  // Compare sources: "compare sigma vs elastic for T1059"
  const srcCompareMatch = msg.match(/compare\s+(sigma|splunk|elastic|kql|sublime|crowdstrike).*(?:vs|and|with).*(?:for\s+)?(T\d{4}(?:\.\d{3})?)/i)
    || msg.match(/compare.*(?:sources?|coverage).*(?:for\s+)?(T\d{4}(?:\.\d{3})?)/i);
  if (srcCompareMatch) {
    const techId = (srcCompareMatch[2] || srcCompareMatch[1]).toUpperCase();
    if (techId.match(/^T\d{4}/)) {
      const { data: intel } = await sb.rpc('compare_sources_for_technique', { p_technique_id: techId });
      if (intel) {
        let report = `## Source Comparison for ${techId} — ${intel.technique_name || ''}\n\n`;
        report += `**Total Detections:** ${intel.total_detections} across ${intel.sources_with_coverage} sources\n\n`;
        report += `| Source | Count | Has Coverage | Top Detections |\n|--------|-------|-------------|----------------|\n`;
        for (const s of intel.sources || []) {
          const topDets = s.detections?.slice(0, 2).map((d: { name: string }) => d.name).join('; ') || '';
          report += `| ${s.source} | ${s.count} | ${s.has_coverage ? '**YES**' : 'NO'} | ${topDets} |\n`;
        }
        return { dataReport: report };
      }
    }
  }

  // Procedure coverage: "procedure coverage for T1059.001", "what procedures does T1003 cover"
  const procMatch = msg.match(/procedure.*(?:for|of)\s+(T\d{4}(?:\.\d{3})?)/i)
    || msg.match(/(T\d{4}(?:\.\d{3})?).*procedure/i);
  if (procMatch) {
    const techId = procMatch[1].toUpperCase();
    const { data: intel } = await sb.rpc('get_procedure_coverage', { p_technique_id: techId });
    if (intel) {
      let report = `## Procedure Coverage — ${techId} ${intel.technique_name || ''}\n\n`;
      report += `**Total Procedures:** ${intel.total_procedures} | **Total Detections:** ${intel.total_detections}\n\n`;

      if (intel.by_source?.length) {
        report += `**Detection Sources:** ${intel.by_source.map((s: { source: string; count: number }) => `${s.source} (${s.count})`).join(', ')}\n\n`;
      }

      if (intel.procedures?.length) {
        report += `### Procedures\n\n`;
        report += `| Procedure | Category | Detections | Confidence |\n|-----------|----------|------------|------------|\n`;
        for (const p of intel.procedures) {
          report += `| ${p.name} | ${p.category} | ${p.detection_count} | ${Math.round(p.confidence * 100)}% |\n`;
        }
        report += '\n';

        // Show details for top procedures
        for (const p of intel.procedures.slice(0, 5)) {
          report += `**${p.name}** *(${p.category})*\n> ${cleanDescription(p.description, 200)}\n\n`;
        }
      } else {
        report += `*No procedure references found for this technique.*\n`;
      }
      return { dataReport: report };
    }
  }

  // Filter queries: "detections for CVE-2024-1234", "detections using powershell.exe", "show critical detections"
  const cveMatch = msg.match(/(CVE-\d{4}-\d+)/i);
  if (cveMatch) {
    const { data: intel } = await sb.rpc('search_detections_by_filter', { p_filter_type: 'cve', p_filter_value: cveMatch[1], p_limit: 15 });
    if (intel) {
      let report = `## Detections for ${cveMatch[1]} (${intel.total} found)\n\n`;
      if (intel.results) {
        for (const d of intel.results) {
          report += `- **[${d.source_type}]** ${d.name} *(${d.severity})* — ${JSON.stringify(d.mitre_ids)}\n`;
          if (d.description) report += `  ${cleanDescription(d.description, 150)}\n`;
        }
      } else {
        report += `*No detections found for ${cveMatch[1]}.*\n`;
      }
      return { dataReport: report };
    }
  }

  const processMatch = msg.match(/(?:detections?|rules?)\s+(?:for|using|with|about)\s+([\w.]+\.exe)/i)
    || msg.match(/([\w.]+\.exe)/i);
  if (processMatch && msg.match(/detect|rule|cover|process/i)) {
    const { data: intel } = await sb.rpc('search_detections_by_filter', { p_filter_type: 'process_name', p_filter_value: processMatch[1], p_limit: 15 });
    if (intel?.total > 0) {
      let report = `## Detections for Process: ${processMatch[1]} (${intel.total} found)\n\n`;
      if (intel.results) {
        for (const d of intel.results) {
          report += `- **[${d.source_type}]** ${d.name} *(${d.severity})* — ${JSON.stringify(d.mitre_ids)}\n`;
        }
      }
      return { dataReport: report };
    }
  }

  // Not a data query — return null to fall through to AI
  return { dataReport: null };
}

// Pre-fetch relevant data using server-side RPC functions
// These return complete, structured intelligence — the AI never has to guess
async function prefetchContext(userMessage: string): Promise<string | null> {
  const { createClient } = await import('@supabase/supabase-js');
  const sb = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
  );

  const msg = userMessage.toLowerCase();
  const parts: string[] = [];

  // Detect actor queries
  const actorMatch = msg.match(/(?:apt|threat actor|group|coverage against|coverage for)\s*[-:]?\s*(\w[\w\s.@-]*)/i);
  if (actorMatch || msg.includes('actor') || msg.includes('apt')) {
    const searchTerm = actorMatch?.[1]?.trim() || '';
    if (searchTerm) {
      const { data: intel } = await sb.rpc('get_actor_intelligence', { p_actor_name: searchTerm });
      if (intel && intel.actor_name) {
        parts.push(`=== ACTOR INTELLIGENCE: ${intel.actor_name} ===
Aliases: ${JSON.stringify(intel.aliases)}
Description: ${intel.description}
Total techniques: ${intel.total_techniques}
Covered by detections: ${intel.covered}
Gaps (no detections): ${intel.gaps}
Coverage: ${intel.coverage_pct}%

TACTIC BREAKDOWN:
${intel.tactic_breakdown ? intel.tactic_breakdown.map((t: { tactic: string; total: number; covered: number }) => `  ${t.tactic}: ${t.covered}/${t.total} covered`).join('\n') : 'N/A'}

COVERED TECHNIQUES (with detection counts and sources):
${intel.covered_techniques ? intel.covered_techniques.slice(0, 15).map((t: { id: string; name: string; detection_count: number; sources: string[] }) => `  ${t.id} ${t.name} — ${t.detection_count} detections [${(t.sources || []).join(', ')}]`).join('\n') : 'None'}

GAP TECHNIQUES (NO detections exist):
${intel.gap_techniques ? intel.gap_techniques.map((t: { id: string; name: string }) => `  ${t.id} ${t.name}`).join('\n') : 'None'}`);
      }
    }
  }

  // Detect technique queries (T1xxx)
  const techMatch = msg.match(/T\d{4}(?:\.\d{3})?/gi);
  if (techMatch) {
    for (const tid of techMatch.slice(0, 3)) {
      const techniqueId = tid.toUpperCase();
      const { data: intel } = await sb.rpc('get_technique_intelligence', { p_technique_id: techniqueId });
      if (intel) {
        parts.push(`=== TECHNIQUE INTELLIGENCE: ${techniqueId} — ${intel.technique_name || 'Unknown'} ===
Description: ${intel.description || 'N/A'}
Platforms: ${JSON.stringify(intel.platforms)}
Total detections: ${intel.total_detections}

DETECTIONS BY SOURCE:
${intel.by_source ? intel.by_source.map((s: { source: string; count: number; detections: Array<{ name: string; severity: string }> }) =>
  `  ${s.source}: ${s.count} detections${s.detections ? '\n' + s.detections.slice(0, 5).map((d: { name: string; severity: string }) => `    - ${d.name} (${d.severity})`).join('\n') : ''}`
).join('\n') : '  No detections found'}

SOURCES WITH COVERAGE: ${intel.sources_with_coverage ? intel.sources_with_coverage.join(', ') : 'None'}
SOURCES WITHOUT COVERAGE (GAPS): ${intel.sources_without_coverage ? intel.sources_without_coverage.join(', ') : 'All sources have coverage'}

THREAT ACTORS USING THIS TECHNIQUE:
${intel.actors_using ? intel.actors_using.slice(0, 10).map((a: { name: string }) => `  - ${a.name}`).join('\n') : 'None known'}`);
      }
    }
  }

  // Detect search/keyword queries
  if (!actorMatch && !techMatch && msg.length > 3) {
    const searchTerms = msg.replace(/[?!.,]/g, '').split(/\s+/).filter(w => w.length > 2).slice(0, 4).join(' ');
    if (searchTerms) {
      const { data: intel } = await sb.rpc('search_detections_full', { p_query: searchTerms, p_limit: 15 });
      if (intel && intel.results) {
        parts.push(`=== SEARCH RESULTS: "${searchTerms}" (${intel.total_results} total) ===
${intel.results.map((d: { name: string; source_type: string; severity: string; description: string; mitre_ids: string[]; detection_type: string }) =>
  `- [${d.source_type}] ${d.name} (severity: ${d.severity}, type: ${d.detection_type})\n  Techniques: ${JSON.stringify(d.mitre_ids)}\n  ${d.description || ''}`
).join('\n')}`);
      }
    }
  }

  // Always include coverage summary
  const { data: summary } = await sb.rpc('get_coverage_summary');
  if (summary) {
    parts.push(`=== DATABASE SUMMARY ===
Total detections: ${summary.total_detections}
Total ATT&CK techniques: ${summary.total_techniques}
Techniques with detections: ${summary.covered_techniques} (${summary.coverage_pct}% coverage)
Total threat actors: ${summary.total_actors}
Detections by source: ${JSON.stringify(summary.by_source)}
Detections by tactic: ${JSON.stringify(summary.by_tactic)}
Weakest tactics: ${JSON.stringify(summary.weakest_tactics)}
Strongest tactics: ${JSON.stringify(summary.strongest_tactics)}`);
  }

  return parts.length > 0 ? parts.join('\n\n') : null;
}
