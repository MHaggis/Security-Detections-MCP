/**
 * Sampling Handler - Utilities for MCP Sampling
 * 
 * Sampling allows the server to request LLM completions from the client.
 * This is useful for autonomous analysis where the server needs
 * the LLM to reason about data.
 * 
 * Note: The client (Cursor) must support sampling capability for this to work.
 * If not supported, functions will return null and callers should fall back
 * to direct analysis.
 */

import { getServerInstance } from '../server.js';

// Configuration
const DEFAULT_MAX_TOKENS = 2000;

export interface SamplingMessage {
  role: 'user' | 'assistant';
  content: { type: 'text'; text: string };
}

export interface SamplingRequest {
  messages: SamplingMessage[];
  systemPrompt?: string;
  maxTokens?: number;
  temperature?: number;
  includeContext?: string;
}

export interface SamplingResponse {
  content: { type: 'text'; text: string };
  model?: string;
  stopReason?: string;
}

// Type for server with sampling capability
interface ServerWithSampling {
  createMessage: (params: {
    messages: Array<{ role: string; content: { type: string; text: string } }>;
    systemPrompt?: string;
    maxTokens?: number;
    temperature?: number;
    includeContext?: string;
  }) => Promise<{
    content?: { type?: string; text?: string };
    model?: string;
    stopReason?: string;
  }>;
}

/**
 * Check if the server has createMessage method
 */
function hasCreateMessage(server: unknown): server is ServerWithSampling {
  return (
    server !== null &&
    typeof server === 'object' &&
    'createMessage' in server &&
    typeof (server as ServerWithSampling).createMessage === 'function'
  );
}

/**
 * Check if the client supports sampling
 */
export function isSamplingSupported(): boolean {
  const server = getServerInstance();
  return hasCreateMessage(server);
}

/**
 * Request an LLM completion from the client via MCP sampling
 * 
 * @param request - The sampling request parameters
 * @returns The LLM response, or null if sampling is not supported
 */
export async function requestSampling(request: SamplingRequest): Promise<SamplingResponse | null> {
  const server = getServerInstance();
  
  if (!server) {
    console.error('[sampling] No server instance available');
    return null;
  }

  if (!hasCreateMessage(server)) {
    console.error('[sampling] Server does not support createMessage');
    return null;
  }

  try {
    const response = await server.createMessage({
      messages: request.messages.map(m => ({
        role: m.role,
        content: { type: 'text', text: m.content.text },
      })),
      systemPrompt: request.systemPrompt,
      maxTokens: request.maxTokens ?? DEFAULT_MAX_TOKENS,
      temperature: request.temperature,
      includeContext: request.includeContext,
    });

    // Safely extract response content with null checks
    const responseText = response?.content?.text;
    if (typeof responseText !== 'string') {
      console.error('[sampling] Invalid response format - missing content.text');
      return null;
    }

    return {
      content: { type: 'text', text: responseText },
      model: response.model,
      stopReason: response.stopReason,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    // Check for specific "not supported" errors
    const notSupportedPatterns = [
      'does not support sampling',
      'not supported',
      'capability',
      'not implemented',
    ];
    
    const isNotSupported = notSupportedPatterns.some(p => 
      errorMessage.toLowerCase().includes(p.toLowerCase())
    );
    
    if (isNotSupported) {
      console.error('[sampling] Client does not support sampling capability');
    } else {
      console.error('[sampling] Sampling request failed:', errorMessage);
    }
    
    return null;
  }
}

/**
 * Request LLM analysis of security data
 * 
 * This is a convenience wrapper for common security analysis patterns.
 * Falls back to returning null if sampling isn't supported.
 */
export async function requestAnalysis(
  analysisType: 'coverage' | 'gaps' | 'comparison' | 'recommendation',
  data: Record<string, unknown>,
  context?: string
): Promise<{ analysis: string; reasoning: string } | null> {
  const prompts: Record<string, string> = {
    coverage: `Analyze this security detection coverage data and provide insights:
- What tactics/techniques have strong coverage?
- Where are the gaps?
- What are the priorities for improvement?

Data: ${JSON.stringify(data, null, 2)}

${context ? `Context: ${context}` : ''}

Provide your analysis in a structured format with clear recommendations.`,

    gaps: `Analyze these detection gaps and prioritize them:
- Which gaps are most critical?
- What threats do they leave you vulnerable to?
- What's the recommended order of remediation?

Gaps: ${JSON.stringify(data, null, 2)}

${context ? `Context: ${context}` : ''}

Provide prioritized recommendations with reasoning.`,

    comparison: `Compare these detection sources and provide insights:
- Which source has better coverage overall?
- Where does each source excel or fall short?
- What's the recommended multi-source strategy?

Comparison Data: ${JSON.stringify(data, null, 2)}

${context ? `Context: ${context}` : ''}

Provide a balanced comparison with actionable recommendations.`,

    recommendation: `Based on this security data, provide detection recommendations:
- What detections should be created first?
- What data sources are needed?
- What are the implementation considerations?

Data: ${JSON.stringify(data, null, 2)}

${context ? `Context: ${context}` : ''}

Provide specific, actionable detection recommendations.`,
  };

  const response = await requestSampling({
    messages: [
      {
        role: 'user',
        content: { type: 'text', text: prompts[analysisType] },
      },
    ],
    systemPrompt: 'You are an expert security detection engineer analyzing detection coverage. Be specific, technical, and actionable.',
    maxTokens: 2000,
  });

  if (!response) return null;

  return {
    analysis: response.content.text,
    reasoning: `Analysis generated via MCP sampling (model: ${response.model || 'unknown'})`,
  };
}

/**
 * Check sampling availability and return status info
 */
export function getSamplingStatus(): {
  available: boolean;
  reason: string;
  recommendation: string;
} {
  const server = getServerInstance();
  
  if (!server) {
    return {
      available: false,
      reason: 'No server instance available',
      recommendation: 'Server must be initialized before checking sampling',
    };
  }

  const hasCreateMessage = typeof (server as unknown as { createMessage?: unknown }).createMessage === 'function';
  
  if (!hasCreateMessage) {
    return {
      available: false,
      reason: 'Server SDK does not expose createMessage method',
      recommendation: 'Ensure MCP SDK version 1.25.3+ is installed',
    };
  }

  // Note: We can't actually check if client supports sampling until we try
  return {
    available: true,
    reason: 'Sampling method available (client support unknown until first request)',
    recommendation: 'First sampling request will determine client support',
  };
}
