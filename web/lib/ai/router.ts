export interface ModelConfig {
  provider: 'openrouter' | 'anthropic' | 'openai';
  model: string;
  apiKey: string;
  baseUrl: string;
}

export type ModelSource =
  | 'byok-claude'
  | 'byok-openai'
  | 'byok-openrouter'
  | 'pro'
  | 'admin'
  | 'free';

export interface UserProfile {
  tier: string;
  preferred_model: string;
  openrouter_api_key_encrypted: string | null;
  claude_api_key_encrypted: string | null;
  openai_api_key_encrypted: string | null;
}

export interface ModelRoutingInfo {
  source: ModelSource;
  provider: 'openrouter' | 'anthropic' | 'openai';
  model: string;
  modelLabel: string;
  note?: string;
  fallbackModels?: string[];
}

// Free tier models — ordered by quality for instruction following + context fidelity
export const FREE_MODELS = [
  'nvidia/nemotron-3-super-120b-a12b:free',    // 120B MoE, 12B active, 262K ctx, tool calling
  'nousresearch/hermes-3-llama-3.1-405b:free',  // 405B dense, 131K ctx, best instruction following
  'meta-llama/llama-3.3-70b-instruct:free',     // 70B dense, 66K ctx, proven reliable
  'openai/gpt-oss-120b:free',                   // 117B, 131K ctx, tool calling
];
const FREE_MODEL = FREE_MODELS[0];

// Pro/Admin tier models (via OpenRouter paid routes)
const PRO_MODELS: Record<string, string> = {
  'auto': 'anthropic/claude-sonnet-4-6',
  'claude': 'anthropic/claude-sonnet-4-6',
  'claude-opus': 'anthropic/claude-opus-4-6',
  'gpt': 'openai/gpt-5.4',
  'gpt-codex': 'openai/gpt-5.3-codex',
};

// Import decrypt — this module is only used server-side (chat API route)
import { decrypt } from '@/lib/crypto';

const MODEL_LABELS: Record<string, string> = {
  'claude-sonnet-4-6-20250514': 'Claude Sonnet 4.6',
  'anthropic/claude-sonnet-4-6': 'Claude Sonnet 4.6',
  'anthropic/claude-opus-4-6': 'Claude Opus 4.6',
  'gpt-5.4': 'GPT-5.4',
  'openai/gpt-5.4': 'GPT-5.4',
  'openai/gpt-5.3-codex': 'GPT-5.3 Codex',
  'nvidia/nemotron-3-super-120b-a12b:free': 'Nemotron 3 Super 120B (Free)',
  'nousresearch/hermes-3-llama-3.1-405b:free': 'Hermes 3 Llama 405B (Free)',
  'meta-llama/llama-3.3-70b-instruct:free': 'Llama 3.3 70B Instruct (Free)',
  'openai/gpt-oss-120b:free': 'GPT-OSS 120B (Free)',
};

function getModelLabel(model: string): string {
  return MODEL_LABELS[model] || model;
}

export function getModelRoutingInfo(profile: UserProfile | null): ModelRoutingInfo {
  if (profile?.claude_api_key_encrypted) {
    return {
      source: 'byok-claude',
      provider: 'anthropic',
      model: 'claude-sonnet-4-6-20250514',
      modelLabel: getModelLabel('claude-sonnet-4-6-20250514'),
      note: 'Using your Claude API key',
    };
  }

  if (profile?.openai_api_key_encrypted) {
    return {
      source: 'byok-openai',
      provider: 'openai',
      model: 'gpt-5.4',
      modelLabel: getModelLabel('gpt-5.4'),
      note: 'Using your OpenAI API key',
    };
  }

  if (profile?.openrouter_api_key_encrypted) {
    const model = PRO_MODELS[profile.preferred_model] || PRO_MODELS['auto'];
    return {
      source: 'byok-openrouter',
      provider: 'openrouter',
      model,
      modelLabel: getModelLabel(model),
      note: 'Using your OpenRouter API key',
    };
  }

  if (profile?.tier === 'pro' || profile?.tier === 'admin') {
    if (profile.preferred_model === 'auto') {
      return {
        source: profile.tier === 'admin' ? 'admin' : 'pro',
        provider: 'openrouter',
        model: FREE_MODEL,
        modelLabel: getModelLabel(FREE_MODEL),
        note: 'Auto uses the free model pool by default. Pick Claude/GPT explicitly to use frontier models.',
        fallbackModels: FREE_MODELS,
      };
    }
    const model = PRO_MODELS[profile.preferred_model] || PRO_MODELS['auto'];
    return {
      source: profile.tier === 'admin' ? 'admin' : 'pro',
      provider: 'openrouter',
      model,
      modelLabel: getModelLabel(model),
      note: 'Using app-managed frontier model routing',
    };
  }

  return {
    source: 'free',
    provider: 'openrouter',
    model: FREE_MODEL,
    modelLabel: getModelLabel(FREE_MODEL),
    note: 'Free tier uses automatic fallback across free models',
    fallbackModels: FREE_MODELS,
  };
}

export function getModelConfig(profile: UserProfile | null): ModelConfig {
  const routing = getModelRoutingInfo(profile);

  if (routing.source === 'byok-claude') {
    return {
      provider: 'anthropic',
      model: routing.model,
      apiKey: decrypt(profile!.claude_api_key_encrypted!),
      baseUrl: 'https://api.anthropic.com/v1',
    };
  }

  if (routing.source === 'byok-openai') {
    return {
      provider: 'openai',
      model: routing.model,
      apiKey: decrypt(profile!.openai_api_key_encrypted!),
      baseUrl: 'https://api.openai.com/v1',
    };
  }

  if (routing.source === 'byok-openrouter') {
    return {
      provider: 'openrouter',
      model: routing.model,
      apiKey: decrypt(profile!.openrouter_api_key_encrypted!),
      baseUrl: 'https://openrouter.ai/api/v1',
    };
  }

  return {
    provider: 'openrouter',
    model: routing.model,
    apiKey: process.env.OPENROUTER_API_KEY!,
    baseUrl: 'https://openrouter.ai/api/v1',
  };
}

export function getRateLimit(tier: string): number {
  if (tier === 'pro' || tier === 'admin') return 500;
  return 20;
}
