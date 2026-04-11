export interface ModelConfig {
  provider: 'openrouter' | 'anthropic' | 'openai';
  model: string;
  apiKey: string;
  baseUrl: string;
}

interface UserProfile {
  tier: string;
  preferred_model: string;
  openrouter_api_key_encrypted: string | null;
  claude_api_key_encrypted: string | null;
  openai_api_key_encrypted: string | null;
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

export function getModelConfig(profile: UserProfile | null): ModelConfig {
  // Lazy import decrypt to avoid crypto module in client bundles
  const { decrypt } = require('@/lib/crypto') as { decrypt: (s: string) => string };

  // BYOK: User has their own Claude API key
  if (profile?.claude_api_key_encrypted) {
    return {
      provider: 'anthropic',
      model: 'claude-sonnet-4-6-20250514',
      apiKey: decrypt(profile.claude_api_key_encrypted),
      baseUrl: 'https://api.anthropic.com/v1',
    };
  }

  // BYOK: User has their own OpenAI API key
  if (profile?.openai_api_key_encrypted) {
    return {
      provider: 'openai',
      model: 'gpt-5.4',
      apiKey: decrypt(profile.openai_api_key_encrypted),
      baseUrl: 'https://api.openai.com/v1',
    };
  }

  // BYOK: User has their own OpenRouter API key
  if (profile?.openrouter_api_key_encrypted) {
    const model = PRO_MODELS[profile.preferred_model] || PRO_MODELS['auto'];
    return {
      provider: 'openrouter',
      model,
      apiKey: decrypt(profile.openrouter_api_key_encrypted),
      baseUrl: 'https://openrouter.ai/api/v1',
    };
  }

  // Pro/Admin tier: use app's OpenRouter key with frontier models
  if (profile?.tier === 'pro' || profile?.tier === 'admin') {
    const model = PRO_MODELS[profile.preferred_model] || PRO_MODELS['auto'];
    return {
      provider: 'openrouter',
      model,
      apiKey: process.env.OPENROUTER_API_KEY!,
      baseUrl: 'https://openrouter.ai/api/v1',
    };
  }

  // Free tier: OpenRouter free smart router
  return {
    provider: 'openrouter',
    model: FREE_MODEL,
    apiKey: process.env.OPENROUTER_API_KEY!,
    baseUrl: 'https://openrouter.ai/api/v1',
  };
}

export function getRateLimit(tier: string): number {
  if (tier === 'pro' || tier === 'admin') return 500;
  return 20;
}
