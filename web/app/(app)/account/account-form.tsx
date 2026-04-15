'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

interface AccountFormProps {
  userId: string;
  displayName: string;
  hasClaudeKey: boolean;
  hasOpenaiKey: boolean;
  hasOpenrouterKey: boolean;
  preferredModel: string;
  tier: string;
}

export function AccountForm({ displayName, hasClaudeKey, hasOpenaiKey, hasOpenrouterKey, preferredModel, tier }: AccountFormProps) {
  const router = useRouter();
  const [name, setName] = useState(displayName);
  const [claudeKey, setClaudeKey] = useState('');
  const [openaiKey, setOpenaiKey] = useState('');
  const [openrouterKey, setOpenrouterKey] = useState('');
  const [model, setModel] = useState(preferredModel);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [claudeSet, setClaudeSet] = useState(hasClaudeKey);
  const [openaiSet, setOpenaiSet] = useState(hasOpenaiKey);
  const [openrouterSet, setOpenrouterSet] = useState(hasOpenrouterKey);
  const isProOrAdmin = tier === 'pro' || tier === 'admin';
  const isFreeNoByok = !isProOrAdmin && !claudeSet && !openaiSet && !openrouterSet;

  let autoOptionLabel = 'Auto (Default routing)';
  if (claudeSet) {
    autoOptionLabel = 'Auto (ignored while Claude BYOK key is set)';
  } else if (openaiSet) {
    autoOptionLabel = 'Auto (ignored while OpenAI BYOK key is set)';
  } else if (openrouterSet) {
    autoOptionLabel = 'Auto (Claude Sonnet 4.6)';
  } else if (isProOrAdmin) {
    autoOptionLabel = 'Auto (Free model pool default)';
  } else if (isFreeNoByok) {
    autoOptionLabel = 'Auto (Nemotron 3 Super 120B - Free default)';
  }

  async function handleSave() {
    setSaving(true);
    setMessage(null);

    // Client-side validation
    if (claudeKey && !claudeKey.startsWith('sk-ant-')) {
      setMessage('Error: Claude API key must start with sk-ant-');
      setSaving(false);
      return;
    }
    if (openaiKey && !openaiKey.startsWith('sk-')) {
      setMessage('Error: OpenAI API key must start with sk-');
      setSaving(false);
      return;
    }
    if (openrouterKey && !openrouterKey.startsWith('sk-or-')) {
      setMessage('Error: OpenRouter API key must start with sk-or-');
      setSaving(false);
      return;
    }

    const body: Record<string, string | null> = {
      display_name: name || null,
      preferred_model: model,
    };

    // Only send keys if user entered new ones (encrypted server-side)
    if (claudeKey) body.claude_key = claudeKey;
    if (openaiKey) body.openai_key = openaiKey;
    if (openrouterKey) body.openrouter_key = openrouterKey;

    const res = await fetch('/api/account', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const data = await res.json();

    if (!res.ok) {
      setMessage(`Error: ${data.error}`);
    } else {
      setMessage('Settings saved!');
      if (claudeKey) setClaudeSet(true);
      if (openaiKey) setOpenaiSet(true);
      if (openrouterKey) setOpenrouterSet(true);
      setClaudeKey('');
      setOpenaiKey('');
      setOpenrouterKey('');
      router.refresh();
    }
    setSaving(false);
  }

  async function clearKey(keyField: string) {
    const keyMap: Record<string, string> = {
      claude_api_key_encrypted: 'claude_key',
      openai_api_key_encrypted: 'openai_key',
      openrouter_api_key_encrypted: 'openrouter_key',
    };
    const apiField = keyMap[keyField];
    if (!apiField) return;

    const res = await fetch('/api/account', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [apiField]: null }),
    });

    if (res.ok) {
      setMessage('Key removed.');
      if (keyField.includes('claude')) setClaudeSet(false);
      if (keyField.includes('openai')) setOpenaiSet(false);
      if (keyField.includes('openrouter')) setOpenrouterSet(false);
      router.refresh();
    }
  }

  return (
    <div className="space-y-4">
      {/* Display Name */}
      <div>
        <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
          Display Name
        </label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Enter your display name"
          maxLength={100}
          className="w-full bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text placeholder:text-text-dim/50 outline-none font-[family-name:var(--font-mono)] text-sm"
        />
      </div>

      {/* Preferred Model */}
      <div>
        <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
          Preferred Model
        </label>
        <select
          value={model}
          onChange={(e) => setModel(e.target.value)}
          className="w-full bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text outline-none font-[family-name:var(--font-mono)] text-sm"
        >
          <option value="auto">{autoOptionLabel}</option>
          <option value="claude">Claude Sonnet 4.6</option>
          <option value="claude-opus">Claude Opus 4.6</option>
          <option value="gpt">GPT-5.4</option>
          <option value="gpt-codex">GPT-5.3 Codex</option>
        </select>
        {isFreeNoByok && (
          <p className="text-text-dim text-xs mt-2">
            Free tier currently uses the free model pool with default <code className="text-amber">nvidia/nemotron-3-super-120b-a12b:free</code>.
          </p>
        )}
        {!openrouterSet && isProOrAdmin && (
          <p className="text-text-dim text-xs mt-2">
            On {tier.toUpperCase()}, <code className="text-amber">auto</code> uses the free model pool. Pick Claude/GPT explicitly to force frontier models.
          </p>
        )}
      </div>

      {/* Claude API Key */}
      <div>
        <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
          Claude API Key
          {claudeSet && <span className="text-green ml-2">&#10003; Set</span>}
        </label>
        <div className="flex gap-2">
          <input
            type="password"
            value={claudeKey}
            onChange={(e) => setClaudeKey(e.target.value)}
            placeholder={claudeSet ? '••••••••' : 'sk-ant-...'}
            className="flex-1 bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text placeholder:text-text-dim/50 outline-none font-[family-name:var(--font-mono)] text-sm"
          />
          {claudeSet && (
            <button
              onClick={() => clearKey('claude_api_key_encrypted')}
              className="text-red hover:text-red-dim text-sm px-3 transition-colors"
            >
              Remove
            </button>
          )}
        </div>
      </div>

      {/* OpenAI API Key */}
      <div>
        <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
          OpenAI API Key
          {openaiSet && <span className="text-green ml-2">&#10003; Set</span>}
        </label>
        <div className="flex gap-2">
          <input
            type="password"
            value={openaiKey}
            onChange={(e) => setOpenaiKey(e.target.value)}
            placeholder={openaiSet ? '••••••••' : 'sk-...'}
            className="flex-1 bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text placeholder:text-text-dim/50 outline-none font-[family-name:var(--font-mono)] text-sm"
          />
          {openaiSet && (
            <button
              onClick={() => clearKey('openai_api_key_encrypted')}
              className="text-red hover:text-red-dim text-sm px-3 transition-colors"
            >
              Remove
            </button>
          )}
        </div>
      </div>

      {/* OpenRouter API Key */}
      <div>
        <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
          OpenRouter API Key
          {openrouterSet && <span className="text-green ml-2">&#10003; Set</span>}
        </label>
        <div className="flex gap-2">
          <input
            type="password"
            value={openrouterKey}
            onChange={(e) => setOpenrouterKey(e.target.value)}
            placeholder={openrouterSet ? '••••••••' : 'sk-or-v1-...'}
            className="flex-1 bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text placeholder:text-text-dim/50 outline-none font-[family-name:var(--font-mono)] text-sm"
          />
          {openrouterSet && (
            <button
              onClick={() => clearKey('openrouter_api_key_encrypted')}
              className="text-red hover:text-red-dim text-sm px-3 transition-colors"
            >
              Remove
            </button>
          )}
        </div>
      </div>

      {/* Save */}
      <div className="flex items-center gap-4 pt-2">
        <button
          onClick={handleSave}
          disabled={saving}
          className="bg-amber hover:bg-amber-dim disabled:opacity-50 text-bg font-bold px-6 py-2 rounded-[var(--radius-button)] transition-colors"
        >
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
        {message && (
          <span className={`text-sm ${message.startsWith('Error') ? 'text-red' : 'text-green'}`}>
            {message}
          </span>
        )}
      </div>
    </div>
  );
}
