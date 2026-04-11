'use client';

import { useState, useRef, useEffect } from 'react';
import { createClient } from '@/lib/supabase/client';
import { Markdown } from '@/components/chat/markdown';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
}

interface Conversation {
  id: string;
  title: string | null;
  updated_at: string;
}

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const supabase = createClient();

  // Load recent conversations on mount
  useEffect(() => {
    loadConversations();
  }, []);

  // Check for conversation ID in URL params
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const convId = params.get('c');
    if (convId) {
      loadConversation(convId);
    }
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  async function loadConversations() {
    const { data } = await supabase
      .from('conversations')
      .select('id, title, updated_at')
      .order('updated_at', { ascending: false })
      .limit(10);
    if (data) setConversations(data);
  }

  async function loadConversation(id: string) {
    setConversationId(id);
    const { data } = await supabase
      .from('messages')
      .select('id, role, content')
      .eq('conversation_id', id)
      .order('created_at', { ascending: true });
    if (data) {
      setMessages(data.map(m => ({
        id: m.id,
        role: m.role as 'user' | 'assistant',
        content: m.content,
      })));
    }
  }

  async function startNewChat() {
    setMessages([]);
    setConversationId(null);
    setInput('');
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userContent = input.trim();
    const userMessage: Message = {
      id: crypto.randomUUID(),
      role: 'user',
      content: userContent,
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      // Create conversation if this is the first message
      let convId = conversationId;
      if (!convId) {
        const { data: { user } } = await supabase.auth.getUser();
        if (!user) throw new Error('Not authenticated');

        const title = userContent.substring(0, 100);
        const { data: conv } = await supabase
          .from('conversations')
          .insert({ user_id: user.id, title, message_count: 0 })
          .select()
          .single();
        if (conv) {
          convId = conv.id;
          setConversationId(conv.id);
        }
      }

      // Save user message to DB
      if (convId) {
        await supabase.from('messages').insert({
          conversation_id: convId,
          role: 'user',
          content: userContent,
        });
      }

      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: [...messages, userMessage].map(m => ({
            role: m.role,
            content: m.content,
          })),
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        if (response.status === 429) {
          throw new Error('Rate limit exceeded — free tier is busy right now.');
        }
        throw new Error(errorText);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let assistantContent = '';
      const assistantId = crypto.randomUUID();

      setMessages(prev => [...prev, { id: assistantId, role: 'assistant', content: '' }]);

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value);
          assistantContent += chunk;
          setMessages(prev =>
            prev.map(m =>
              m.id === assistantId ? { ...m, content: assistantContent } : m
            )
          );
        }
      }

      // Save assistant message to DB
      if (convId) {
        await supabase.from('messages').insert({
          conversation_id: convId,
          role: 'assistant',
          content: assistantContent,
        });
        // Update conversation
        await supabase.from('conversations').update({
          message_count: messages.length + 2,
          updated_at: new Date().toISOString(),
        }).eq('id', convId);
      }

      // Refresh conversation list
      loadConversations();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Something went wrong';
      const isRateLimit = errorMessage.includes('Rate limit') || errorMessage.includes('429') || errorMessage.includes('busy');
      setMessages(prev => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: 'assistant',
          content: isRateLimit
            ? 'The free tier is currently rate limited. To get faster, unlimited access with frontier AI models, upgrade to Pro via GitHub Sponsors: https://github.com/sponsors/MHaggis\n\nOr bring your own API key in Account Settings for instant access.'
            : `Error: ${errorMessage}`,
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] max-w-6xl mx-auto gap-4">
      {/* Chat history sidebar */}
      <div className="w-56 shrink-0 hidden md:flex flex-col border-r border-border pr-4">
        <button
          onClick={startNewChat}
          className="w-full bg-amber hover:bg-amber-dim text-bg font-bold py-2 rounded-[var(--radius-button)] text-sm transition-colors mb-4"
        >
          + New Chat
        </button>
        <div className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
          Recent Chats
        </div>
        <div className="flex-1 overflow-y-auto space-y-1">
          {conversations.map(conv => (
            <button
              key={conv.id}
              onClick={() => loadConversation(conv.id)}
              className={`w-full text-left px-3 py-2 rounded-[var(--radius-card)] text-xs transition-colors truncate ${
                conversationId === conv.id
                  ? 'bg-amber/10 text-amber border border-amber/30'
                  : 'text-text-dim hover:text-text hover:bg-card2'
              }`}
            >
              {conv.title || 'Untitled'}
            </button>
          ))}
          {conversations.length === 0 && (
            <p className="text-text-dim/50 text-xs px-3">No conversations yet</p>
          )}
        </div>
      </div>

      {/* Main chat area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto space-y-4 pb-4">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-center overflow-y-auto py-8">
              <div className="text-5xl mb-3">&#129302;</div>
              <h2 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-2">
                DETECTION INTELLIGENCE AI
              </h2>
              <p className="text-text-dim max-w-md mb-6 text-sm">
                Ask about detection coverage, threat actors, MITRE ATT&CK techniques, or analyze threat reports.
              </p>

              {/* Capabilities */}
              <div className="w-full max-w-2xl mb-6 text-left">
                <h3 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2 text-center">
                  What You Can Ask
                </h3>
                <div className="bg-card border border-border rounded-[var(--radius-card)] overflow-hidden">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left text-amber font-[family-name:var(--font-mono)] px-3 py-2">Query Type</th>
                        <th className="text-left text-text-dim font-[family-name:var(--font-mono)] px-3 py-2">Example</th>
                        <th className="text-center text-text-dim font-[family-name:var(--font-mono)] px-3 py-2">Source</th>
                      </tr>
                    </thead>
                    <tbody className="text-text-dim">
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">Actor coverage</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Coverage against APT29&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span></td></tr>
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">Technique detail</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Show me T1059.001&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span></td></tr>
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">List detections</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Give me 5 sigma rules for powershell&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span></td></tr>
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">Gap analysis</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;What are our biggest gaps?&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span></td></tr>
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">Threat profiles</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Gap analysis for ransomware&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span></td></tr>
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">Compare actors</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Compare APT29 vs APT28&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span></td></tr>
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">Compare sources</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Compare sources for T1059.001&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span></td></tr>
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">Procedure coverage</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Procedure coverage for T1003.001&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span></td></tr>
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">CVE lookup</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Detections for CVE-2024-1234&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span></td></tr>
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">Process name</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Detections for powershell.exe&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span></td></tr>
                      <tr className="border-b border-border/50"><td className="px-3 py-1.5 text-text">Threat report</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Analyze https://blog.example.com/apt-report&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-green">DB</span> + <span className="text-blue">AI</span></td></tr>
                      <tr><td className="px-3 py-1.5 text-text">General questions</td><td className="px-3 py-1.5 font-[family-name:var(--font-mono)]">&quot;Search for credential access&quot;</td><td className="px-3 py-1.5 text-center"><span className="text-blue">AI</span></td></tr>
                    </tbody>
                  </table>
                </div>
                <div className="flex justify-center gap-4 mt-2 text-xs text-text-dim">
                  <span><span className="text-green">DB</span> = Direct database query (always accurate)</span>
                  <span><span className="text-blue">AI</span> = AI-assisted (uses free model)</span>
                </div>
              </div>

              {/* Quick suggestions */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-w-lg mb-6">
                {[
                  "What's our coverage against APT29?",
                  "Show me detections for T1059.001",
                  "Gap analysis for ransomware",
                  "Compare APT29 vs APT28",
                ].map((q) => (
                  <button
                    key={q}
                    onClick={() => setInput(q)}
                    className="bg-card hover:bg-card2 border border-border hover:border-border-bright rounded-[var(--radius-card)] p-3 text-left text-sm text-text-dim hover:text-text transition-all"
                  >
                    {q}
                  </button>
                ))}
              </div>

              {/* Upgrade CTA */}
              <div className="bg-card border border-amber/20 rounded-[var(--radius-card)] px-6 py-4 max-w-lg">
                <p className="text-text-dim text-xs text-center">
                  <span className="text-green">DB</span> queries return exact data from our detection database.{' '}
                  <span className="text-blue">AI</span> queries use free open-source models which may be less accurate.{' '}
                  For frontier AI models (Claude, GPT-5.4, Opus), <a href="https://github.com/sponsors/MHaggis" target="_blank" rel="noopener noreferrer" className="text-amber hover:text-amber-dim">upgrade to Pro</a>{' '}
                  or <a href="/account" className="text-amber hover:text-amber-dim">bring your own API key</a>.
                </p>
              </div>
            </div>
          )}

          {messages.map((m) => (
            <div
              key={m.id}
              className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[80%] rounded-[var(--radius-card)] px-4 py-3 ${
                  m.role === 'user'
                    ? 'bg-amber/20 border border-amber/30 text-text-bright'
                    : 'bg-card border border-border text-text'
                }`}
              >
                {m.role === 'assistant' ? (
                  <Markdown content={m.content} />
                ) : (
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{m.content}</p>
                )}
              </div>
            </div>
          ))}

          {isLoading && (
            <div className="flex justify-start">
              <div className="bg-card border border-border rounded-[var(--radius-card)] px-4 py-3">
                <div className="flex gap-1">
                  <span className="w-2 h-2 bg-amber rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                  <span className="w-2 h-2 bg-amber rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                  <span className="w-2 h-2 bg-amber rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                </div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <form onSubmit={handleSubmit} className="border-t border-border pt-4">
          <div className="flex gap-3">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about detection coverage..."
              className="flex-1 bg-card border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-3 text-text placeholder:text-text-dim/50 outline-none transition-colors text-sm"
              disabled={isLoading}
            />
            <button
              type="submit"
              disabled={isLoading || !input.trim()}
              className="bg-amber hover:bg-amber-dim disabled:opacity-50 text-bg font-bold px-6 py-3 rounded-[var(--radius-button)] transition-colors shrink-0"
            >
              Send
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
