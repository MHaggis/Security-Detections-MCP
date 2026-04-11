import { createClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';

export default async function BillingPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) redirect('/login');

  const { data: profile } = await supabase
    .from('profiles')
    .select('tier')
    .eq('id', user.id)
    .single();

  return (
    <div className="max-w-2xl mx-auto animate-slide-up">
      <Link href="/account" className="text-text-dim hover:text-text text-sm mb-4 inline-block transition-colors">
        &larr; Back to Account
      </Link>

      <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider mb-8">
        UPGRADE TO PRO
      </h1>

      {profile?.tier === 'pro' ? (
        <div className="bg-card border border-green/30 rounded-[var(--radius-card)] p-8 text-center">
          <div className="w-14 h-14 rounded-full bg-green/10 border border-green/30 flex items-center justify-center mx-auto mb-4">
            <span className="text-green text-2xl">&#10003;</span>
          </div>
          <h2 className="font-[family-name:var(--font-display)] text-2xl text-green tracking-wider mb-2">
            PRO ACTIVE
          </h2>
          <p className="text-text-dim text-sm mb-4">
            You have full access to frontier AI models and all Pro features. Thank you for your support!
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* What you get */}
          <div className="bg-card border border-amber/30 rounded-[var(--radius-card)] p-8 glow-amber">
            <h2 className="font-[family-name:var(--font-display)] text-2xl text-amber tracking-wider mb-4">
              PRO FEATURES
            </h2>
            <ul className="space-y-3 text-sm text-text-dim mb-8">
              <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> Unlimited AI chats with frontier models</li>
              <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> Claude Sonnet 4.5, GPT-4.1, Codex, Opus</li>
              <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> Threat report analysis</li>
              <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> Save &amp; export coverage snapshots</li>
              <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> ATT&CK Navigator layer export</li>
              <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> Priority support</li>
            </ul>

            <div className="text-center">
              <div className="flex items-baseline justify-center gap-2 mb-6">
                <span className="font-[family-name:var(--font-display)] text-5xl text-text-bright">$25</span>
                <span className="text-text-dim text-sm">/month</span>
                <span className="text-text-dim text-sm mx-2">or</span>
                <span className="font-[family-name:var(--font-display)] text-5xl text-text-bright">$250</span>
                <span className="text-text-dim text-sm">/year</span>
              </div>

              <a
                href="https://github.com/sponsors/MHaggis"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-block bg-amber hover:bg-amber-dim text-bg font-bold px-8 py-3 rounded-[var(--radius-button)] text-lg transition-colors"
              >
                Sponsor on GitHub
              </a>
              <p className="text-text-dim text-xs mt-4">
                After sponsoring, your account will be upgraded to Pro within 24 hours.
              </p>
            </div>
          </div>

          {/* BYOK alternative */}
          <div className="bg-card border border-border rounded-[var(--radius-card)] p-6 text-center">
            <p className="text-text-dim text-sm">
              Or bring your own API key (Claude, OpenAI, OpenRouter) in{' '}
              <Link href="/account" className="text-amber hover:text-amber-dim transition-colors">Account Settings</Link>
              {' '}to use frontier models at your own cost.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
