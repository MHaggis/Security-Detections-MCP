'use client';

import { useState } from 'react';
import Link from 'next/link';
import { createClient } from '@/lib/supabase/client';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const supabase = createClient();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/auth/callback?next=/account`,
    });

    if (error) {
      setError(error.message);
    } else {
      setSent(true);
    }
    setLoading(false);
  }

  return (
    <div className="min-h-screen bg-bg bg-grid flex items-center justify-center p-6">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link href="/" className="inline-flex items-center gap-3">
            <div className="w-10 h-10 rounded bg-amber/20 border border-amber/40 flex items-center justify-center">
              <span className="text-amber font-bold">SD</span>
            </div>
            <span className="font-[family-name:var(--font-display)] text-2xl tracking-wider text-text-bright">
              SECURITY DETECTIONS
            </span>
          </Link>
        </div>

        <div className="bg-card border border-border rounded-[var(--radius-card)] p-8">
          {sent ? (
            <div className="text-center py-4">
              <div className="w-14 h-14 rounded-full bg-green/10 border border-green/30 flex items-center justify-center mx-auto mb-4">
                <span className="text-green text-2xl">&#10003;</span>
              </div>
              <h1 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-2">
                CHECK YOUR EMAIL
              </h1>
              <p className="text-text-dim text-sm mb-6">
                We sent a password reset link to{' '}
                <span className="text-amber font-[family-name:var(--font-mono)]">{email}</span>.
              </p>
              <Link href="/login" className="text-amber hover:text-amber-dim transition-colors text-sm">
                Back to sign in
              </Link>
            </div>
          ) : (
            <>
              <h1 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-2">
                RESET PASSWORD
              </h1>
              <p className="text-text-dim text-sm mb-6">
                Enter your email and we&apos;ll send you a reset link.
              </p>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
                    Email
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text placeholder:text-text-dim/50 outline-none transition-colors font-[family-name:var(--font-mono)] text-sm"
                    placeholder="analyst@example.com"
                    required
                  />
                </div>

                {error && (
                  <div className="bg-red/10 border border-red/30 rounded-[var(--radius-card)] px-4 py-2 text-red text-sm">
                    {error}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-amber hover:bg-amber-dim disabled:opacity-50 text-bg font-bold py-3 rounded-[var(--radius-button)] transition-colors"
                >
                  {loading ? 'Sending...' : 'Send Reset Link'}
                </button>
              </form>

              <p className="text-text-dim text-sm text-center mt-6">
                Remember your password?{' '}
                <Link href="/login" className="text-amber hover:text-amber-dim transition-colors">
                  Sign in
                </Link>
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
