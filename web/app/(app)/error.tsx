'use client';

export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="max-w-2xl mx-auto py-20 text-center">
      <div className="text-5xl mb-4">&#9888;</div>
      <h2 className="font-[family-name:var(--font-display)] text-2xl text-text-bright tracking-wider mb-4">
        SOMETHING WENT WRONG
      </h2>
      <p className="text-text-dim text-sm mb-6">
        {error.message || 'An unexpected error occurred. Please try again.'}
      </p>
      <button
        onClick={reset}
        className="bg-amber hover:bg-amber-dim text-bg font-bold px-6 py-2 rounded-[var(--radius-button)] transition-colors"
      >
        Try Again
      </button>
    </div>
  );
}
