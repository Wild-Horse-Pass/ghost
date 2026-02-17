"use client";

export default function RootError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0a0a0a] text-gray-100 antialiased">
        <div className="flex flex-col items-center justify-center min-h-screen px-4">
          <div className="text-center max-w-md">
            <div className="text-4xl font-bold text-gray-500 mb-4">Error</div>
            <p className="text-gray-400 mb-2">Something went wrong.</p>
            <p className="text-sm text-gray-500 mb-6 font-mono break-all">
              {error.message || "Unknown error"}
            </p>
            <button
              onClick={reset}
              className="px-6 py-2.5 bg-orange-600 hover:bg-orange-500 text-white rounded-lg font-medium transition-colors"
            >
              Try Again
            </button>
          </div>
        </div>
      </body>
    </html>
  );
}
