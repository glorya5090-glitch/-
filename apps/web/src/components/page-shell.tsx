import type { ReactNode } from 'react';

export function PageShell({ children }: { children: ReactNode }) {
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-5xl flex-col gap-8 px-6 py-10 lg:px-10">
      {children}
    </main>
  );
}
