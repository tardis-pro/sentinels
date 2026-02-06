'use client';

import { ReactNode, useMemo } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Activity,
  Bot,
  Boxes,
  LayoutDashboard,
  Shield,
  Users,
  Webhook,
} from 'lucide-react';
import { cn } from '@/lib/utils';

export const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

export type FetchResult<T = unknown> = {
  ok: boolean;
  data: T | null;
  error: string | null;
};

const NAV_ITEMS = [
  { href: '/analytics', label: 'Overview', icon: LayoutDashboard },
  { href: '/policies', label: 'Policies', icon: Boxes },
  { href: '/webhooks', label: 'Webhooks', icon: Webhook },
  { href: '/ai', label: 'AI', icon: Bot },
  { href: '/collaboration', label: 'Collaboration', icon: Users },
];

export async function requestJson<T = unknown>(path: string): Promise<FetchResult<T>> {
  try {
    const res = await fetch(`${API_URL}${path}`);
    const text = await res.text();
    const data = text ? (JSON.parse(text) as T) : null;
    return { ok: res.ok, data, error: res.ok ? null : `${res.status} ${res.statusText}` };
  } catch (error) {
    return { ok: false, data: null, error: error instanceof Error ? error.message : 'Request failed' };
  }
}

export async function postJson(path: string, body?: unknown): Promise<FetchResult> {
  return mutateJson('POST', path, body);
}

export async function putJson(path: string, body?: unknown): Promise<FetchResult> {
  return mutateJson('PUT', path, body);
}

export async function patchJson(path: string, body?: unknown): Promise<FetchResult> {
  return mutateJson('PATCH', path, body);
}

export async function deleteJson(path: string): Promise<FetchResult> {
  return mutateJson('DELETE', path);
}

async function mutateJson(method: 'POST' | 'PUT' | 'PATCH' | 'DELETE', path: string, body?: unknown): Promise<FetchResult> {
  try {
    const res = await fetch(`${API_URL}${path}`, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    const data = text ? JSON.parse(text) : null;
    return { ok: res.ok, data, error: res.ok ? null : `${res.status} ${res.statusText}` };
  } catch (error) {
    return { ok: false, data: null, error: error instanceof Error ? error.message : 'Request failed' };
  }
}

export function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

export function StatusPill({ ok }: { ok: boolean }) {
  return (
    <span
      className={cn(
        'rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide',
        ok ? 'border-emerald-300/50 bg-emerald-500/15 text-emerald-200' : 'border-red-300/50 bg-red-500/15 text-red-200'
      )}
    >
      {ok ? 'ok' : 'error'}
    </span>
  );
}

export function ApiCard({ title, result, hint }: { title: string; result: FetchResult; hint?: string }) {
  const preview = useMemo(() => {
    if (!result.data) return 'No data';
    return JSON.stringify(result.data, null, 2).slice(0, 420);
  }, [result.data]);

  return (
    <article className="rounded-xl border border-slate-700 bg-slate-900/70 p-4">
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
        <StatusPill ok={result.ok} />
      </div>
      {hint && <p className="mb-2 text-xs text-slate-400">{hint}</p>}
      {result.error && <p className="mb-2 text-xs text-red-300">{result.error}</p>}
      <pre className="max-h-48 overflow-auto rounded-lg border border-slate-700/80 bg-slate-950/70 p-2 text-[11px] text-slate-300">
        {preview}
      </pre>
    </article>
  );
}

export function ConsoleShell({
  title,
  subtitle,
  right,
  children,
}: {
  title: string;
  subtitle: string;
  right?: ReactNode;
  children: ReactNode;
}) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100">
      <header className="sticky top-0 z-20 border-b border-slate-700/60 bg-[#0b1220]/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-5 py-4 md:px-8">
          <div className="flex items-center gap-3">
            <Link href="/" className="rounded-lg border border-slate-600 bg-slate-900/60 p-2 text-slate-200 hover:border-slate-400">
              <Shield className="h-4 w-4" />
            </Link>
            <div>
              <p className="text-[11px] uppercase tracking-[0.18em] text-slate-400">Sentinel Control Plane</p>
              <h1 className="text-xl font-semibold">{title}</h1>
              <p className="text-xs text-slate-400">{subtitle}</p>
            </div>
          </div>
          {right}
        </div>
        <nav className="mx-auto flex max-w-7xl flex-wrap gap-2 px-5 pb-3 md:px-8">
          {NAV_ITEMS.map((item) => {
            const active = pathname === item.href;
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  'inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-semibold uppercase tracking-wide transition',
                  active
                    ? 'border-cyan-300/50 bg-cyan-500/15 text-cyan-100'
                    : 'border-slate-600 bg-slate-800/70 text-slate-300 hover:border-slate-400'
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                {item.label}
              </Link>
            );
          })}
        </nav>
      </header>
      <main className="mx-auto max-w-7xl space-y-6 px-5 py-6 md:px-8">{children}</main>
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(circle_at_10%_8%,rgba(14,116,144,0.1),transparent_35%),radial-gradient(circle_at_90%_4%,rgba(190,24,93,0.08),transparent_35%)]" />
      <div className="pointer-events-none fixed bottom-4 right-4 flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/80 px-3 py-1 text-[11px] text-slate-400">
        <Activity className="h-3.5 w-3.5 text-emerald-300" />
        live telemetry
      </div>
    </div>
  );
}
