'use client';

import { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { ApiCard, ConsoleShell, FetchResult, requestJson } from '../_components/console-kit';
import { cn } from '@/lib/utils';

type WebhookState = {
  webhooks: FetchResult;
  stats: FetchResult;
  triggers: FetchResult;
};

const initialState: WebhookState = {
  webhooks: { ok: false, data: null, error: null },
  stats: { ok: false, data: null, error: null },
  triggers: { ok: false, data: null, error: null },
};

export default function WebhooksPage() {
  const [loading, setLoading] = useState(true);
  const [state, setState] = useState<WebhookState>(initialState);

  const load = useCallback(async () => {
    setLoading(true);
    const [webhooks, stats, triggers] = await Promise.all([
      requestJson('/webhooks'),
      requestJson('/webhooks/stats'),
      requestJson('/scan-triggers'),
    ]);
    setState({ webhooks, stats, triggers });
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <ConsoleShell
      title="Webhook Ops"
      subtitle="Inbound events, outbound delivery health, and trigger orchestration"
      right={
        <button onClick={load} className="inline-flex items-center gap-2 rounded-lg border border-slate-500 bg-slate-800 px-3 py-1.5 text-sm hover:border-slate-300">
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} /> Refresh
        </button>
      }
    >
      <section className="grid gap-3 lg:grid-cols-3">
        <ApiCard title="Webhook Configurations" result={state.webhooks} hint="Connected endpoints and activation state" />
        <ApiCard title="Delivery Statistics" result={state.stats} hint="24h status breakdown" />
        <ApiCard title="Scan Triggers Queue" result={state.triggers} hint="Pending scan trigger backlog" />
      </section>
    </ConsoleShell>
  );
}
