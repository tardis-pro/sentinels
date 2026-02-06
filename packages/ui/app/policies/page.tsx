'use client';

import { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { ApiCard, ConsoleShell, FetchResult, postJson, requestJson } from '../_components/console-kit';
import { cn } from '@/lib/utils';

type PolicyState = {
  policies: FetchResult;
  statistics: FetchResult;
  frameworks: FetchResult;
};

const initialState: PolicyState = {
  policies: { ok: false, data: null, error: null },
  statistics: { ok: false, data: null, error: null },
  frameworks: { ok: false, data: null, error: null },
};

export default function PoliciesPage() {
  const [loading, setLoading] = useState(true);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [state, setState] = useState<PolicyState>(initialState);

  const load = useCallback(async () => {
    setLoading(true);
    const [policies, statistics, frameworks] = await Promise.all([
      requestJson('/policies'),
      requestJson('/policies/statistics'),
      requestJson('/policies/compliance/frameworks'),
    ]);
    setState({ policies, statistics, frameworks });
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const seedTemplates = async () => {
    setActionMessage(null);
    const result = await postJson('/policies/templates/seed');
    setActionMessage(result.ok ? 'Policy templates seeded' : `Seeding failed: ${result.error}`);
    await load();
  };

  return (
    <ConsoleShell
      title="Policy Studio"
      subtitle="Policy lifecycle, compliance frameworks, and guardrail metrics"
      right={
        <div className="flex items-center gap-2">
          <button onClick={seedTemplates} className="rounded-md border border-purple-400/50 bg-purple-500/10 px-3 py-1.5 text-xs font-semibold text-purple-200">Seed templates</button>
          <button onClick={load} className="inline-flex items-center gap-2 rounded-lg border border-slate-500 bg-slate-800 px-3 py-1.5 text-sm hover:border-slate-300">
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} /> Refresh
          </button>
        </div>
      }
    >
      {actionMessage && <p className="text-sm text-slate-300">{actionMessage}</p>}
      <section className="grid gap-3 lg:grid-cols-3">
        <ApiCard title="Policy List" result={state.policies} hint="Authoring and enablement state" />
        <ApiCard title="Policy Statistics" result={state.statistics} hint="Coverage by category and severity" />
        <ApiCard title="Compliance Frameworks" result={state.frameworks} hint="Mapped framework controls" />
      </section>
    </ConsoleShell>
  );
}
