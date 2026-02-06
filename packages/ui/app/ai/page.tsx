'use client';

import { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { ApiCard, ConsoleShell, FetchResult, requestJson } from '../_components/console-kit';
import { cn } from '@/lib/utils';

type AiState = {
  status: FetchResult;
  findings: FetchResult;
  projects: FetchResult;
};

const initialState: AiState = {
  status: { ok: false, data: null, error: null },
  findings: { ok: false, data: null, error: null },
  projects: { ok: false, data: null, error: null },
};

export default function AiPage() {
  const [loading, setLoading] = useState(true);
  const [state, setState] = useState<AiState>(initialState);

  const load = useCallback(async () => {
    setLoading(true);
    const [status, findings, projects] = await Promise.all([
      requestJson('/ai/status'),
      requestJson('/findings'),
      requestJson('/projects'),
    ]);
    setState({ status, findings, projects });
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <ConsoleShell
      title="AI Center"
      subtitle="Model availability and context feeds for AI-assisted triage"
      right={
        <button onClick={load} className="inline-flex items-center gap-2 rounded-lg border border-slate-500 bg-slate-800 px-3 py-1.5 text-sm hover:border-slate-300">
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} /> Refresh
        </button>
      }
    >
      <section className="grid gap-3 lg:grid-cols-3">
        <ApiCard title="AI Provider Status" result={state.status} hint="Provider, model, and runtime availability" />
        <ApiCard title="Latest Findings Feed" result={state.findings} hint="Primary evidence stream for analysis" />
        <ApiCard title="Project Context" result={state.projects} hint="Available repositories for AI workflows" />
      </section>
    </ConsoleShell>
  );
}
