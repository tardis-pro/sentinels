'use client';

import { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { ApiCard, ConsoleShell, FetchResult, isUuid, requestJson } from '../_components/console-kit';
import { cn } from '@/lib/utils';

type CollaborationState = {
  users: FetchResult;
  teams: FetchResult;
  stats: FetchResult;
  sla: FetchResult;
  risk: FetchResult;
  trackers: FetchResult;
};

const initialState: CollaborationState = {
  users: { ok: false, data: null, error: null },
  teams: { ok: false, data: null, error: null },
  stats: { ok: false, data: null, error: null },
  sla: { ok: false, data: null, error: null },
  risk: { ok: false, data: null, error: null },
  trackers: { ok: false, data: null, error: null },
};

export default function CollaborationPage() {
  const [loading, setLoading] = useState(true);
  const [orgId, setOrgId] = useState('');
  const [state, setState] = useState<CollaborationState>(initialState);

  const load = useCallback(async () => {
    setLoading(true);
    const validOrgId = isUuid(orgId) ? orgId : '';
    const [users, teams, stats, sla, risk, trackers] = await Promise.all([
      requestJson('/users'),
      validOrgId ? requestJson(`/teams?orgId=${encodeURIComponent(validOrgId)}`) : requestJson('/teams'),
      validOrgId
        ? requestJson(`/collaboration/stats?orgId=${encodeURIComponent(validOrgId)}`)
        : Promise.resolve({ ok: true, data: { note: 'Enter a valid org UUID to load org stats' }, error: null } as FetchResult),
      validOrgId
        ? requestJson(`/sla?orgId=${encodeURIComponent(validOrgId)}`)
        : Promise.resolve({ ok: true, data: { note: 'Enter a valid org UUID to load SLA settings' }, error: null } as FetchResult),
      validOrgId
        ? requestJson(`/risk-acceptance/pending?orgId=${encodeURIComponent(validOrgId)}`)
        : Promise.resolve({ ok: true, data: { note: 'Enter a valid org UUID to load risk queue' }, error: null } as FetchResult),
      validOrgId
        ? requestJson(`/issue-trackers?orgId=${encodeURIComponent(validOrgId)}`)
        : Promise.resolve({ ok: true, data: { note: 'Enter a valid org UUID to load trackers' }, error: null } as FetchResult),
    ]);
    setState({ users, teams, stats, sla, risk, trackers });
    setLoading(false);
  }, [orgId]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <ConsoleShell
      title="Collaboration Hub"
      subtitle="People, team operations, SLA, and risk acceptance management"
      right={
        <button onClick={load} className="inline-flex items-center gap-2 rounded-lg border border-slate-500 bg-slate-800 px-3 py-1.5 text-sm hover:border-slate-300">
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} /> Refresh
        </button>
      }
    >
      <section className="rounded-xl border border-slate-700 bg-slate-900/65 p-4">
        <label className="text-xs text-slate-300">
          Organization UUID
          <input
            value={orgId}
            onChange={(e) => setOrgId(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
            className="mt-1 w-full max-w-xl rounded-md border border-slate-600 bg-slate-950 px-2.5 py-2 text-sm"
          />
        </label>
      </section>

      <section className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
        <ApiCard title="Users" result={state.users} />
        <ApiCard title="Teams" result={state.teams} />
        <ApiCard title="Collaboration Stats" result={state.stats} />
        <ApiCard title="SLA Configurations" result={state.sla} />
        <ApiCard title="Pending Risk Acceptances" result={state.risk} />
        <ApiCard title="Issue Tracker Integrations" result={state.trackers} />
      </section>
    </ConsoleShell>
  );
}
