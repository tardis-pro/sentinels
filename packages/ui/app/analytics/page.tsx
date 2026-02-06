'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowRight, RefreshCw } from 'lucide-react';
import { ApiCard, ConsoleShell, FetchResult, isUuid, postJson, requestJson } from '../_components/console-kit';
import { cn } from '@/lib/utils';

type Project = { id: string; name: string; path: string };

type DashboardData = {
  capabilities: FetchResult;
  projects: FetchResult<Project[]>;
  findings: FetchResult;
  scans: FetchResult;
  gitProvider: FetchResult;
  analyticsSummary: FetchResult;
  trends: FetchResult;
  analyticsProjects: FetchResult;
  scannerPerformance: FetchResult;
  analyticsCompliance: FetchResult;
  postureHistory: FetchResult;
  findingDensity: FetchResult;
  remediationVelocity: FetchResult;
  policies: FetchResult;
  policyStats: FetchResult;
  frameworks: FetchResult;
  webhooks: FetchResult;
  webhookStats: FetchResult;
  scanTriggers: FetchResult;
  aiStatus: FetchResult;
  users: FetchResult;
  teams: FetchResult;
  collaborationStats: FetchResult;
  slaConfigs: FetchResult;
  riskPending: FetchResult;
  issueTrackers: FetchResult;
};

const initialData: DashboardData = {
  capabilities: { ok: false, data: null, error: null },
  projects: { ok: false, data: null, error: null },
  findings: { ok: false, data: null, error: null },
  scans: { ok: false, data: null, error: null },
  gitProvider: { ok: false, data: null, error: null },
  analyticsSummary: { ok: false, data: null, error: null },
  trends: { ok: false, data: null, error: null },
  analyticsProjects: { ok: false, data: null, error: null },
  scannerPerformance: { ok: false, data: null, error: null },
  analyticsCompliance: { ok: false, data: null, error: null },
  postureHistory: { ok: false, data: null, error: null },
  findingDensity: { ok: false, data: null, error: null },
  remediationVelocity: { ok: false, data: null, error: null },
  policies: { ok: false, data: null, error: null },
  policyStats: { ok: false, data: null, error: null },
  frameworks: { ok: false, data: null, error: null },
  webhooks: { ok: false, data: null, error: null },
  webhookStats: { ok: false, data: null, error: null },
  scanTriggers: { ok: false, data: null, error: null },
  aiStatus: { ok: false, data: null, error: null },
  users: { ok: false, data: null, error: null },
  teams: { ok: false, data: null, error: null },
  collaborationStats: { ok: false, data: null, error: null },
  slaConfigs: { ok: false, data: null, error: null },
  riskPending: { ok: false, data: null, error: null },
  issueTrackers: { ok: false, data: null, error: null },
};

const DOMAIN_LINKS = [
  { href: '/policies', title: 'Policy Studio', description: 'Lifecycle, templates, frameworks, and policy metrics.' },
  { href: '/webhooks', title: 'Webhook Ops', description: 'Delivery health, trigger queues, and Git provider plumbing.' },
  { href: '/ai', title: 'AI Center', description: 'Provider status, readiness, and AI triage surfaces.' },
  { href: '/collaboration', title: 'Collaboration Hub', description: 'Org-scoped teams, SLA, and risk workflows.' },
];

export default function IntegratedApiConsole() {
  const [loading, setLoading] = useState(true);
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [orgId, setOrgId] = useState('');
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [data, setData] = useState<DashboardData>(initialData);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    const projects = await requestJson<Project[]>('/projects');
    const activeProject = selectedProjectId || projects.data?.[0]?.id || '';
    if (!selectedProjectId && activeProject) {
      setSelectedProjectId(activeProject);
    }
    const validOrgId = isUuid(orgId) ? orgId : '';

    const [
      capabilities,
      findings,
      scans,
      gitProvider,
      analyticsSummary,
      trends,
      analyticsProjects,
      scannerPerformance,
      analyticsCompliance,
      postureHistory,
      findingDensity,
      remediationVelocity,
      policies,
      policyStats,
      frameworks,
      webhooks,
      webhookStats,
      scanTriggers,
      aiStatus,
      users,
      teams,
      collaborationStats,
      slaConfigs,
      riskPending,
      issueTrackers,
    ] = await Promise.all([
      requestJson('/_capabilities'),
      requestJson('/findings'),
      activeProject ? requestJson(`/projects/${activeProject}/scans`) : Promise.resolve({ ok: false, data: null, error: null } as FetchResult),
      activeProject ? requestJson(`/projects/${activeProject}/git/provider`) : Promise.resolve({ ok: false, data: null, error: null } as FetchResult),
      requestJson('/analytics/summary'),
      requestJson('/analytics/trends?interval=week'),
      requestJson('/analytics/projects?limit=6'),
      requestJson('/analytics/scanners'),
      requestJson('/analytics/compliance?framework=OWASP%20Top%2010'),
      requestJson('/analytics/posture-history?days=30'),
      requestJson('/analytics/finding-density'),
      requestJson('/analytics/remediation-velocity?days=30'),
      requestJson('/policies'),
      requestJson('/policies/statistics'),
      requestJson('/policies/compliance/frameworks'),
      requestJson('/webhooks'),
      requestJson('/webhooks/stats'),
      requestJson('/scan-triggers'),
      requestJson('/ai/status'),
      requestJson('/users'),
      validOrgId ? requestJson(`/teams?orgId=${encodeURIComponent(validOrgId)}`) : requestJson('/teams'),
      validOrgId
        ? requestJson(`/collaboration/stats?orgId=${encodeURIComponent(validOrgId)}`)
        : Promise.resolve({ ok: true, data: { note: 'Provide valid orgId UUID' }, error: null } as FetchResult),
      validOrgId
        ? requestJson(`/sla?orgId=${encodeURIComponent(validOrgId)}`)
        : Promise.resolve({ ok: true, data: { note: 'Provide valid orgId UUID' }, error: null } as FetchResult),
      validOrgId
        ? requestJson(`/risk-acceptance/pending?orgId=${encodeURIComponent(validOrgId)}`)
        : Promise.resolve({ ok: true, data: { note: 'Provide valid orgId UUID' }, error: null } as FetchResult),
      validOrgId
        ? requestJson(`/issue-trackers?orgId=${encodeURIComponent(validOrgId)}`)
        : Promise.resolve({ ok: true, data: { note: 'Provide valid orgId UUID' }, error: null } as FetchResult),
    ]);

    setData({
      capabilities,
      projects,
      findings,
      scans,
      gitProvider,
      analyticsSummary,
      trends,
      analyticsProjects,
      scannerPerformance,
      analyticsCompliance,
      postureHistory,
      findingDensity,
      remediationVelocity,
      policies,
      policyStats,
      frameworks,
      webhooks,
      webhookStats,
      scanTriggers,
      aiStatus,
      users,
      teams,
      collaborationStats,
      slaConfigs,
      riskPending,
      issueTrackers,
    });
    setLoading(false);
  }, [orgId, selectedProjectId]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  const runMaintenanceAction = async (kind: 'analytics' | 'policies' | 'event') => {
    setActionMessage(null);
    const result =
      kind === 'analytics'
        ? await postJson('/analytics/refresh')
        : kind === 'policies'
          ? await postJson('/policies/templates/seed')
          : await postJson('/analytics/track', {
              eventType: 'ui_manual',
              projectId: selectedProjectId || null,
              scanId: null,
              metricName: 'dashboard_refresh',
              metricValue: 1,
              dimensions: { source: 'integrated-console' },
            });
    setActionMessage(result.ok ? `${kind} action completed` : `${kind} action failed: ${result.error}`);
    await fetchAll();
  };

  const okCount = Object.values(data).filter((item) => item.ok).length;
  const totalCount = Object.values(data).length;

  return (
    <ConsoleShell
      title="Executive Overview"
      subtitle="One-page health map across all API domains"
      right={
        <div className="flex flex-wrap items-center gap-3">
          <div className="rounded-lg border border-emerald-400/40 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-200">
            Healthy endpoints: {okCount}/{totalCount}
          </div>
          <button
            onClick={fetchAll}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-500 bg-slate-800 px-3 py-1.5 text-sm hover:border-slate-300"
          >
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} /> Refresh
          </button>
        </div>
      }
    >
      <section className="grid gap-3 rounded-xl border border-slate-700 bg-slate-900/65 p-4 md:grid-cols-3">
        <label className="text-xs text-slate-300">
          Active project
          <select
            value={selectedProjectId}
            onChange={(e) => setSelectedProjectId(e.target.value)}
            className="mt-1 w-full rounded-md border border-slate-600 bg-slate-950 px-2.5 py-2 text-sm"
          >
            <option value="">Auto-select</option>
            {(data.projects.data || []).map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>
        </label>

        <label className="text-xs text-slate-300">
          Organization id
          <input
            value={orgId}
            onChange={(e) => setOrgId(e.target.value)}
            placeholder="optional UUID"
            className="mt-1 w-full rounded-md border border-slate-600 bg-slate-950 px-2.5 py-2 text-sm"
          />
        </label>

        <div className="flex flex-wrap items-end gap-2">
          <button onClick={() => runMaintenanceAction('analytics')} className="rounded-md border border-sky-400/50 bg-sky-500/10 px-3 py-2 text-xs font-semibold text-sky-200">Refresh analytics</button>
          <button onClick={() => runMaintenanceAction('policies')} className="rounded-md border border-purple-400/50 bg-purple-500/10 px-3 py-2 text-xs font-semibold text-purple-200">Seed policies</button>
          <button onClick={() => runMaintenanceAction('event')} className="rounded-md border border-amber-400/50 bg-amber-500/10 px-3 py-2 text-xs font-semibold text-amber-200">Track event</button>
        </div>
      </section>

      {actionMessage && <p className="text-sm text-slate-300">{actionMessage}</p>}

      <section className="grid gap-3 lg:grid-cols-2 xl:grid-cols-4">
        {DOMAIN_LINKS.map((item) => (
          <Link key={item.href} href={item.href} className="rounded-xl border border-slate-700 bg-slate-900/60 p-4 transition hover:border-cyan-300/40 hover:bg-slate-900/80">
            <p className="text-sm font-semibold text-slate-100">{item.title}</p>
            <p className="mt-1 text-xs text-slate-400">{item.description}</p>
            <div className="mt-3 inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-cyan-200">
              Open workspace <ArrowRight className="h-3.5 w-3.5" />
            </div>
          </Link>
        ))}
      </section>

      <section className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
        <ApiCard title="Capabilities" result={data.capabilities} />
        <ApiCard title="Projects" result={data.projects} />
        <ApiCard title="Findings" result={data.findings} />
        <ApiCard title="Project Scans" result={data.scans} hint="Depends on selected project" />
        <ApiCard title="Git Provider" result={data.gitProvider} hint="Depends on selected project" />
        <ApiCard title="Scan Triggers" result={data.scanTriggers} />
        <ApiCard title="Analytics Summary" result={data.analyticsSummary} />
        <ApiCard title="Trend Snapshot" result={data.trends} />
        <ApiCard title="AI Status" result={data.aiStatus} />
      </section>
    </ConsoleShell>
  );
}
