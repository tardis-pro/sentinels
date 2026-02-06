'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  ArrowLeft,
  Bot,
  Boxes,
  CheckCircle2,
  Clock3,
  FileCode2,
  Loader2,
  Play,
  Radar,
  ShieldAlert,
  Users,
  Webhook,
  XCircle,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface PageProps {
  params: { id: string };
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

interface ScanRun {
  id: string;
  scanner_name: string;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed';
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
  error_log?: string | null;
  created_at: string;
}

interface Scan {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  scanners: string[];
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  runs: ScanRun[];
  error_log?: string;
}

interface Finding {
  id: string;
  scanner_name: string;
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN';
  file_path: string;
  start_line: number;
  title: string;
  description: string;
  code_snippet?: string;
  snippet_start_line?: number;
  snippet_end_line?: number;
}

interface Project {
  id: string;
  name: string;
  path: string;
}

export default function ProjectDetails({ params }: PageProps) {
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [selectedScanners, setSelectedScanners] = useState<string[]>(['trivy', 'semgrep']);

  const formatTimestamp = (value?: string | null) => (value ? new Date(value).toLocaleString() : '--');

  const statusTone = (status: string) => {
    switch (status) {
      case 'completed':
        return 'border-emerald-400/40 bg-emerald-500/10 text-emerald-200';
      case 'failed':
        return 'border-red-400/40 bg-red-500/10 text-red-200';
      case 'running':
      case 'queued':
        return 'border-amber-400/40 bg-amber-500/10 text-amber-200';
      default:
        return 'border-slate-500/40 bg-slate-500/10 text-slate-200';
    }
  };

  const severityTone = (severity: Finding['severity']) => {
    switch (severity) {
      case 'CRITICAL':
        return 'border-red-400/50 bg-red-500/20 text-red-100';
      case 'HIGH':
        return 'border-orange-400/50 bg-orange-500/20 text-orange-100';
      case 'MEDIUM':
        return 'border-amber-400/50 bg-amber-500/20 text-amber-100';
      case 'LOW':
        return 'border-sky-400/50 bg-sky-500/20 text-sky-100';
      default:
        return 'border-slate-400/50 bg-slate-500/20 text-slate-100';
    }
  };

  const AVAILABLE_SCANNERS = [
    { id: 'trivy', label: 'Trivy' },
    { id: 'semgrep', label: 'Semgrep' },
    { id: 'bandit', label: 'Bandit' },
    { id: 'clair', label: 'Clair' },
    { id: 'sonarqube', label: 'SonarQube' },
  ];

  const toggleScanner = (id: string) => {
    setSelectedScanners((prev) => (prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]));
  };

  const fetchProjectData = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/projects/${params.id}`);
      if (res.ok) {
        const current = await res.json();
        setProject(current);
      } else {
        setProject({ id: params.id, name: 'Unknown Project', path: params.id });
      }

      const scansRes = await fetch(`${API_URL}/projects/${params.id}/scans`);
      const history = await scansRes.json();
      setScans(history);

      if (history.length > 0) {
        const latestScanId = history[0].id;
        setActiveScanId((current) => current ?? latestScanId);
        const findingsRes = await fetch(`${API_URL}/scans/${latestScanId}/findings`);
        const scanFindings = await findingsRes.json();
        setFindings(scanFindings);
      }
    } catch (e) {
      console.error(e);
      setProject({ id: params.id, name: 'Unknown Project', path: params.id });
    }
  }, [params.id]);

  useEffect(() => {
    fetchProjectData();
  }, [fetchProjectData]);

  useEffect(() => {
    if (!activeScanId) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_URL}/scans/${activeScanId}`);
        if (res.ok) {
          const scan = await res.json();
          if (scan.status === 'completed' || scan.status === 'failed') {
            setIsScanning(false);
            const fRes = await fetch(`${API_URL}/scans/${activeScanId}/findings`);
            const scanFindings = await fRes.json();
            setFindings(scanFindings);
            clearInterval(interval);
          }
        }
      } catch (e) {
        console.error('Polling error', e);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [activeScanId]);

  const triggerScan = async () => {
    if (selectedScanners.length === 0) {
      alert('Please select at least one scanner.');
      return;
    }
    setIsScanning(true);
    try {
      const res = await fetch(`${API_URL}/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: params.id,
          scanners: selectedScanners,
        }),
      });
      const data = await res.json();
      setActiveScanId(data.id);
    } catch (e) {
      console.error(e);
      setIsScanning(false);
    }
  };

  const severityCounts = findings.reduce(
    (acc, finding) => {
      acc[finding.severity] = (acc[finding.severity] || 0) + 1;
      return acc;
    },
    {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
      UNKNOWN: 0,
    } as Record<Finding['severity'], number>
  );

  const riskScore = Math.min(
    100,
    severityCounts.CRITICAL * 24 + severityCounts.HIGH * 10 + severityCounts.MEDIUM * 5 + severityCounts.LOW * 2
  );
  const riskTier = riskScore >= 70 ? 'critical' : riskScore >= 35 ? 'elevated' : 'stable';

  if (!project) {
    return (
      <div className="grid min-h-screen place-items-center bg-[#070a12] px-6 text-slate-100">
        <div className="inline-flex items-center gap-3 rounded-full border border-red-500/30 bg-red-500/10 px-5 py-3 text-sm">
          <Loader2 className="h-4 w-4 animate-spin text-red-300" />
          Acquiring threat telemetry...
        </div>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#070a12] text-slate-100">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_15%_10%,rgba(239,68,68,0.16),transparent_38%),radial-gradient(circle_at_85%_0%,rgba(56,189,248,0.14),transparent_36%),linear-gradient(180deg,#070a12,#0a1020)]" />

      <header className="sticky top-0 z-20 border-b border-red-500/20 bg-[#090d17]/85 backdrop-blur">
        <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center justify-between gap-5 px-5 py-4 md:px-8">
          <div className="flex min-w-0 items-center gap-4">
            <Link
              href="/"
              className="rounded-full border border-slate-600/60 bg-slate-800/70 p-2 text-slate-200 transition hover:border-red-400/50 hover:text-red-200"
            >
              <ArrowLeft className="h-5 w-5" />
            </Link>
            <div>
              <p className="text-[11px] uppercase tracking-[0.22em] text-red-300/80">Threat Command</p>
              <h1 className="truncate text-xl font-semibold tracking-tight text-slate-100 md:text-2xl">{project.name}</h1>
              <p className="truncate font-mono text-xs text-slate-400">{project.path}</p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-2 text-center">
              <p className="text-[10px] uppercase tracking-[0.18em] text-red-200/80">Risk Score</p>
              <p className="text-xl font-bold text-red-100">{riskScore}</p>
            </div>
            <div
              className={cn(
                'rounded-xl border px-4 py-2 text-center',
                riskTier === 'critical'
                  ? 'border-red-400/40 bg-red-500/10 text-red-200'
                  : riskTier === 'elevated'
                    ? 'border-amber-400/40 bg-amber-500/10 text-amber-200'
                    : 'border-emerald-400/40 bg-emerald-500/10 text-emerald-200'
              )}
            >
              <p className="text-[10px] uppercase tracking-[0.18em]">Threat Posture</p>
              <p className="text-sm font-semibold uppercase">{riskTier}</p>
            </div>
          </div>
        </div>
        <div className="mx-auto flex w-full max-w-7xl flex-wrap gap-2 px-5 pb-3 md:px-8">
          <Link href="/analytics" className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/40 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-cyan-100">
            <Radar className="h-3.5 w-3.5" /> Overview
          </Link>
          <Link href="/policies" className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-800/70 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200 hover:border-slate-400">
            <Boxes className="h-3.5 w-3.5" /> Policies
          </Link>
          <Link href="/webhooks" className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-800/70 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200 hover:border-slate-400">
            <Webhook className="h-3.5 w-3.5" /> Webhooks
          </Link>
          <Link href="/ai" className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-800/70 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200 hover:border-slate-400">
            <Bot className="h-3.5 w-3.5" /> AI
          </Link>
          <Link href="/collaboration" className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-800/70 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200 hover:border-slate-400">
            <Users className="h-3.5 w-3.5" /> Collaboration
          </Link>
        </div>
      </header>

      <main className="relative mx-auto w-full max-w-7xl px-5 py-6 md:px-8 md:py-8">
        <section className="mb-6 rounded-2xl border border-slate-700/50 bg-slate-900/70 p-4 shadow-[0_0_0_1px_rgba(15,23,42,0.4),0_25px_80px_rgba(2,6,23,0.6)] md:p-5">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="rounded-xl border border-red-400/40 bg-red-500/15 p-2.5">
                <ShieldAlert className="h-5 w-5 text-red-200" />
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-[0.2em] text-slate-400">Active Defense Console</p>
                <p className="text-sm text-slate-200">Select scanners and launch a new sweep.</p>
              </div>
            </div>

            <button
              onClick={triggerScan}
              disabled={isScanning}
              className={cn(
                'inline-flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-semibold transition',
                isScanning
                  ? 'cursor-not-allowed border-slate-600 bg-slate-800 text-slate-400'
                  : 'border-red-400/50 bg-red-600/80 text-white hover:bg-red-500'
              )}
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Running scan...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  Run Analysis
                </>
              )}
            </button>
          </div>

          <div className="flex flex-wrap gap-2">
            {AVAILABLE_SCANNERS.map((scanner) => {
              const selected = selectedScanners.includes(scanner.id);
              return (
                <label
                  key={scanner.id}
                  className={cn(
                    'inline-flex cursor-pointer items-center gap-2 rounded-full border px-3 py-1.5 text-xs transition',
                    selected
                      ? 'border-red-400/50 bg-red-500/15 text-red-100'
                      : 'border-slate-600 bg-slate-800/70 text-slate-300 hover:border-slate-500'
                  )}
                >
                  <input
                    type="checkbox"
                    checked={selected}
                    onChange={() => toggleScanner(scanner.id)}
                    disabled={isScanning}
                    className="h-3.5 w-3.5 rounded border-slate-500 bg-slate-900 text-red-500 focus:ring-red-400"
                  />
                  {scanner.label}
                </label>
              );
            })}
          </div>

          {activeScanId && (
            <div className="mt-4 flex items-start gap-3 rounded-xl border border-sky-400/30 bg-sky-500/10 px-4 py-3 text-sm text-sky-100">
              <Radar className="mt-0.5 h-4 w-4 flex-shrink-0" />
              <div>
                <p className="font-medium">
                  Tracking scan <span className="font-mono text-xs text-sky-200/90">{activeScanId}</span>
                </p>
                <p className="text-xs text-sky-100/80">{isScanning ? 'Collectors are still active.' : 'Execution complete. Reviewing telemetry.'}</p>
              </div>
            </div>
          )}
        </section>

        <section className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3">
            <p className="text-[10px] uppercase tracking-[0.18em] text-red-200/80">Critical</p>
            <p className="text-2xl font-semibold text-red-100">{severityCounts.CRITICAL}</p>
          </div>
          <div className="rounded-xl border border-orange-500/30 bg-orange-500/10 p-3">
            <p className="text-[10px] uppercase tracking-[0.18em] text-orange-200/80">High</p>
            <p className="text-2xl font-semibold text-orange-100">{severityCounts.HIGH}</p>
          </div>
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3">
            <p className="text-[10px] uppercase tracking-[0.18em] text-amber-200/80">Medium</p>
            <p className="text-2xl font-semibold text-amber-100">{severityCounts.MEDIUM}</p>
          </div>
          <div className="rounded-xl border border-slate-500/30 bg-slate-500/10 p-3">
            <p className="text-[10px] uppercase tracking-[0.18em] text-slate-300/80">Open Findings</p>
            <p className="text-2xl font-semibold text-slate-100">{findings.length}</p>
          </div>
        </section>

        <div className="grid gap-6 xl:grid-cols-[1.05fr_1fr]">
          <section className="rounded-2xl border border-slate-700/60 bg-slate-900/65 p-4 md:p-5">
            <div className="mb-4 flex items-center gap-2">
              <Clock3 className="h-4 w-4 text-slate-300" />
              <h2 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-200">Scan Timeline</h2>
              <span className="rounded-full border border-slate-600 bg-slate-800 px-2 py-0.5 text-xs text-slate-300">{scans.length}</span>
            </div>

            {scans.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-600/70 bg-slate-800/40 px-4 py-8 text-center text-sm text-slate-400">
                No scans yet. Launch your first defense sweep.
              </div>
            ) : (
              <div className="space-y-3">
                {scans.map((scan) => (
                  <button
                    key={scan.id}
                    onClick={() => {
                      setActiveScanId(scan.id);
                      fetch(`${API_URL}/scans/${scan.id}/findings`)
                        .then((res) => res.json())
                        .then((scanFindings) => {
                          setFindings(scanFindings);
                        });
                    }}
                    className={cn(
                      'w-full rounded-xl border p-3 text-left transition',
                      activeScanId === scan.id
                        ? 'border-red-400/60 bg-red-500/10 shadow-[0_0_0_1px_rgba(248,113,113,0.35)]'
                        : 'border-slate-700 bg-slate-800/60 hover:border-slate-500'
                    )}
                  >
                    <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                      <p className="truncate font-mono text-[11px] text-slate-300">{scan.id}</p>
                      <span className={cn('rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase', statusTone(scan.status))}>
                        {scan.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400">
                      {formatTimestamp(scan.started_at || scan.created_at)} {' -> '} {formatTimestamp(scan.completed_at)}
                    </p>
                    {scan.error_log && (
                      <div className="mt-2 rounded-lg border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-100">
                        <div className="mb-1 flex items-center gap-1.5 font-semibold">
                          <XCircle className="h-3.5 w-3.5" />
                          Scan Error
                        </div>
                        <p className="whitespace-pre-wrap font-mono text-[11px] text-red-100/90">{scan.error_log}</p>
                      </div>
                    )}

                    <div className="mt-2 space-y-1.5">
                      {scan.runs.map((run) => (
                        <div key={run.id} className="rounded-md border border-slate-700/70 bg-slate-900/65 px-2.5 py-2">
                          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                            <span className="font-semibold uppercase tracking-wide text-slate-200">{run.scanner_name}</span>
                            <span className={cn('rounded-full border px-2 py-0.5 font-semibold uppercase', statusTone(run.status))}>
                              {run.status}
                            </span>
                            <span className="text-slate-400">Findings: {run.findings_count ?? 0}</span>
                          </div>
                          {run.error_log && (
                            <p className="mt-2 whitespace-pre-wrap break-all font-mono text-[10px] text-red-200">{run.error_log}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </section>

          <section className="rounded-2xl border border-slate-700/60 bg-slate-900/65 p-4 md:p-5">
            <div className="mb-4 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-300" />
              <h2 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-200">Security Findings</h2>
              <span className="rounded-full border border-slate-600 bg-slate-800 px-2 py-0.5 text-xs text-slate-300">{findings.length}</span>
            </div>

            {findings.length === 0 ? (
              <div className="rounded-xl border border-dashed border-emerald-500/40 bg-emerald-500/10 px-4 py-10 text-center">
                <CheckCircle2 className="mx-auto mb-2 h-8 w-8 text-emerald-300" />
                <p className="text-sm font-medium text-emerald-100">No findings in current view.</p>
                <p className="mt-1 text-xs text-emerald-200/80">Run additional scanners or inspect older scans.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {findings.map((finding) => (
                  <article key={finding.id} className="rounded-xl border border-slate-700 bg-slate-800/60 p-3.5">
                    <div className="mb-2 flex flex-wrap items-center gap-2">
                      <span className={cn('rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide', severityTone(finding.severity))}>
                        {finding.severity}
                      </span>
                      <span className="text-[11px] uppercase tracking-wide text-slate-300">{finding.scanner_name}</span>
                      <span className="font-mono text-[11px] text-slate-400">{finding.rule_id}</span>
                    </div>
                    <h3 className="text-sm font-semibold text-slate-100">{finding.title}</h3>
                    <p className="mt-1 text-sm text-slate-300">{finding.description}</p>
                    <div className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-slate-600 bg-slate-900/70 px-2 py-1 font-mono text-[11px] text-slate-300">
                      <FileCode2 className="h-3.5 w-3.5" />
                      {finding.file_path}:{finding.start_line}
                    </div>
                    {finding.scanner_name === 'sonarqube' && finding.code_snippet && (
                      <details className="mt-3 rounded-lg border border-slate-700/80 bg-slate-950/60 p-2">
                        <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-cyan-200">
                          Expand Code In Question
                        </summary>
                        <p className="mt-2 text-[11px] text-slate-400">
                          Lines {finding.snippet_start_line ?? finding.start_line} - {finding.snippet_end_line ?? finding.start_line}
                        </p>
                        <pre className="mt-2 max-h-64 overflow-auto rounded-md border border-slate-700 bg-slate-950 p-2 font-mono text-[11px] text-slate-200">
                          {finding.code_snippet}
                        </pre>
                      </details>
                    )}
                  </article>
                ))}
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
}
