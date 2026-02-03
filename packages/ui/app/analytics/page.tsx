'use client';

import { useState, useEffect, useCallback } from 'react';
import {
  Shield, TrendingUp, AlertTriangle, CheckCircle, Clock,
  BarChart3, PieChart, Activity, FileText, Download, RefreshCw
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface AnalyticsSummary {
  totalProjects: number;
  totalScans: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  securityPostureScore: number;
}

interface TrendDataPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

interface ProjectScore {
  projectId: string;
  projectName: string;
  securityScore: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  lastFindingAt: string | null;
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

export default function AnalyticsDashboard() {
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [trends, setTrends] = useState<TrendDataPoint[]>([]);
  const [projectScores, setProjectScores] = useState<ProjectScore[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedPeriod, setSelectedPeriod] = useState<'day' | 'week' | 'month'>('day');

  const fetchAnalytics = useCallback(async () => {
    setLoading(true);
    try {
      const [summaryRes, trendsRes, projectsRes] = await Promise.all([
        fetch(`${API_URL}/api/analytics/summary`),
        fetch(`${API_URL}/api/analytics/trends?interval=${selectedPeriod}`),
        fetch(`${API_URL}/api/analytics/projects?limit=10`),
      ]);

      if (summaryRes.ok) setSummary(await summaryRes.json());
      if (trendsRes.ok) setTrends(await trendsRes.json());
      if (projectsRes.ok) setProjectScores(await projectsRes.json());
    } catch (error) {
      console.error('Failed to fetch analytics:', error);
    } finally {
      setLoading(false);
    }
  }, [selectedPeriod]);

  useEffect(() => {
    fetchAnalytics();
  }, [fetchAnalytics]);

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  const maxTrendValue = Math.max(...trends.map(t => t.total), 1);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 p-8 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 animate-spin text-indigo-600 mx-auto mb-4" />
          <p className="text-slate-500">Loading analytics...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 p-8 font-sans">
      <header className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-600 rounded-lg">
            <BarChart3 className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-indigo-900">Security Analytics</h1>
            <p className="text-slate-500">Comprehensive security posture overview</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <select
            value={selectedPeriod}
            onChange={(e) => setSelectedPeriod(e.target.value as 'day' | 'week' | 'month')}
            className="px-4 py-2 bg-white border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="day">Last 90 Days</option>
            <option value="week">Last 12 Weeks</option>
            <option value="month">Last 12 Months</option>
          </select>

          <button
            onClick={fetchAnalytics}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </header>

      <main className="max-w-7xl mx-auto space-y-8">
        {/* Security Posture Score */}
        <section className="bg-white rounded-xl border border-slate-200 p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <Shield className="w-5 h-5 text-indigo-500" />
              <h2 className="text-lg font-bold text-slate-800">Security Posture Score</h2>
            </div>
            <span className={cn(
              "px-3 py-1 rounded-full text-sm font-semibold",
              summary && summary.securityPostureScore >= 80 ? "bg-emerald-100 text-emerald-700" :
              summary && summary.securityPostureScore >= 50 ? "bg-amber-100 text-amber-700" :
              "bg-red-100 text-red-700"
            )}>
              {summary ? `${summary.securityPostureScore}%` : 'N/A'}
            </span>
          </div>

          {summary && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-4 bg-red-50 rounded-lg border border-red-100">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-red-500" />
                  <span className="text-sm font-medium text-red-700">Critical</span>
                </div>
                <p className="text-2xl font-bold text-red-800">{summary.criticalCount}</p>
              </div>

              <div className="p-4 bg-orange-50 rounded-lg border border-orange-100">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-orange-500" />
                  <span className="text-sm font-medium text-orange-700">High</span>
                </div>
                <p className="text-2xl font-bold text-orange-800">{summary.highCount}</p>
              </div>

              <div className="p-4 bg-yellow-50 rounded-lg border border-yellow-100">
                <div className="flex items-center gap-2 mb-2">
                  <Clock className="w-4 h-4 text-yellow-500" />
                  <span className="text-sm font-medium text-yellow-700">Medium</span>
                </div>
                <p className="text-2xl font-bold text-yellow-800">{summary.mediumCount}</p>
              </div>

              <div className="p-4 bg-blue-50 rounded-lg border border-blue-100">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="w-4 h-4 text-blue-500" />
                  <span className="text-sm font-medium text-blue-700">Low</span>
                </div>
                <p className="text-2xl font-bold text-blue-800">{summary.lowCount}</p>
              </div>
            </div>
          )}
        </section>

        {/* Trends Chart */}
        <section className="bg-white rounded-xl border border-slate-200 p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <TrendingUp className="w-5 h-5 text-indigo-500" />
              <h2 className="text-lg font-bold text-slate-800">Finding Trends</h2>
            </div>
          </div>

          {trends.length > 0 ? (
            <div className="h-64 flex items-end gap-1">
              {trends.map((point, idx) => (
                <div
                  key={point.date}
                  className="flex-1 flex flex-col items-center gap-1"
                >
                  <div className="w-full flex flex-col gap-0.5" style={{ height: '200px' }}>
                    <div
                      className="w-full bg-red-400 rounded-t"
                      style={{
                        height: `${(point.critical / maxTrendValue) * 100}%`,
                        minHeight: point.critical > 0 ? '4px' : '0',
                      }}
                      title={`Critical: ${point.critical}`}
                    />
                    <div
                      className="w-full bg-orange-400"
                      style={{
                        height: `${(point.high / maxTrendValue) * 100}%`,
                        minHeight: point.high > 0 ? '4px' : '0',
                      }}
                      title={`High: ${point.high}`}
                    />
                    <div
                      className="w-full bg-yellow-400"
                      style={{
                        height: `${(point.medium / maxTrendValue) * 100}%`,
                        minHeight: point.medium > 0 ? '4px' : '0',
                      }}
                      title={`Medium: ${point.medium}`}
                    />
                    <div
                      className="w-full bg-blue-400 rounded-b"
                      style={{
                        height: `${(point.low / maxTrendValue) * 100}%`,
                        minHeight: point.low > 0 ? '4px' : '0',
                      }}
                      title={`Low: ${point.low}`}
                    />
                  </div>
                  <span className="text-xs text-slate-400 truncate w-full text-center">
                    {formatDate(point.date)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-slate-400">
              No trend data available
            </div>
          )}

          {/* Legend */}
          <div className="flex items-center justify-center gap-6 mt-4 pt-4 border-t border-slate-100">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-red-400 rounded" />
              <span className="text-sm text-slate-600">Critical</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-orange-400 rounded" />
              <span className="text-sm text-slate-600">High</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-yellow-400 rounded" />
              <span className="text-sm text-slate-600">Medium</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-blue-400 rounded" />
              <span className="text-sm text-slate-600">Low</span>
            </div>
          </div>
        </section>

        {/* Project Scores */}
        <section className="bg-white rounded-xl border border-slate-200 p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <Activity className="w-5 h-5 text-indigo-500" />
              <h2 className="text-lg font-bold text-slate-800">Project Security Scores</h2>
            </div>
          </div>

          <div className="space-y-4">
            {projectScores.map((project) => (
              <div
                key={project.projectId}
                className="flex items-center gap-4 p-4 bg-slate-50 rounded-lg border border-slate-100"
              >
                <div className="flex-1 min-w-0">
                  <h3 className="font-semibold text-slate-800 truncate">{project.projectName}</h3>
                  <div className="flex items-center gap-2 mt-1 text-sm text-slate-500">
                    <span>{project.totalFindings} findings</span>
                    {project.criticalCount > 0 && (
                      <span className="text-red-600">• {project.criticalCount} critical</span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="w-32 h-2 bg-slate-200 rounded-full overflow-hidden">
                    <div
                      className={cn(
                        "h-full rounded-full",
                        project.securityScore >= 80 ? "bg-emerald-500" :
                        project.securityScore >= 50 ? "bg-amber-500" : "bg-red-500"
                      )}
                      style={{ width: `${project.securityScore}%` }}
                    />
                  </div>
                  <span className={cn(
                    "text-sm font-bold w-12 text-right",
                    project.securityScore >= 80 ? "text-emerald-600" :
                    project.securityScore >= 50 ? "text-amber-600" : "text-red-600"
                  )}>
                    {project.securityScore.toFixed(0)}
                  </span>
                </div>
              </div>
            ))}

            {projectScores.length === 0 && (
              <p className="text-center text-slate-400 py-8">No project data available</p>
            )}
          </div>
        </section>

        {/* Summary Stats */}
        {summary && (
          <section className="grid grid-cols-3 gap-4">
            <div className="bg-white rounded-xl border border-slate-200 p-6 text-center">
              <FileText className="w-8 h-8 text-slate-400 mx-auto mb-2" />
              <p className="text-3xl font-bold text-slate-800">{summary.totalProjects}</p>
              <p className="text-sm text-slate-500">Total Projects</p>
            </div>

            <div className="bg-white rounded-xl border border-slate-200 p-6 text-center">
              <Activity className="w-8 h-8 text-slate-400 mx-auto mb-2" />
              <p className="text-3xl font-bold text-slate-800">{summary.totalScans}</p>
              <p className="text-sm text-slate-500">Total Scans</p>
            </div>

            <div className="bg-white rounded-xl border border-slate-200 p-6 text-center">
              <AlertTriangle className="w-8 h-8 text-slate-400 mx-auto mb-2" />
              <p className="text-3xl font-bold text-slate-800">{summary.totalFindings}</p>
              <p className="text-sm text-slate-500">Total Findings</p>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
