import { Client } from 'pg';

const client = new Client({
  connectionString: process.env.DATABASE_URL || 'postgres://sentinel:sentinel@localhost:35432/sentinel',
});

interface DateRange {
  start?: string;
  end?: string;
}

interface AnalyticsSummary {
  totalProjects: number;
  totalScans: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  securityPostureScore: number;
  avgMttd: number; // Mean time to detect in hours
  avgMttr: number; // Mean time to remediate in hours
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

interface ScannerPerformance {
  scannerName: string;
  totalRuns: number;
  successfulRuns: number;
  failedRuns: number;
  avgDurationSeconds: number;
  totalFindings: number;
}

interface ComplianceSummary {
  framework: string;
  compliantFindings: number;
  nonCompliantFindings: number;
  compliancePercentage: number;
  topControls: { id: string; name: string; findings: number }[];
}

export async function connectAnalyticsDb() {
  await client.connect();
  console.log('Connected to PostgreSQL for analytics');
}

export async function getAnalyticsSummary(projectId?: string, dateRange?: DateRange): Promise<AnalyticsSummary> {
  const query = `
    SELECT
      (SELECT COUNT(*) FROM projects) as total_projects,
      (SELECT COUNT(*) FROM scans WHERE status = 'completed') as total_scans,
      (SELECT COUNT(*) FROM findings ${
        projectId ? "WHERE scan_id IN (SELECT id FROM scans WHERE project_id = $4)" : ''
      }) as total_findings,
      (SELECT COUNT(*) FROM findings WHERE severity = 'CRITICAL' ${
        projectId ? "AND scan_id IN (SELECT id FROM scans WHERE project_id = $4)" : ''
      }) as critical_count,
      (SELECT COUNT(*) FROM findings WHERE severity = 'HIGH' ${
        projectId ? "AND scan_id IN (SELECT id FROM scans WHERE project_id = $4)" : ''
      }) as high_count,
      (SELECT COUNT(*) FROM findings WHERE severity = 'MEDIUM' ${
        projectId ? "AND scan_id IN (SELECT id FROM scans WHERE project_id = $4)" : ''
      }) as medium_count,
      (SELECT COUNT(*) FROM findings WHERE severity = 'LOW' ${
        projectId ? "AND scan_id IN (SELECT id FROM scans WHERE project_id = $4)" : ''
      }) as low_count
  `;

  const result = await client.query(query, projectId ? [projectId] : []);
  const row = result.rows[0];

  const criticalCount = parseInt(row.critical_count);
  const highCount = parseInt(row.high_count);
  const totalFindings = parseInt(row.total_findings);

  // Calculate security posture score (0-100)
  let securityScore = 100;
  if (totalFindings > 0) {
    securityScore = 100 - (criticalCount * 25) - (highCount * 10);
    securityScore = Math.max(0, Math.min(100, securityScore));
  }

  return {
    totalProjects: parseInt(row.total_projects) || 0,
    totalScans: parseInt(row.total_scans) || 0,
    totalFindings,
    criticalCount,
    highCount,
    mediumCount: parseInt(row.medium_count) || 0,
    lowCount: parseInt(row.low_count) || 0,
    securityPostureScore: Math.round(securityScore * 10) / 10,
    avgMttd: 0, // Would require additional tracking
    avgMttr: 0, // Would require resolution tracking
  };
}

export async function getFindingTrends(
  interval: 'day' | 'week' | 'month' = 'day',
  dateRange?: DateRange,
  projectId?: string
): Promise<TrendDataPoint[]> {
  let groupFormat: string;
  switch (interval) {
    case 'day':
      groupFormat = "DATE(created_at)";
      break;
    case 'week':
      groupFormat = "DATE_TRUNC('week', created_at)";
      break;
    case 'month':
      groupFormat = "DATE_TRUNC('month', created_at)";
      break;
  }

  let query = `
    SELECT
      ${groupFormat} as date,
      COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical,
      COUNT(*) FILTER (WHERE severity = 'HIGH') as high,
      COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium,
      COUNT(*) FILTER (WHERE severity = 'LOW') as low,
      COUNT(*) as total
    FROM findings
  `;

  const params: (string | number | boolean)[] = [];

  if (projectId || dateRange?.start || dateRange?.end) {
    const conditions: string[] = [];

    if (projectId) {
      conditions.push(`scan_id IN (SELECT id FROM scans WHERE project_id = $${params.length + 1})`);
      params.push(projectId);
    }

    if (dateRange?.start) {
      conditions.push(`created_at >= $${params.length + 1}`);
      params.push(dateRange.start);
    }

    if (dateRange?.end) {
      conditions.push(`created_at <= $${params.length + 1}`);
      params.push(dateRange.end);
    }

    query += ` WHERE ${conditions.join(' AND ')}`;
  }

  query += ` GROUP BY ${groupFormat} ORDER BY date DESC LIMIT 90`;

  const result = await client.query(query, params);

  return result.rows.map(row => ({
    date: row.date instanceof Date ? row.date.toISOString().split('T')[0] : String(row.date),
    critical: parseInt(row.critical) || 0,
    high: parseInt(row.high) || 0,
    medium: parseInt(row.medium) || 0,
    low: parseInt(row.low) || 0,
    total: parseInt(row.total) || 0,
  })).reverse();
}

export async function getProjectScores(limit: number = 10): Promise<ProjectScore[]> {
  const result = await client.query(
    `SELECT * FROM mv_project_scores ORDER BY security_score ASC LIMIT $1`,
    [limit]
  );

  return result.rows.map(row => ({
    projectId: row.project_id,
    projectName: row.project_name,
    securityScore: parseFloat(row.security_score) || 0,
    totalFindings: parseInt(row.total_findings) || 0,
    criticalCount: parseInt(row.critical_count) || 0,
    highCount: parseInt(row.high_count) || 0,
    lastFindingAt: row.last_finding_at ? String(row.last_finding_at) : null,
  }));
}

export async function getScannerPerformance(): Promise<ScannerPerformance[]> {
  const result = await client.query('SELECT * FROM mv_scanner_performance');

  return result.rows.map(row => ({
    scannerName: row.scanner_name,
    totalRuns: parseInt(row.total_runs) || 0,
    successfulRuns: parseInt(row.successful_runs) || 0,
    failedRuns: parseInt(row.failed_runs) || 0,
    avgDurationSeconds: parseFloat(row.avg_duration_seconds) || 0,
    totalFindings: parseInt(row.total_findings) || 0,
  }));
}

export async function getComplianceSummary(
  framework: string = 'OWASP Top 10'
): Promise<ComplianceSummary> {
  const frameworkResult = await client.query(
    'SELECT id FROM compliance_frameworks WHERE name = $1',
    [framework]
  );

  if (frameworkResult.rows.length === 0) {
    return {
      framework,
      compliantFindings: 0,
      nonCompliantFindings: 0,
      compliancePercentage: 100,
      topControls: [],
    };
  }

  const frameworkId = frameworkResult.rows[0].id;

  // Get total findings
  const totalResult = await client.query('SELECT COUNT(*) as total FROM findings');
  const totalFindings = parseInt(totalResult.rows[0].total) || 0;

  // Get findings with compliance mapping
  const mappedResult = await client.query(
    `SELECT COUNT(DISTINCT f.id) as mapped
     FROM findings f
     JOIN finding_compliance_mapping m ON f.rule_id ~ m.finding_rule_pattern
     WHERE m.framework_id = $1`,
    [frameworkId]
  );

  const mappedFindings = parseInt(mappedResult.rows[0].mapped) || 0;

  // Get top failing controls
  const topControlsResult = await client.query(
    `SELECT 
        m.control_id,
        m.control_name,
        COUNT(f.id) as findings_count
     FROM finding_compliance_mapping m
     LEFT JOIN findings f ON f.rule_id ~ m.finding_rule_pattern
     WHERE m.framework_id = $1
     GROUP BY m.control_id, m.control_name
     ORDER BY findings_count DESC
     LIMIT 5`,
    [frameworkId]
  );

  const topControls = topControlsResult.rows.map(row => ({
    id: row.control_id,
    name: row.control_name,
    findings: parseInt(row.findings_count) || 0,
  }));

  const compliancePercentage = totalFindings > 0
    ? Math.round((mappedFindings / totalFindings) * 100)
    : 100;

  return {
    framework,
    compliantFindings: mappedFindings,
    nonCompliantFindings: totalFindings - mappedFindings,
    compliancePercentage,
    topControls,
  };
}

export async function refreshMaterializedViews(): Promise<void> {
  await client.query('SELECT refresh_analytics_views()');
}

export async function trackAnalyticsEvent(
  eventType: string,
  projectId: string | null,
  scanId: string | null,
  metricName: string,
  metricValue: number,
  dimensions: Record<string, any> = {}
): Promise<void> {
  await client.query(
    `INSERT INTO analytics_events 
     (event_type, project_id, scan_id, metric_name, metric_value, dimensions)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [eventType, projectId, scanId, metricName, metricValue, JSON.stringify(dimensions)]
  );
}

export async function getSecurityPostureHistory(
  days: number = 30
): Promise<{ date: string; score: number }[]> {
  const result = await client.query(
    `SELECT 
        DATE(created_at) as date,
        AVG(
          100 - 
          (COUNT(*) FILTER (WHERE severity = 'CRITICAL') * 25) - 
          (COUNT(*) FILTER (WHERE severity = 'HIGH') * 10)
        ) as score
     FROM findings
     WHERE created_at >= NOW() - INTERVAL '${days} days'
     GROUP BY DATE(created_at)
     ORDER BY date DESC`,
    []
  );

  return result.rows.map(row => ({
    date: row.date instanceof Date ? row.date.toISOString().split('T')[0] : String(row.date),
    score: Math.round((parseFloat(row.score) || 100) * 10) / 10,
  })).reverse();
}

export async function getFindingDensityByType(): Promise<{ type: string; count: number }[]> {
  const result = await client.query(
    `SELECT 
        CASE 
          WHEN scanner_name = 'trivy' THEN 'SCA/Container'
          WHEN scanner_name = 'semgrep' THEN 'SAST'
          WHEN scanner_name = 'bandit' THEN 'Python Security'
          WHEN scanner_name = 'clair' THEN 'Container Vuln'
          WHEN scanner_name = 'sonarqube' THEN 'Code Quality'
          ELSE scanner_name
        END as type,
        COUNT(*) as count
     FROM findings
     GROUP BY scanner_name
     ORDER BY count DESC`
  );

  return result.rows.map(row => ({
    type: row.type,
    count: parseInt(row.count) || 0,
  }));
}

export async function getRemediationVelocity(
  days: number = 30
): Promise<{ week: string; opened: number; closed: number }[]> {
  const result = await client.query(
    `WITH opened AS (
        SELECT DATE_TRUNC('week', created_at) as week, COUNT(*) as count
        FROM findings
        WHERE created_at >= NOW() - INTERVAL '${days} days'
        GROUP BY week
    ),
    closed AS (
        SELECT DATE_TRUNC('week', closed_at) as week, COUNT(*) as count
        FROM findings
        WHERE closed_at IS NOT NULL AND closed_at >= NOW() - INTERVAL '${days} days'
        GROUP BY week
    )
    SELECT 
        COALESCE(o.week, c.week) as week,
        COALESCE(o.count, 0) as opened,
        COALESCE(c.count, 0) as closed
    FROM opened o
    FULL OUTER JOIN closed c ON o.week = c.week
    ORDER BY week`
  );

  return result.rows.map(row => ({
    week: row.week instanceof Date ? row.week.toISOString().split('T')[0] : String(row.week),
    opened: parseInt(row.opened) || 0,
    closed: parseInt(row.closed) || 0,
  }));
}
