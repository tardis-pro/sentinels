-- Analytics migration: Add tables for dashboard and reporting
-- Run this after the base schema (001_initial.sql)

-- Analytics events table for tracking metrics over time
CREATE TABLE IF NOT EXISTS analytics_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL, -- 'finding', 'scan', 'project', 'user'
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    metric_name TEXT NOT NULL,
    metric_value NUMERIC,
    dimensions JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for analytics queries
CREATE INDEX IF NOT EXISTS idx_analytics_events_type ON analytics_events(event_type);
CREATE INDEX IF NOT EXISTS idx_analytics_events_project ON analytics_events(project_id);
CREATE INDEX IF NOT EXISTS idx_analytics_events_created ON analytics_events(created_at);
CREATE INDEX IF NOT EXISTS idx_analytics_events_metric ON analytics_events(metric_name, created_at);

-- Materialized view for daily findings summary (refreshable)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_daily_findings AS
SELECT 
    DATE(created_at) as date,
    severity,
    COUNT(*) as count,
    COUNT(DISTINCT project_id) as affected_projects,
    COUNT(DISTINCT scan_id) as scans_run
FROM findings
GROUP BY DATE(created_at), severity
ORDER BY date DESC;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_daily_findings_date_sev 
ON mv_daily_findings(date, severity);

-- Materialized view for project security scores
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_project_scores AS
SELECT 
    p.id as project_id,
    p.name as project_name,
    COUNT(f.id) as total_findings,
    COUNT(f.id) FILTER (WHERE f.severity = 'CRITICAL') as critical_count,
    COUNT(f.id) FILTER (WHERE f.severity = 'HIGH') as high_count,
    COUNT(f.id) FILTER (WHERE f.severity = 'MEDIUM') as medium_count,
    COUNT(f.id) FILTER (WHERE f.severity = 'LOW') as low_count,
    COALESCE(
        100 - (COUNT(f.id) FILTER (WHERE f.severity IN ('CRITICAL', 'HIGH')) * 10)::NUMERIC,
        100
    ) as security_score,
    MAX(f.created_at) as last_finding_at,
    COUNT(DISTINCT s.id) as total_scans
FROM projects p
LEFT JOIN findings f ON f.project_id = p.id
LEFT JOIN scans s ON s.project_id = p.id
GROUP BY p.id, p.name;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_project_scores_project 
ON mv_project_scores(project_id);

-- Materialized view for scanner performance
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_scanner_performance AS
SELECT 
    sr.scanner_name,
    COUNT(sr.id) as total_runs,
    COUNT(sr.id) FILTER (WHERE sr.status = 'completed') as successful_runs,
    COUNT(sr.id) FILTER (WHERE sr.status = 'failed') as failed_runs,
    AVG(EXTRACT(EPOCH FROM (sr.completed_at - sr.started_at))) as avg_duration_seconds,
    SUM(sr.findings_count) as total_findings,
    AVG(sr.findings_count) as avg_findings_per_scan
FROM scan_runs sr
GROUP BY sr.scanner_name;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_scanner_performance_name 
ON mv_scanner_performance(scanner_name);

-- Compliance framework mapping table
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE, -- 'OWASP Top 10', 'PCI-DSS', 'SOC 2'
    description TEXT,
    version TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Finding to compliance mapping
CREATE TABLE IF NOT EXISTS finding_compliance_mapping (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_rule_pattern TEXT NOT NULL, -- Pattern to match rule_id
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id),
    control_id TEXT NOT NULL, -- e.g., 'A1:2017-Injection'
    control_name TEXT,
    severity_weight INTEGER DEFAULT 1, -- For scoring
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(finding_rule_pattern, framework_id)
);

-- Scheduled reports configuration
CREATE TABLE IF NOT EXISTS scheduled_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    report_type TEXT NOT NULL, -- 'summary', 'trends', 'compliance', 'custom'
    schedule_cron TEXT NOT NULL, -- Cron expression
    recipients TEXT[] NOT NULL, -- Email addresses
    filters JSONB DEFAULT '{}', -- {projectIds: [], severity: [], etc}
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID NOT NULL, -- Would reference users table
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Report history
CREATE TABLE IF NOT EXISTS report_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL REFERENCES scheduled_reports(id),
    status TEXT NOT NULL, -- 'generating', 'completed', 'failed'
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    file_path TEXT, -- Path to generated report
    record_count INTEGER,
    error_message TEXT
);

-- Function to refresh analytics materialized views
CREATE OR REPLACE FUNCTION refresh_analytics_views()
RETURNS VOID AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_daily_findings;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_project_scores;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_scanner_performance;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate project security score
CREATE OR REPLACE FUNCTION calculate_project_security_score(project_uuid UUID)
RETURNS NUMERIC AS $$
DECLARE
    score NUMERIC;
    critical_count INTEGER;
    high_count INTEGER;
    total_count INTEGER;
BEGIN
    SELECT 
        COUNT(*) FILTER (WHERE severity = 'CRITICAL'),
        COUNT(*) FILTER (WHERE severity = 'HIGH'),
        COUNT(*)
    INTO critical_count, high_count, total_count
    FROM findings 
    WHERE project_id = project_uuid;

    IF total_count = 0 THEN
        RETURN 100;
    END IF;

    -- Score calculation: Start at 100, deduct 25 for critical, 10 for high
    score := 100 - (critical_count * 25) - (high_count * 10);
    RETURN GREATEST(0, LEAST(100, score));
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Insert default compliance frameworks
INSERT INTO compliance_frameworks (name, description, version) VALUES
    ('OWASP Top 10', 'OWASP Top 10 Web Application Security Risks', '2021'),
    ('PCI-DSS', 'Payment Card Industry Data Security Standard', '4.0'),
    ('SOC 2', 'Service Organization Control 2 Trust Services Criteria', '2017')
ON CONFLICT (name) DO NOTHING;

-- Insert sample compliance mappings
INSERT INTO finding_compliance_mapping (finding_rule_pattern, framework_id, control_id, control_name, severity_weight) SELECT 
    'sql|Injection|injection',
    id,
    'A1:2017-Injection',
    'Injection',
    3
FROM compliance_frameworks WHERE name = 'OWASP Top 10'
ON CONFLICT (finding_rule_pattern, framework_id) DO NOTHING;

INSERT INTO finding_compliance_mapping (finding_rule_pattern, framework_id, control_id, control_name, severity_weight) SELECT 
    'xss|cross-site|cross site',
    id,
    'A3:2017-Cross-Site Scripting (XSS)',
    'Cross-Site Scripting',
    2
FROM compliance_frameworks WHERE name = 'OWASP Top 10'
ON CONFLICT (finding_rule_pattern, framework_id) DO NOTHING;

-- Insert sample finding compliance mappings for other rule patterns
INSERT INTO finding_compliance_mapping (finding_rule_pattern, framework_id, control_id, control_name, severity_weight) SELECT 
    'secret|api.key|token|password|credential',
    id,
    'A2:2017-Broken Authentication',
    'Broken Authentication',
    3
FROM compliance_frameworks WHERE name = 'OWASP Top 10'
ON CONFLICT (finding_rule_pattern, framework_id) DO NOTHING;

INSERT INTO finding_compliance_mapping (finding_rule_pattern, framework_id, control_id, control_name, severity_weight) SELECT 
    'xxe|xml.external',
    id,
    'A4:2017-XML External Entities (XXE)',
    'XML External Entities',
    3
FROM compliance_frameworks WHERE name = 'OWASP Top 10'
ON CONFLICT (finding_rule_pattern, framework_id) DO NOTHING;

INSERT INTO finding_compliance_mapping (finding_rule_pattern, framework_id, control_id, control_name, severity_weight) SELECT 
    'broken.*access|idor|path.traversal',
    id,
    'A5:2017-Broken Access Control',
    'Broken Access Control',
    3
FROM compliance_frameworks WHERE name = 'OWASP Top 10'
ON CONFLICT (finding_rule_pattern, framework_id) DO NOTHING;

PRINT 'Analytics migration completed successfully';
