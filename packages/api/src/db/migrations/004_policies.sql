-- ============================================================================
-- Policy Engine Database Schema
-- Purpose: Stores policies, compliance frameworks, and evaluation results
-- ============================================================================

-- Policies table - stores security and compliance policies with OPA/Rego rules
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(50) NOT NULL CHECK (category IN ('security', 'compliance', 'operational', 'custom')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    rego_policy TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    enforcement_action VARCHAR(20) NOT NULL CHECK (enforcement_action IN ('block', 'warn', 'notify', 'log')),
    tags JSONB DEFAULT '[]'::jsonb,
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT unique_policy_name UNIQUE (name, COALESCE(project_id, '00000000-0000-0000-0000-000000000000'))
);

-- Policy rules table - individual rules within policies
CREATE TABLE IF NOT EXISTS policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    rego_rule TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT unique_rule_name UNIQUE (policy_id, name)
);

-- Policy evaluation results - stores evaluation history
CREATE TABLE IF NOT EXISTS policy_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    passed BOOLEAN NOT NULL,
    violations JSONB DEFAULT '[]'::jsonb,
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT unique_finding_policy UNIQUE (finding_id, policy_id)
);

-- Policy enforcement actions - tracks enforcement actions taken
CREATE TABLE IF NOT EXISTS policy_enforcements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evaluation_id UUID NOT NULL REFERENCES policy_evaluations(id) ON DELETE CASCADE,
    action VARCHAR(20) NOT NULL CHECK (action IN ('block', 'warn', 'notify', 'log')),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'dismissed', 'overridden')),
    applied_by UUID REFERENCES users(id) ON DELETE SET NULL,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notes TEXT,
    
    CONSTRAINT unique_evaluation_action UNIQUE (evaluation_id, action)
);

-- Compliance frameworks table
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    version VARCHAR(50) DEFAULT '1.0',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Compliance controls - maps policies to compliance requirements
CREATE TABLE IF NOT EXISTS compliance_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_id VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    policy_ids JSONB DEFAULT '[]'::jsonb,
    requirements TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT unique_control_id UNIQUE (framework_id, control_id)
);

-- Policy tags - flexible tagging system for policies
CREATE TABLE IF NOT EXISTS policy_tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    tag_key VARCHAR(100) NOT NULL,
    tag_value TEXT NOT NULL,
    
    CONSTRAINT unique_policy_tag UNIQUE (policy_id, tag_key)
);

-- ============================================================================
-- Indexes for performance
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_policies_category ON policies(category);
CREATE INDEX IF NOT EXISTS idx_policies_severity ON policies(severity);
CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
CREATE INDEX IF NOT EXISTS idx_policies_project ON policies(project_id);
CREATE INDEX IF NOT EXISTS idx_policies_created ON policies(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_policy_rules_policy ON policy_rules(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_rules_enabled ON policy_rules(enabled);

CREATE INDEX IF NOT EXISTS idx_evaluations_finding ON policy_evaluations(finding_id);
CREATE INDEX IF NOT EXISTS idx_evaluations_policy ON policy_evaluations(policy_id);
CREATE INDEX IF NOT EXISTS idx_evaluations_passed ON policy_evaluations(passed);
CREATE INDEX IF NOT EXISTS idx_evaluations_date ON policy_evaluations(evaluated_at DESC);

CREATE INDEX IF NOT EXISTS idx_controls_framework ON compliance_controls(framework_id);
CREATE INDEX IF NOT EXISTS idx_controls_policy ON compliance_controls(policy_ids);

CREATE INDEX IF NOT EXISTS idx_policy_tags_policy ON policy_tags(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_tags_key ON policy_tags(tag_key);

-- ============================================================================
-- Functions
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to auto-update updated_at on policies
DROP TRIGGER IF EXISTS update_policies_updated_at ON policies;
CREATE TRIGGER update_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger to auto-update updated_at on compliance_frameworks
DROP TRIGGER IF EXISTS update_frameworks_updated_at ON compliance_frameworks;
CREATE TRIGGER update_frameworks_updated_at
    BEFORE UPDATE ON compliance_frameworks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Materialized Views for Policy Analytics
-- ============================================================================

-- Policy compliance summary by project
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_policy_compliance AS
SELECT 
    p.project_id,
    pr.name AS project_name,
    p.category,
    p.severity,
    COUNT(DISTINCT p.id) AS total_policies,
    COUNT(DISTINCT pe.id) FILTER (WHERE pe.passed = true) AS passing_evaluations,
    COUNT(DISTINCT pe.id) FILTER (WHERE pe.passed = false) AS failing_evaluations,
    CASE 
        WHEN COUNT(DISTINCT pe.id) > 0 
        THEN ROUND((COUNT(DISTINCT pe.id) FILTER (WHERE pe.passed = true)::numeric / COUNT(DISTINCT pe.id)) * 100, 2)
        ELSE 100 
    END AS compliance_percentage,
    NOW() AS last_refreshed
FROM policies p
LEFT JOIN projects pr ON p.project_id = pr.id
LEFT JOIN policy_evaluations pe ON p.id = pe.policy_id
GROUP BY p.project_id, pr.name, p.category, p.severity;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_policy_compliance ON mv_policy_compliance(project_id, category, severity);

-- Policy violation trends
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_policy_violations AS
SELECT 
    DATE_TRUNC('day', pe.evaluated_at)::date AS date,
    p.category,
    p.severity,
    p.enforcement_action,
    COUNT(pe.id) AS violation_count,
    COUNT(DISTINCT pe.finding_id) AS unique_findings
FROM policy_evaluations pe
JOIN policies p ON pe.policy_id = p.id
WHERE pe.passed = false
GROUP BY DATE_TRUNC('day', pe.evaluated_at)::date, p.category, p.severity, p.enforcement_action
ORDER BY date DESC;

CREATE INDEX IF NOT EXISTS idx_mv_policy_violations_date ON mv_policy_violations(date DESC);

-- ============================================================================
-- Views for easier querying
-- ============================================================================

-- View: Active policies with their rules
CREATE OR REPLACE VIEW v_active_policies AS
SELECT 
    p.*,
    COUNT(pr.id) AS rule_count
FROM policies p
LEFT JOIN policy_rules pr ON p.id = pr.policy_id AND pr.enabled = true
WHERE p.enabled = true
GROUP BY p.id;

-- View: Policy evaluation summary by finding
CREATE OR REPLACE VIEW v_finding_policy_status AS
SELECT 
    f.*,
    COUNT(pe.id) AS total_evaluations,
    COUNT(pe.id) FILTER (WHERE pe.passed = true) AS passing_checks,
    COUNT(pe.id) FILTER (WHERE pe.passed = false) AS failing_checks,
    CASE 
        WHEN COUNT(pe.id) FILTER (WHERE pe.passed = false) > 0 THEN 'non-compliant'
        WHEN COUNT(pe.id) > 0 THEN 'compliant'
        ELSE 'pending'
    END AS compliance_status
FROM findings f
LEFT JOIN policy_evaluations pe ON f.id = pe.finding_id
GROUP BY f.id;

-- View: Compliance framework coverage
CREATE OR REPLACE VIEW v_framework_coverage AS
SELECT 
    cf.id AS framework_id,
    cf.name AS framework_name,
    cf.description,
    COUNT(cc.id) AS total_controls,
    COUNT(cc.id) FILTER (
        EXISTS (
            SELECT 1 FROM unnest(cc.policy_ids) AS pid
            JOIN policies p ON p.id = pid::uuid
            WHERE p.enabled = true
        )
    ) AS mapped_controls,
    COUNT(cc.id) FILTER (
        NOT EXISTS (
            SELECT 1 FROM unnest(cc.policy_ids) AS pid
            JOIN policies p ON p.id = pid::uuid
            WHERE p.enabled = true
        )
    ) AS unmapped_controls
FROM compliance_frameworks cf
LEFT JOIN compliance_controls cc ON cf.id = cc.framework_id
GROUP BY cf.id, cf.name, cf.description;

-- ============================================================================
-- Seed Data: Built-in Policy Templates
-- ============================================================================

-- Insert built-in security policies
INSERT INTO policies (name, description, category, severity, rego_policy, enabled, enforcement_action, tags)
VALUES 
    ('Critical Vulnerability Block', 'Block deployments with critical severity vulnerabilities', 
     'security', 'CRITICAL', 
     '# Critical Vulnerability Policy
package sentinel.critical_vuln

deny[msg] {
  input.finding.severity == "CRITICAL"
  msg := "Critical severity vulnerability detected - deployment blocked"
}', true, 'block', '["security", "critical", "deployment"]'),
     
    ('High Severity Warning', 'Warn on high severity vulnerabilities',
     'security', 'HIGH',
     '# High Severity Warning Policy
package sentinel.high_severity

deny[msg] {
  input.finding.severity == "HIGH"
  msg := "High severity vulnerability requires attention"
}', true, 'warn', '["security", "high", "warning"]'),
     
    ('Secret Scanning Policy', 'Block any secrets detected in code',
     'security', 'CRITICAL',
     '# Secret Scanning Policy
package sentinel.secret_scanning

deny[msg] {
  input.finding.type == "secret"
  msg := "Exposed secret detected - immediate remediation required"
}', true, 'block', '["security", "secret", "credential"]'),
     
    ('Production Environment Strict', 'Apply stricter controls in production',
     'compliance', 'HIGH',
     '# Production Environment Policy
package sentinel.production

deny[msg] {
  input.context.environment == "production"
  input.finding.severity in ["CRITICAL", "HIGH"]
  msg := "High/Critical findings not allowed in production"
}', true, 'block', '["compliance", "production", "environment"]'),
     
    ('License Compliance', 'Ensure license compliance for dependencies',
     'compliance', 'MEDIUM',
     '# License Compliance Policy
package sentinel.license

deny[msg] {
  input.finding.type == "license"
  input.finding.tags.license_type in ["GPL-3.0", "AGPL-3.0", "SSPL"]
  msg := "Prohibited license detected - review required"
}', true, 'warn', '["compliance", "license", "dependency"]')
ON CONFLICT (name, COALESCE(project_id, '00000000-0000-0000-0000-000000000000')) DO NOTHING;

-- Seed common compliance frameworks
INSERT INTO compliance_frameworks (name, description)
VALUES 
    ('OWASP Top 10', 'OWASP Top 10 security risks and best practices'),
    ('PCI-DSS', 'Payment Card Industry Data Security Standard'),
    ('SOC 2', 'Service Organization Control 2 compliance'),
    ('HIPAA', 'Health Insurance Portability and Accountability Act'),
    ('GDPR', 'General Data Protection Regulation')
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- Comments for documentation
-- ============================================================================

COMMENT ON TABLE policies IS 'Stores security and compliance policies with OPA/Rego policy definitions';
COMMENT ON TABLE policy_rules IS 'Individual rules within policies for granular control';
COMMENT ON TABLE policy_evaluations IS 'Historical record of policy evaluations against findings';
COMMENT ON TABLE policy_enforcements IS 'Tracks enforcement actions taken based on policy violations';
COMMENT ON TABLE compliance_frameworks IS 'Compliance frameworks (OWASP, PCI-DSS, etc.)';
COMMENT ON TABLE compliance_controls IS 'Controls mapped to compliance frameworks';
COMMENT ON TABLE policy_tags IS 'Flexible tagging system for policy organization';

COMMENT ON COLUMN policies.rego_policy IS 'OPA/Rego policy code for policy evaluation';
COMMENT ON COLUMN policies.enforcement_action IS 'Action to take when policy is violated: block, warn, notify, or log';
COMMENT ON COLUMN policies.category IS 'Policy category: security, compliance, operational, or custom';
