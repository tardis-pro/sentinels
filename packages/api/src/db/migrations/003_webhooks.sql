-- Webhooks migration: Inbound and outbound webhook infrastructure
-- Run this after the base schema (001_initial.sql)

-- Webhook configurations for outbound notifications
CREATE TABLE IF NOT EXISTS webhook_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    endpoint_url TEXT NOT NULL,
    secret TEXT, -- For HMAC signature verification/signing
    event_types TEXT[] NOT NULL DEFAULT '{}', -- Array of event types to send
    is_active BOOLEAN DEFAULT TRUE,
    retry_count INTEGER DEFAULT 3,
    retry_delay_seconds INTEGER DEFAULT 60,
    timeout_seconds INTEGER DEFAULT 30,
    created_by UUID NOT NULL, -- Would reference users table
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Inbound webhook installations (GitHub Apps, GitLab webhooks, etc.)
CREATE TABLE IF NOT EXISTS webhook_installations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider TEXT NOT NULL CHECK (provider IN ('github', 'gitlab', 'bitbucket')),
    installation_id TEXT NOT NULL, -- Provider-specific installation ID
    account_id TEXT, -- User/organization ID
    account_name TEXT,
    webhook_id TEXT, -- Provider's webhook ID
    webhook_secret TEXT, -- Secret for verifying incoming webhooks
    scope TEXT NOT NULL DEFAULT 'repo', -- repo, org, user
    permissions JSONB DEFAULT '{}', -- Provider-specific permissions
    events TEXT[] NOT NULL DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    installed_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(provider, installation_id)
);

-- Repositories linked to webhook installations
CREATE TABLE IF NOT EXISTS webhook_repo_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id UUID NOT NULL REFERENCES webhook_installations(id) ON DELETE CASCADE,
    repo_id TEXT NOT NULL, -- Provider-specific repo ID
    repo_name TEXT NOT NULL,
    repo_full_name TEXT,
    default_branch TEXT DEFAULT 'main',
    is_active BOOLEAN DEFAULT TRUE,
    linked_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(installation_id, repo_id)
);

-- Webhook event log (inbound)
CREATE TABLE IF NOT EXISTS webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id UUID REFERENCES webhook_installations(id) ON DELETE SET NULL,
    repo_link_id UUID REFERENCES webhook_repo_links(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    delivery_id TEXT NOT NULL, -- Provider's delivery ID
    payload JSONB NOT NULL,
    headers JSONB DEFAULT '{}',
    processing_status TEXT NOT NULL DEFAULT 'received' CHECK (processing_status IN ('received', 'processing', 'completed', 'failed', 'ignored')),
    error_message TEXT,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(delivery_id)
);

-- Indexes for webhook events
CREATE INDEX IF NOT EXISTS idx_webhook_events_installation ON webhook_events(installation_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_type ON webhook_events(event_type);
CREATE INDEX IF NOT EXISTS idx_webhook_events_status ON webhook_events(processing_status);
CREATE INDEX IF NOT EXISTS idx_webhook_events_created ON webhook_events(created_at);

-- Outbound webhook deliveries
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_config_id UUID NOT NULL REFERENCES webhook_configs(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'retrying')),
    attempts INTEGER DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ,
    response_status INTEGER,
    response_headers JSONB,
    response_body TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Indexes for webhook deliveries
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_config ON webhook_deliveries(webhook_config_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created ON webhook_deliveries(created_at);

-- Integration settings per project
CREATE TABLE IF NOT EXISTS project_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    integration_type TEXT NOT NULL CHECK (integration_type IN ('github', 'gitlab', 'bitbucket', 'jira', 'slack', 'pagerduty')),
    config JSONB NOT NULL, -- Encrypted credentials and settings
    auto_scan BOOLEAN DEFAULT FALSE, -- Auto-scan on push/PR
    scan_on_pr BOOLEAN DEFAULT TRUE,
    scan_on_push BOOLEAN DEFAULT FALSE,
    branch_pattern TEXT DEFAULT '.*', -- Regex for branches to scan
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(project_id, integration_type)
);

-- SLA policies for scan scheduling
CREATE TABLE IF NOT EXISTS scan_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    cron_expression TEXT NOT NULL,
    timezone TEXT DEFAULT 'UTC',
    scanners TEXT[] NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for schedules
CREATE INDEX IF NOT EXISTS idx_scan_schedules_project ON scan_schedules(project_id);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_next_run ON scan_schedules(next_run_at) WHERE is_active = TRUE;

-- Function to calculate next run time from cron
CREATE OR REPLACE FUNCTION calculate_next_run(cron_expr TEXT, timezone TEXT DEFAULT 'UTC')
RETURNS TIMESTAMPTZ AS $$
BEGIN
    -- Simplified cron parsing (full implementation would use a cron library)
    -- This is a placeholder that would need proper cron library integration
    RETURN NOW() + INTERVAL '1 day';
END;
$$ LANGUAGE plpgsql;

-- Function to update schedule next_run_at
CREATE OR REPLACE FUNCTION update_schedule_next_run()
RETURNS TRIGGER AS $$
BEGIN
    NEW.next_run_at = calculate_next_run(NEW.cron_expression, NEW.timezone);
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_schedule_next_run
    BEFORE UPDATE ON scan_schedules
    FOR EACH ROW
    WHEN (OLD.is_active IS TRUE AND (OLD.cron_expression IS DISTINCT FROM NEW.cron_expression OR OLD.timezone IS DISTINCT FROM NEW.timezone))
    EXECUTE FUNCTION update_schedule_next_run();

-- Webhook event types enum
DO $$
BEGIN
    CREATE TYPE webhook_event_type AS ENUM (
        'scan.completed',
        'scan.failed',
        'scan.started',
        'finding.critical',
        'finding.high',
        'finding.new',
        'finding.resolved',
        'project.created',
        'project.deleted'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Sample outbound webhook configurations
INSERT INTO webhook_configs (name, description, endpoint_url, secret, event_types, created_by) VALUES
    ('Slack Notifications', 'Send security alerts to Slack', 'https://hooks.slack.com/services/xxx/yyy/zzz', 'webhook_secret', ARRAY['finding.critical', 'finding.high', 'scan.completed', 'scan.failed'], 'system'),
    ('PagerDuty Alerts', 'Create PagerDuty incidents for critical findings', 'https://events.pagerduty.com/v2/enqueue', 'pagerduty_api_key', ARRAY['finding.critical'], 'system')
ON CONFLICT DO NOTHING;

PRINT 'Webhooks migration completed successfully';
