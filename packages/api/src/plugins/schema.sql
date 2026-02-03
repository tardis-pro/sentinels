-- Plugin Framework Database Schema
-- Tables for plugin registry, configurations, and execution tracking

-- Plugin registry table
CREATE TABLE IF NOT EXISTS plugins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  description TEXT,
  type VARCHAR(20) NOT NULL,
  author TEXT,
  license TEXT,
  repository TEXT,
  tags TEXT[] DEFAULT '{}',
  source_url TEXT,
  checksum TEXT,
  permissions JSONB DEFAULT '{}',
  is_active BOOLEAN DEFAULT true,
  installed_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_plugins_type ON plugins(type);
CREATE INDEX IF NOT EXISTS idx_plugins_tags ON plugins USING GIN(tags);

-- Plugin configurations (user settings)
CREATE TABLE IF NOT EXISTS plugin_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  plugin_id UUID REFERENCES plugins(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  settings JSONB DEFAULT '{}',
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_plugin_configs_plugin ON plugin_configs(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_configs_project ON plugin_configs(project_id);

-- Plugin execution history
CREATE TABLE IF NOT EXISTS plugin_executions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  plugin_id UUID REFERENCES plugins(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  config JSONB DEFAULT '{}',
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  findings_count INT DEFAULT 0,
  duration_ms INT,
  error_log TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_plugin_executions_plugin ON plugin_executions(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_executions_scan ON plugin_executions(scan_id);

-- Plugin marketplace cache (for community plugins)
CREATE TABLE IF NOT EXISTS marketplace_plugins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  registry_url TEXT NOT NULL,
  plugin_data JSONB NOT NULL,
  last_updated TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_marketplace_plugins ON marketplace_plugins(registry_url);
