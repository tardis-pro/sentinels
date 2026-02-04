/**
 * Plugin Framework Types
 * Defines interfaces for scanner plugins, parsers, and enrichers
 */

export type PluginType = 'scanner' | 'parser' | 'enrichment' | 'notification' | 'report';

export interface PluginMetadata {
  id: string;
  name: string;
  version: string;
  description: string;
  type: PluginType;
  author: string;
  license?: string;
  repository?: string;
  tags: string[];
}

export interface ScannerPlugin extends PluginMetadata {
  type: 'scanner';
  supportedLanguages: string[];
  scannerTypes: ('sast' | 'sca' | 'secret' | 'container' | 'infra')[];
  
  execute(config: ScanConfig): Promise<ScanResult>;
  healthCheck(): Promise<HealthStatus>;
}

export interface ParserPlugin extends PluginMetadata {
  type: 'parser';
  supportedFormats: string[];
  
  parse(rawOutput: any): Promise<UnifiedFinding[]>;
  validate(rawOutput: any): boolean;
}

export interface EnrichmentPlugin extends PluginMetadata {
  type: 'enrichment';
  
  enrich(finding: UnifiedFinding): Promise<EnrichedFinding>;
}

export interface NotificationPlugin extends PluginMetadata {
  type: 'notification';
  supportedChannels: string[];
  
  send(notification: Notification): Promise<void>;
}

export interface ReportPlugin extends PluginMetadata {
  type: 'report';
  supportedFormats: string[];
  
  generate(report: ReportRequest): Promise<ReportResult>;
}

export interface ScanConfig {
  targetPath: string;
  config?: Record<string, any>;
  timeout?: number;
  environment?: Record<string, string>;
}

export interface ScanResult {
  findings: UnifiedFinding[];
  metrics: ScanMetrics;
  errors?: string[];
}

export interface ScanMetrics {
  duration: number;
  filesScanned: number;
  findingsCount: number;
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  message?: string;
  details?: Record<string, any>;
}

export interface UnifiedFinding {
  scanner_name: string;
  rule_id: string;
  severity: string;
  file_path: string;
  start_line?: number;
  end_line?: number;
  title: string;
  description?: string;
  remediation?: string;
  raw_data?: any;
}

export interface EnrichedFinding extends UnifiedFinding {
  enriched_data: Record<string, any>;
  cve_ids?: string[];
  cwe_ids?: string[];
}

export interface Notification {
  channel: string;
  recipients?: string[];
  subject: string;
  body: string;
  priority?: 'low' | 'normal' | 'high' | 'critical';
  attachments?: Attachment[];
}

export interface Attachment {
  filename: string;
  content: Buffer | string;
  contentType: string;
}

export interface ReportRequest {
  type: string;
  format: string;
  filters?: Record<string, any>;
  options?: Record<string, any>;
}

export interface ReportResult {
  content: Buffer | string;
  contentType: string;
  filename: string;
}

// Plugin lifecycle
export interface PluginLifecycle {
  install(config: PluginConfig): Promise<void>;
  uninstall(): Promise<void>;
  update(version: string): Promise<void>;
  configure(config: Record<string, any>): Promise<void>;
}

export interface PluginConfig {
  id: string;
  version: string;
  settings?: Record<string, any>;
  permissions?: PluginPermissions;
}

export interface PluginPermissions {
  network?: boolean;
  filesystem?: 'none' | 'read' | 'read-write';
  environment?: string[];
}
