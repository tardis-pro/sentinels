import { Client } from 'pg';

const client = new Client({
  connectionString: process.env.DATABASE_URL || 'postgres://sentinel:sentinel@localhost:35432/sentinel',
});

let policyConnected = false;
let policyConnectPromise: Promise<void> | null = null;

// ============================================================================
// Types
// ============================================================================

export interface Policy {
  id: string;
  name: string;
  description: string;
  category: PolicyCategory;
  severity: PolicySeverity;
  regoPolicy: string;
  enabled: boolean;
  enforcementAction: EnforcementAction;
  tags: string[];
  projectId?: string;
  createdAt: Date;
  updatedAt: Date;
}

export type PolicyCategory = 
  | 'security'
  | 'compliance'
  | 'operational'
  | 'custom';

export type PolicySeverity = 
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFO';

export type EnforcementAction = 
  | 'block'
  | 'warn'
  | 'notify'
  | 'log';

export interface PolicyEvaluation {
  policyId: string;
  policyName: string;
  passed: boolean;
  ruleId?: string;
  findings: PolicyFinding[];
  evaluatedAt: Date;
}

export interface PolicyFinding {
  resource: string;
  line?: number;
  message: string;
  details: Record<string, any>;
}

export interface PolicyRule {
  id: string;
  name: string;
  policyId: string;
  regoRule: string;
  description: string;
  enabled: boolean;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  description: string;
  controls: ComplianceControl[];
}

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  policyIds: string[];
  frameworkId: string;
}

// ============================================================================
// Database Connection
// ============================================================================

export async function connectPolicyDb(): Promise<void> {
  if (policyConnected) {
    return;
  }
  if (policyConnectPromise) {
    await policyConnectPromise;
    return;
  }

  policyConnectPromise = client
    .connect()
    .then(async () => {
      await createPolicyTables();
      policyConnected = true;
      console.log('Policy Engine: Connected to PostgreSQL');
    })
    .catch((error) => {
      policyConnectPromise = null;
      throw error;
    });

  await policyConnectPromise;
}

export async function createPolicyTables(): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS policies (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      rego_policy TEXT NOT NULL,
      enabled BOOLEAN DEFAULT true,
      enforcement_action TEXT NOT NULL,
      tags JSONB DEFAULT '[]',
      project_id UUID,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS compliance_frameworks (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS compliance_controls (
      id TEXT PRIMARY KEY,
      framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      policy_ids JSONB DEFAULT '[]',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS finding_compliance_mapping (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
      control_id TEXT NOT NULL,
      control_name TEXT NOT NULL,
      finding_rule_pattern TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_policies_category ON policies(category);
    CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
    CREATE INDEX IF NOT EXISTS idx_policies_project ON policies(project_id);
    CREATE INDEX IF NOT EXISTS idx_compliance_controls_framework ON compliance_controls(framework_id);
    CREATE INDEX IF NOT EXISTS idx_finding_compliance_mapping_framework ON finding_compliance_mapping(framework_id);
  `);
}

async function ensureConnection(): Promise<void> {
  if (!policyConnected) {
    await connectPolicyDb();
  }
}

// ============================================================================
// Policy CRUD Operations
// ============================================================================

export async function createPolicy(policy: {
  name: string;
  description: string;
  category: PolicyCategory;
  severity: PolicySeverity;
  regoPolicy: string;
  enabled?: boolean;
  enforcementAction: EnforcementAction;
  tags?: string[];
  projectId?: string;
}): Promise<Policy> {
  await ensureConnection();
  
  const result = await client.query(
    `INSERT INTO policies (
      name, description, category, severity, rego_policy, 
      enabled, enforcement_action, tags, project_id
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    RETURNING *`,
    [
      policy.name,
      policy.description,
      policy.category,
      policy.severity,
      policy.regoPolicy,
      policy.enabled ?? true,
      policy.enforcementAction,
      JSON.stringify(policy.tags || []),
      policy.projectId || null,
    ]
  );

  return mapPolicyRow(result.rows[0]);
}

export async function getPolicyById(id: string): Promise<Policy | null> {
  await ensureConnection();
  
  const result = await client.query(
    'SELECT * FROM policies WHERE id = $1',
    [id]
  );

  if (result.rows.length === 0) {
    return null;
  }

  return mapPolicyRow(result.rows[0]);
}

export async function listPolicies(options?: {
  category?: PolicyCategory;
  enabled?: boolean;
  projectId?: string;
  limit?: number;
  offset?: number;
}): Promise<Policy[]> {
  await ensureConnection();
  
  const conditions: string[] = [];
  const params: any[] = [];
  let paramIndex = 1;

  if (options?.category) {
    conditions.push(`category = $${paramIndex++}`);
    params.push(options.category);
  }

  if (options?.enabled !== undefined) {
    conditions.push(`enabled = $${paramIndex++}`);
    params.push(options.enabled);
  }

  if (options?.projectId) {
    conditions.push(`(project_id = $${paramIndex++} OR project_id IS NULL)`);
    params.push(options.projectId);
  }

  const whereClause = conditions.length > 0 
    ? `WHERE ${conditions.join(' AND ')}` 
    : '';

  params.push(options?.limit || 50);
  params.push(options?.offset || 0);

  const result = await client.query(
    `SELECT * FROM policies ${whereClause} ORDER BY created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
    params
  );

  return result.rows.map(mapPolicyRow);
}

export async function updatePolicy(
  id: string,
  updates: Partial<Omit<Policy, 'id' | 'createdAt' | 'updatedAt'>>
): Promise<Policy | null> {
  await ensureConnection();
  
  const setClauses: string[] = [];
  const params: any[] = [];
  let paramIndex = 1;

  const allowedFields: Record<string, string> = {
    name: 'name',
    description: 'description',
    category: 'category',
    severity: 'severity',
    regoPolicy: 'rego_policy',
    enabled: 'enabled',
    enforcementAction: 'enforcement_action',
    tags: 'tags',
    projectId: 'project_id',
  };

  for (const [key, dbField] of Object.entries(allowedFields)) {
    if (key in updates) {
      const value = (updates as any)[key];
      setClauses.push(`${dbField} = $${paramIndex++}`);
      params.push(dbField === 'tags' ? JSON.stringify(value) : value);
    }
  }

  if (setClauses.length === 0) {
    return getPolicyById(id);
  }

  setClauses.push(`updated_at = NOW()`);
  params.push(id);

  const result = await client.query(
    `UPDATE policies SET ${setClauses.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
    params
  );

  if (result.rows.length === 0) {
    return null;
  }

  return mapPolicyRow(result.rows[0]);
}

export async function deletePolicy(id: string): Promise<boolean> {
  await ensureConnection();
  
  const result = await client.query(
    'DELETE FROM policies WHERE id = $1 RETURNING id',
    [id]
  );

  return result.rows.length > 0;
}

// ============================================================================
// OPA/Rego Policy Engine
// ============================================================================

interface OPAInput {
  finding: {
    id: string;
    severity: string;
    type: string;
    title: string;
    description: string;
    scannerName: string;
    file?: string;
    line?: number;
    package?: string;
    ruleId?: string;
    cveId?: string;
    cvssScore?: number;
    remediation?: string;
    tags: Record<string, string>;
  };
  project: {
    id: string;
    name: string;
    type?: string;
  };
  context: {
    environment: string;
    complianceFramework?: string;
    customTags: Record<string, string>;
  };
}

interface OPAEvaluationResult {
  decisions: {
    pass: boolean;
    violations: Array<{
      rule: string;
      message: string;
      details: Record<string, any>;
    }>;
  }[];
}

// Simulated OPA evaluation - in production, use actual OPA Wasm binary
export async function evaluatePolicyWithOPA(
  policy: Policy,
  input: OPAInput
): Promise<OPAEvaluationResult> {
  await ensureConnection();
  
  // For demonstration, we'll implement a simplified policy evaluation
  // In production, this would interface with OPA's Wasm binary or REST API
  
  const violations: Array<{
    rule: string;
    message: string;
    details: Record<string, any>;
  }> = [];

  // Parse the Rego policy to extract rules (simplified)
  const rules = extractRulesFromRego(policy.regoPolicy);
  
  for (const rule of rules) {
    const violation = evaluateRule(rule, input);
    if (violation) {
      violations.push(violation);
    }
  }

  return {
    decisions: [{
      pass: violations.length === 0,
      violations,
    }],
  };
}

interface RegoRule {
  name: string;
  condition: string;
  message: string;
  severity: string;
}

function extractRulesFromRego(rego: string): RegoRule[] {
  const rules: RegoRule[] = [];
  
  // Simplified Rego parsing - look for deny rules
  const denyMatches = rego.matchAll(/deny\s*(?:\[([^\]]+)\])?\s*(?:if)?\s*\{([^}]+)\}/g);
  
  for (const match of denyMatches) {
    const message = match[1] || 'Policy violation';
    const condition = match[2];
    
    // Extract rule name from comments or use default
    const nameMatch = rego.match(new RegExp(`#\\s*(?:Rule|Policy)\\s*:?\\s*([\\w-]+)`, 'i'));
    const name = nameMatch?.[1] || 'unnamed-rule';
    
    rules.push({
      name,
      condition,
      message: message.replace(/"/g, '').trim(),
      severity: policySeverityFromCondition(condition),
    });
  }

  // If no explicit deny rules, check for package-level violations
  if (rules.length === 0) {
    const violationMatches = rego.matchAll(/violation\s*\{([^}]+)\}/g);
    for (const match of violationMatches) {
      const condition = match[1];
      rules.push({
        name: 'violation-check',
        condition,
        message: 'Security policy violation detected',
        severity: policySeverityFromCondition(condition),
      });
    }
  }

  return rules;
}

function evaluateRule(
  rule: RegoRule,
  input: OPAInput
): { rule: string; message: string; details: Record<string, any> } | null {
  const condition = rule.condition.toLowerCase();
  
  // Severity-based evaluation
  if (condition.includes('severity') || condition.includes('critical')) {
    const severityPriority: Record<string, number> = {
      critical: 4, high: 3, medium: 2, low: 1, info: 0,
    };
    
    const inputSeverity = input.finding.severity.toLowerCase();
    const severity = severityPriority[inputSeverity] || 0;
    
    if (severity >= 3) {
      return {
        rule: rule.name,
        message: rule.message,
        details: {
          severity: input.finding.severity,
          reason: `Severity ${inputSeverity} triggers ${rule.severity} policy`,
        },
      };
    }
  }

  // Scanner-specific rules
  if (condition.includes('scanner') || condition.includes('trivy') || condition.includes('semgrep')) {
    const scannerName = input.finding.scannerName.toLowerCase();
    if (condition.includes(scannerName)) {
      return {
        rule: rule.name,
        message: rule.message,
        details: {
          scanner: input.finding.scannerName,
          reason: `${scannerName} finding triggered policy rule`,
        },
      };
    }
  }

  // CVE-based rules
  if (condition.includes('cve') || condition.includes('cvss')) {
    if (input.finding.cveId || input.finding.cvssScore) {
      const cvss = input.finding.cvssScore || 0;
      if (cvss >= 7.0) {
        return {
          rule: rule.name,
          message: rule.message,
          details: {
            cveId: input.finding.cveId,
            cvssScore: input.finding.cvssScore,
            reason: `High CVSS score (${cvss}) requires attention`,
          },
        };
      }
    }
  }

  // Custom tag-based rules
  if (condition.includes('tag') || condition.includes('label')) {
    const customTags = { ...input.finding.tags, ...input.context.customTags };
    const tagsToCheck = Object.entries(customTags);
    
    for (const [key, value] of tagsToCheck) {
      if (condition.includes(key.toLowerCase()) && condition.includes(value.toLowerCase())) {
        return {
          rule: rule.name,
          message: rule.message,
          details: {
            tag: key,
            value,
            reason: `Custom tag ${key}=${value} triggered policy`,
          },
        };
      }
    }
  }

  // Environment-based rules
  if (condition.includes('environment') || condition.includes('prod') || condition.includes('staging')) {
    const env = input.context.environment.toLowerCase();
    if ((condition.includes('prod') && env === 'production') ||
        (condition.includes('staging') && env === 'staging')) {
      return {
        rule: rule.name,
        message: rule.message,
        details: {
          environment: input.context.environment,
          reason: `${env} environment has stricter security requirements`,
        },
      };
    }
  }

  return null;
}

function policySeverityFromCondition(condition: string): string {
  const lower = condition.toLowerCase();
  if (lower.includes('critical') || lower.includes('cvss') && lower.includes('9')) {
    return 'CRITICAL';
  }
  if (lower.includes('high') || lower.includes('cvss') && lower.includes('7')) {
    return 'HIGH';
  }
  if (lower.includes('medium') || lower.includes('cvss') && lower.includes('5')) {
    return 'MEDIUM';
  }
  if (lower.includes('low')) {
    return 'LOW';
  }
  return 'INFO';
}

// ============================================================================
// Policy Evaluation API
// ============================================================================

export async function evaluateFindingAgainstPolicies(
  findingId: string,
  projectId: string,
  policyIds?: string[]
): Promise<PolicyEvaluation[]> {
  await ensureConnection();
  
  // Get the finding
  const findingResult = await client.query(
    'SELECT * FROM findings WHERE id = $1',
    [findingId]
  );

  if (findingResult.rows.length === 0) {
    throw new Error(`Finding ${findingId} not found`);
  }

  const finding = findingResult.rows[0];

  // Get applicable policies
  const policies = policyIds?.length
    ? await Promise.all(policyIds.map(id => getPolicyById(id)))
    : await listPolicies({ enabled: true, projectId });

  const activePolicies = policies.filter((p): p is Policy => p !== null);

  // Build OPA input
  const opaInput: OPAInput = {
    finding: {
      id: finding.id,
      severity: finding.severity,
      type: finding.type,
      title: finding.title,
      description: finding.description,
      scannerName: finding.scanner_name,
      file: finding.file,
      line: finding.line,
      package: finding.package,
      ruleId: finding.rule_id,
      cveId: finding.cve_id,
      cvssScore: finding.cvss_score,
      remediation: finding.remediation,
      tags: (typeof finding.tags === 'string' 
        ? JSON.parse(finding.tags) 
        : finding.tags) || {},
    },
    project: {
      id: projectId,
      name: '',
    },
    context: {
      environment: process.env.SENTINEL_ENVIRONMENT || 'development',
      customTags: {},
    },
  };

  // Evaluate against each policy
  const evaluations: PolicyEvaluation[] = [];

  for (const policy of activePolicies) {
    const result = await evaluatePolicyWithOPA(policy, opaInput);
    const decision = result.decisions[0];

    evaluations.push({
      policyId: policy.id,
      policyName: policy.name,
      passed: decision.pass,
      ruleId: decision.violations[0]?.rule,
      findings: decision.violations.map(v => ({
        resource: opaInput.finding.file || 'unknown',
        line: opaInput.finding.line,
        message: v.message,
        details: v.details,
      })),
      evaluatedAt: new Date(),
    });
  }

  return evaluations;
}

export async function evaluateProjectCompliance(
  projectId: string,
  frameworkName?: string
): Promise<{
  compliant: number;
  nonCompliant: number;
  overallScore: number;
  controls: Array<{
    controlId: string;
    controlName: string;
    status: 'compliant' | 'non-compliant' | 'not-applicable';
    findings: number;
  }>;
}> {
  await ensureConnection();
  
  // Get project findings
  const findingsResult = await client.query(
    `SELECT DISTINCT f.* 
     FROM findings f
     JOIN scans s ON f.scan_id = s.id
     WHERE s.project_id = $1`,
    [projectId]
  );

  const findings = findingsResult.rows;

  // Get applicable policies
  const policies = await listPolicies({ 
    enabled: true, 
    projectId,
    category: 'compliance',
  });

  // Simplified compliance check
  const controlResults: Array<{
    controlId: string;
    controlName: string;
    status: 'compliant' | 'non-compliant' | 'not-applicable';
    findings: number;
  }> = [];

  let compliant = 0;
  let nonCompliant = 0;

  // Map policies to compliance controls
  for (const policy of policies) {
    const policyFindings = findings.filter(f => 
      f.severity === policy.severity && 
      f.type === policy.category
    );

    const isCompliant = policyFindings.length === 0;

    controlResults.push({
      controlId: policy.id,
      controlName: policy.name,
      status: isCompliant ? 'compliant' : 'non-compliant',
      findings: policyFindings.length,
    });

    if (isCompliant) {
      compliant++;
    } else {
      nonCompliant++;
    }
  }

  const total = compliant + nonCompliant;
  const overallScore = total > 0 
    ? Math.round((compliant / total) * 100) 
    : 100;

  return {
    compliant,
    nonCompliant,
    overallScore,
    controls: controlResults,
  };
}

// ============================================================================
// Built-in Policy Templates
// ============================================================================

export const builtInPolicies: Array<{
  name: string;
  description: string;
  category: PolicyCategory;
  severity: PolicySeverity;
  enforcementAction: EnforcementAction;
  regoPolicy: string;
}> = [
  {
    name: 'Critical Vulnerability Block',
    description: 'Block deployments with critical severity vulnerabilities',
    category: 'security',
    severity: 'CRITICAL',
    enforcementAction: 'block',
    regoPolicy: `# Critical Vulnerability Policy
# Deny any finding with CRITICAL severity

package sentinel.critical_vuln

deny[msg] {
  input.finding.severity == "CRITICAL"
  msg := "Critical severity vulnerability detected - deployment blocked"
}
`,
  },
  {
    name: 'High Severity Warning',
    description: 'Warn on high severity vulnerabilities',
    category: 'security',
    severity: 'HIGH',
    enforcementAction: 'warn',
    regoPolicy: `# High Severity Warning Policy
# Warn on findings with HIGH severity

package sentinel.high_severity

deny[msg] {
  input.finding.severity == "HIGH"
  msg := "High severity vulnerability requires attention"
}
`,
  },
  {
    name: 'Secret Scanning Policy',
    description: 'Block any secrets detected in code',
    category: 'security',
    severity: 'CRITICAL',
    enforcementAction: 'block',
    regoPolicy: `# Secret Scanning Policy
# Deny findings indicating exposed secrets

package sentinel.secret_scanning

deny[msg] {
  input.finding.type == "secret"
  msg := "Exposed secret detected - immediate remediation required"
}

deny[msg] {
  input.finding.type == "credential"
  msg := "Credential exposure detected - security risk"
}
`,
  },
  {
    name: 'Production Environment Strict',
    description: 'Strict security policies for production',
    category: 'compliance',
    severity: 'HIGH',
    enforcementAction: 'block',
    regoPolicy: `# Production Environment Policy
# Apply stricter controls in production

package sentinel.production

deny[msg] {
  input.context.environment == "production"
  input.finding.severity in ["CRITICAL", "HIGH"]
  msg := "High/Critical findings not allowed in production"
}
`,
  },
  {
    name: 'License Compliance',
    description: 'Ensure license compliance for dependencies',
    category: 'compliance',
    severity: 'MEDIUM',
    enforcementAction: 'warn',
    regoPolicy: `# License Compliance Policy
# Flag prohibited licenses

package sentinel.license

deny[msg] {
  input.finding.type == "license"
  input.finding.tags.license_type in ["GPL-3.0", "AGPL-3.0", "SSPL"]
  msg := "Prohibited license detected - review required"
}
`,
  },
];

export async function seedBuiltInPolicies(): Promise<Policy[]> {
  await ensureConnection();
  
  const created: Policy[] = [];

  for (const template of builtInPolicies) {
    const existing = await client.query(
      'SELECT id FROM policies WHERE name = $1',
      [template.name]
    );

    if (existing.rows.length === 0) {
      const policy = await createPolicy({
        name: template.name,
        description: template.description,
        category: template.category,
        severity: template.severity,
        regoPolicy: template.regoPolicy,
        enforcementAction: template.enforcementAction,
        enabled: true,
      });
      created.push(policy);
    }
  }

  return created;
}

// ============================================================================
// Compliance Frameworks
// ============================================================================

export async function createComplianceFramework(framework: {
  name: string;
  description: string;
  controls: Array<{
    id?: string;
    name: string;
    description: string;
    policyIds?: string[];
  }>;
}): Promise<ComplianceFramework> {
  await ensureConnection();
  
  const result = await client.query(
    `INSERT INTO compliance_frameworks (name, description)
     VALUES ($1, $2) RETURNING id`,
    [framework.name, framework.description]
  );

  const frameworkId = result.rows[0].id;

  for (let index = 0; index < framework.controls.length; index++) {
    const control = framework.controls[index];
    const controlId = control.id || `${framework.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-ctrl-${index + 1}`;
    await client.query(
      `INSERT INTO compliance_controls (framework_id, id, name, description, policy_ids)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        frameworkId,
        controlId,
        control.name,
        control.description,
        JSON.stringify(control.policyIds || []),
      ]
    );
  }

  return {
    id: frameworkId,
    ...framework,
    controls: framework.controls.map((c, i) => ({
      name: c.name,
      description: c.description,
      policyIds: c.policyIds || [],
      frameworkId,
      id: c.id || `ctrl-${i + 1}`,
    })),
  };
}

export async function getComplianceFrameworks(): Promise<ComplianceFramework[]> {
  await ensureConnection();
  
  const frameworksResult = await client.query(
    'SELECT * FROM compliance_frameworks ORDER BY name'
  );

  const controlsResult = await client.query(
    'SELECT * FROM compliance_controls ORDER BY id'
  );

  const controlsByFramework = controlsResult.rows.reduce((acc, row) => {
    const frameworkId = row.framework_id;
    if (!acc[frameworkId]) {
      acc[frameworkId] = [];
    }
    acc[frameworkId].push({
      id: row.id,
      name: row.name,
      description: row.description,
      policyIds: row.policy_ids,
      frameworkId: row.framework_id,
    });
    return acc;
  }, {} as Record<string, ComplianceControl[]>);

  return frameworksResult.rows.map(row => ({
    id: row.id,
    name: row.name,
    description: row.description,
    controls: controlsByFramework[row.id] || [],
  }));
}

// ============================================================================
// Policy Statistics
// ============================================================================

export async function getPolicyStatistics(): Promise<{
  totalPolicies: number;
  enabledPolicies: number;
  byCategory: Record<string, number>;
  bySeverity: Record<string, number>;
  byEnforcementAction: Record<string, number>;
}> {
  await ensureConnection();
  
  const totalResult = await client.query('SELECT COUNT(*) as count FROM policies');
  const enabledResult = await client.query(
    'SELECT COUNT(*) as count FROM policies WHERE enabled = true'
  );
  const categoryResult = await client.query(
    'SELECT category, COUNT(*) as count FROM policies GROUP BY category'
  );
  const severityResult = await client.query(
    'SELECT severity, COUNT(*) as count FROM policies GROUP BY severity'
  );
  const actionResult = await client.query(
    'SELECT enforcement_action, COUNT(*) as count FROM policies GROUP BY enforcement_action'
  );

  return {
    totalPolicies: parseInt(totalResult.rows[0].count),
    enabledPolicies: parseInt(enabledResult.rows[0].count),
    byCategory: categoryResult.rows.reduce((acc, row) => {
      acc[row.category] = parseInt(row.count);
      return acc;
    }, {} as Record<string, number>),
    bySeverity: severityResult.rows.reduce((acc, row) => {
      acc[row.severity] = parseInt(row.count);
      return acc;
    }, {} as Record<string, number>),
    byEnforcementAction: actionResult.rows.reduce((acc, row) => {
      acc[row.enforcement_action] = parseInt(row.count);
      return acc;
    }, {} as Record<string, number>),
  };
}

// ============================================================================
// Helper Functions
// ============================================================================

function mapPolicyRow(row: any): Policy {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    category: row.category,
    severity: row.severity,
    regoPolicy: row.rego_policy,
    enabled: row.enabled,
    enforcementAction: row.enforcement_action,
    tags: typeof row.tags === 'string' ? JSON.parse(row.tags) : row.tags || [],
    projectId: row.project_id,
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
  };
}
