// Team Collaboration & Triage - Issue #6
// Finding workflow, assignments, comments, team management, and issue tracking integration

import { client } from '../db';

// ============== Types ==============

export interface Team {
  id: string;
  name: string;
  description?: string;
  orgId: string;
  members: TeamMember[];
  createdAt: Date;
  updatedAt: Date;
}

export interface TeamMember {
  userId: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  joinedAt: Date;
}

export interface User {
  id: string;
  email: string;
  name: string;
  avatarUrl?: string;
  createdAt: Date;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  createdAt: Date;
}

export interface FindingAssignment {
  id: string;
  findingId: string;
  assignedTo?: string;
  assignedBy?: string;
  assignedAt?: Date;
  unassignedAt?: Date;
  reason?: string;
}

export interface FindingWorkflow {
  id: string;
  findingId: string;
  fromState: FindingState;
  toState: FindingState;
  changedBy: string;
  changedAt: Date;
  comment?: string;
}

export type FindingState = 
  | 'open'
  | 'assigned'
  | 'in_progress'
  | 'under_review'
  | 'remediated'
  | 'closed'
  | 'false_positive'
  | 'accepted_risk';

export interface Comment {
  id: string;
  findingId: string;
  userId: string;
  content: string;
  mentions: string[];
  parentId?: string;
  createdAt: Date;
  updatedAt: Date;
  isResolved?: boolean;
}

export interface SLAConfig {
  id: string;
  orgId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  targetHours: number;
  escalationEnabled: boolean;
  escalationEmail?: string;
}

export interface RiskAcceptance {
  id: string;
  findingId: string;
  acceptedBy: string;
  acceptedAt: Date;
  expiresAt?: Date;
  reason: string;
  approverEmail?: string;
  approvedAt?: Date;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
}

export interface IssueTrackerConfig {
  id: string;
  orgId: string;
  provider: 'jira' | 'linear' | 'asana' | 'notion' | 'github';
  name: string;
  config: {
    apiUrl?: string;
    projectId?: string;
    boardId?: string;
    mapping?: {
      stateMapping?: Record<string, string>;
      priorityMapping?: Record<string, string>;
    };
    credentials?: {
      apiKey?: string;
      accessToken?: string;
    };
  };
  enabled: boolean;
  createdAt: Date;
}

// ============== Database Schema ==============

export async function createCollaborationTables(): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS organizations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      avatar_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS teams (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      description TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS team_members (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      team_id UUID REFERENCES teams(id) ON DELETE CASCADE,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      role VARCHAR(20) NOT NULL DEFAULT 'member',
      joined_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(team_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS finding_assignments (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
      assigned_to UUID REFERENCES users(id),
      assigned_by UUID REFERENCES users(id),
      assigned_at TIMESTAMPTZ DEFAULT NOW(),
      unassigned_at TIMESTAMPTZ,
      reason TEXT
    );

    CREATE TABLE IF NOT EXISTS finding_workflow (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
      from_state VARCHAR(30),
      to_state VARCHAR(30) NOT NULL,
      changed_by UUID REFERENCES users(id),
      changed_at TIMESTAMPTZ DEFAULT NOW(),
      comment TEXT
    );

    ALTER TABLE findings ADD COLUMN IF NOT EXISTS workflow_state VARCHAR(30) DEFAULT 'open';
    ALTER TABLE findings ADD COLUMN IF NOT EXISTS workflow_updated_at TIMESTAMPTZ;
    ALTER TABLE findings ADD COLUMN IF NOT EXISTS workflow_updated_by UUID;

    CREATE TABLE IF NOT EXISTS comments (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      parent_id UUID REFERENCES comments(id),
      mentions UUID[] DEFAULT '{}',
      is_resolved BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sla_configs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
      severity VARCHAR(20) NOT NULL,
      target_hours DECIMAL NOT NULL,
      escalation_enabled BOOLEAN DEFAULT false,
      escalation_email TEXT,
      UNIQUE(org_id, severity)
    );

    CREATE TABLE IF NOT EXISTS risk_acceptances (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
      accepted_by UUID REFERENCES users(id),
      accepted_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ,
      reason TEXT NOT NULL,
      approver_email TEXT,
      approved_at TIMESTAMPTZ,
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
    );

    CREATE TABLE IF NOT EXISTS issue_tracker_configs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
      provider VARCHAR(20) NOT NULL,
      name TEXT NOT NULL,
      config JSONB NOT NULL,
      enabled BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS issue_syncs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
      tracker_id UUID REFERENCES issue_tracker_configs(id) ON DELETE CASCADE,
      external_issue_id TEXT NOT NULL,
      external_issue_url TEXT,
      last_synced_at TIMESTAMPTZ DEFAULT NOW(),
      sync_status VARCHAR(20) DEFAULT 'synced',
      UNIQUE(finding_id, tracker_id)
    );

    CREATE INDEX IF NOT EXISTS idx_findings_workflow_state ON findings(workflow_state);
    CREATE INDEX IF NOT EXISTS idx_assignments_finding ON finding_assignments(finding_id);
    CREATE INDEX IF NOT EXISTS idx_assignments_user ON finding_assignments(assigned_to);
    CREATE INDEX IF NOT EXISTS idx_workflow_finding ON finding_workflow(finding_id);
    CREATE INDEX IF NOT EXISTS idx_comments_finding ON comments(finding_id);
    CREATE INDEX IF NOT EXISTS idx_risk_acceptances_finding ON risk_acceptances(finding_id);
    CREATE INDEX IF NOT EXISTS idx_issue_syncs_finding ON issue_syncs(finding_id);
  `);
  console.log('Collaboration tables ensured.');
}

// ============== User Management ==============

export async function createUser(email: string, name: string, avatarUrl?: string): Promise<User> {
  const result = await client.query(
    `INSERT INTO users (email, name, avatar_url) VALUES ($1, $2, $3) RETURNING *`,
    [email, name, avatarUrl]
  );
  return mapUserRow(result.rows[0]);
}

export async function getUser(id: string): Promise<User | null> {
  const result = await client.query('SELECT * FROM users WHERE id = $1', [id]);
  return result.rows.length > 0 ? mapUserRow(result.rows[0]) : null;
}

export async function getUserByEmail(email: string): Promise<User | null> {
  const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
  return result.rows.length > 0 ? mapUserRow(result.rows[0]) : null;
}

export async function listUsers(): Promise<User[]> {
  const result = await client.query('SELECT * FROM users ORDER BY created_at DESC');
  return result.rows.map(mapUserRow);
}

function mapUserRow(row: any): User {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    avatarUrl: row.avatar_url,
    createdAt: row.created_at,
  };
}

// ============== Organization & Team Management ==============

export async function createOrganization(name: string, slug: string): Promise<Organization> {
  const result = await client.query(
    `INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING *`,
    [name, slug]
  );
  return mapOrgRow(result.rows[0]);
}

export async function getOrganization(id: string): Promise<Organization | null> {
  const result = await client.query('SELECT * FROM organizations WHERE id = $1', [id]);
  return result.rows.length > 0 ? mapOrgRow(result.rows[0]) : null;
}

export async function createTeam(orgId: string, name: string, description?: string): Promise<Team> {
  const result = await client.query(
    `INSERT INTO teams (org_id, name, description) VALUES ($1, $2, $3) RETURNING *`,
    [orgId, name, description]
  );
  return mapTeamRow(result.rows[0]);
}

export async function addTeamMember(teamId: string, userId: string, role: 'owner' | 'admin' | 'member' | 'viewer' = 'member'): Promise<void> {
  await client.query(
    `INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)
     ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
    [teamId, userId, role]
  );
}

export async function getTeam(id: string): Promise<Team | null> {
  const teamResult = await client.query('SELECT * FROM teams WHERE id = $1', [id]);
  if (teamResult.rows.length === 0) return null;

  const membersResult = await client.query(
    `SELECT u.*, tm.role, tm.joined_at FROM users u
     JOIN team_members tm ON tm.user_id = u.id
     WHERE tm.team_id = $1`,
    [id]
  );

  return mapTeamRow(teamResult.rows[0], membersResult.rows);
}

export async function listTeams(orgId?: string): Promise<Team[]> {
  let query = `SELECT t.* FROM teams t`;
  const params: any[] = [];

  if (orgId) {
    query += ' WHERE t.org_id = $1';
    params.push(orgId);
  }

  query += ' ORDER BY t.created_at DESC';

  const result = await client.query(query, params);
  const teams: Team[] = [];

  for (const team of result.rows) {
    const membersResult = await client.query(
      `SELECT u.*, tm.role, tm.joined_at FROM users u
       JOIN team_members tm ON tm.user_id = u.id
       WHERE tm.team_id = $1`,
      [team.id]
    );
    teams.push(mapTeamRow(team, membersResult.rows));
  }

  return teams;
}

function mapOrgRow(row: any): Organization {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    createdAt: row.created_at,
  };
}

function mapTeamRow(row: any, members?: any[]): Team {
  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    description: row.description,
    members: (members || []).map(m => ({
      userId: m.id,
      role: m.role,
      joinedAt: m.joined_at,
    })),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ============== Finding Assignment ==============

export async function assignFinding(findingId: string, assignedTo: string, assignedBy: string, reason?: string): Promise<FindingAssignment> {
  await client.query(
    `UPDATE findings SET workflow_state = 'assigned', workflow_updated_at = NOW(), workflow_updated_by = $1 WHERE id = $2`,
    [assignedBy, findingId]
  );

  await client.query(
    `UPDATE finding_assignments SET unassigned_at = NOW() WHERE finding_id = $1 AND unassigned_at IS NULL`,
    [findingId]
  );

  const result = await client.query(
    `INSERT INTO finding_assignments (finding_id, assigned_to, assigned_by, reason)
     VALUES ($1, $2, $3, $4) RETURNING *`,
    [findingId, assignedTo, assignedBy, reason]
  );

  await client.query(
    `INSERT INTO finding_workflow (finding_id, from_state, to_state, changed_by, comment)
     VALUES ($1, 'open', 'assigned', $2, $3)`,
    [findingId, assignedBy, `Assigned to user`]
  );

  return mapAssignmentRow(result.rows[0]);
}

export async function unassignFinding(findingId: string, unassignedBy: string): Promise<void> {
  await client.query(
    `UPDATE finding_assignments SET unassigned_at = NOW() WHERE finding_id = $1 AND unassigned_at IS NULL`,
    [findingId]
  );

  await client.query(
    `UPDATE findings SET workflow_state = 'open', workflow_updated_at = NOW(), workflow_updated_by = $1 WHERE id = $2`,
    [unassignedBy, findingId]
  );

  await client.query(
    `INSERT INTO finding_workflow (finding_id, from_state, to_state, changed_by, comment)
     VALUES ($1, 'assigned', 'open', $2, 'Unassigned')`,
    [findingId, unassignedBy]
  );
}

export async function getFindingAssignment(findingId: string): Promise<FindingAssignment | null> {
  const result = await client.query(
    `SELECT * FROM finding_assignments WHERE finding_id = $1 AND unassigned_at IS NULL`,
    [findingId]
  );
  return result.rows.length > 0 ? mapAssignmentRow(result.rows[0]) : null;
}

export async function getAssignedFindings(userId: string): Promise<string[]> {
  const result = await client.query(
    `SELECT finding_id FROM finding_assignments WHERE assigned_to = $1 AND unassigned_at IS NULL`,
    [userId]
  );
  return result.rows.map(r => r.finding_id);
}

function mapAssignmentRow(row: any): FindingAssignment {
  return {
    id: row.id,
    findingId: row.finding_id,
    assignedTo: row.assigned_to,
    assignedBy: row.assigned_by,
    assignedAt: row.assigned_at,
    unassignedAt: row.unassigned_at,
    reason: row.reason,
  };
}

// ============== Workflow State Management ==============

const VALID_TRANSITIONS: Record<FindingState, FindingState[]> = {
  open: ['assigned', 'in_progress', 'false_positive', 'accepted_risk'],
  assigned: ['in_progress', 'open', 'false_positive', 'accepted_risk'],
  in_progress: ['under_review', 'open', 'false_positive', 'accepted_risk'],
  under_review: ['remediated', 'in_progress', 'closed', 'false_positive', 'accepted_risk'],
  remediated: ['closed', 'under_review'],
  closed: ['open', 'remediated'],
  false_positive: ['open'],
  accepted_risk: ['open'],
};

export async function transitionFindingState(
  findingId: string,
  toState: FindingState,
  changedBy: string,
  comment?: string
): Promise<{ success: boolean; error?: string }> {
  const currentResult = await client.query('SELECT workflow_state FROM findings WHERE id = $1', [findingId]);
  if (currentResult.rows.length === 0) {
    return { success: false, error: 'Finding not found' };
  }

  const fromState = currentResult.rows[0].workflow_state;
  const validTargets = VALID_TRANSITIONS[fromState as FindingState] || [];

  if (!validTargets.includes(toState)) {
    return { success: false, error: `Invalid state transition from ${fromState} to ${toState}` };
  }

  await client.query(
    `UPDATE findings SET workflow_state = $1, workflow_updated_at = NOW(), workflow_updated_by = $2 WHERE id = $3`,
    [toState, changedBy, findingId]
  );

  await client.query(
    `INSERT INTO finding_workflow (finding_id, from_state, to_state, changed_by, comment)
     VALUES ($1, $2, $3, $4, $5)`,
    [findingId, fromState, toState, changedBy, comment]
  );

  return { success: true };
}

export async function getFindingWorkflowHistory(findingId: string): Promise<FindingWorkflow[]> {
  const result = await client.query(
    `SELECT * FROM finding_workflow WHERE finding_id = $1 ORDER BY changed_at DESC`,
    [findingId]
  );
  return result.rows.map(row => ({
    id: row.id,
    findingId: row.finding_id,
    fromState: row.from_state,
    toState: row.to_state,
    changedBy: row.changed_by,
    changedAt: row.changed_at,
    comment: row.comment,
  }));
}

export async function getFindingsByState(state: FindingState): Promise<string[]> {
  const result = await client.query('SELECT id FROM findings WHERE workflow_state = $1', [state]);
  return result.rows.map(r => r.id);
}

// ============== Comments ==============

export async function addComment(findingId: string, userId: string, content: string, parentId?: string): Promise<Comment> {
  const mentions = (content.match(/@([a-f0-9-]{36})/g) || []).map(m => m.slice(1));

  const result = await client.query(
    `INSERT INTO comments (finding_id, user_id, content, parent_id, mentions)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [findingId, userId, content, parentId, mentions]
  );

  return mapCommentRow(result.rows[0]);
}

export async function updateComment(commentId: string, content: string): Promise<Comment | null> {
  const mentions = (content.match(/@([a-f0-9-]{36})/g) || []).map(m => m.slice(1));

  const result = await client.query(
    `UPDATE comments SET content = $1, mentions = $2, updated_at = NOW()
     WHERE id = $3 RETURNING *`,
    [content, mentions, commentId]
  );

  if (result.rows.length === 0) return null;
  return mapCommentRow(result.rows[0]);
}

export async function deleteComment(commentId: string): Promise<boolean> {
  const result = await client.query('DELETE FROM comments WHERE id = $1', [commentId]);
  return (result.rowCount ?? 0) > 0;
}

export async function getFindingComments(findingId: string, includeResolved = false): Promise<Comment[]> {
  let query = `SELECT * FROM comments WHERE finding_id = $1`;
  const params: any[] = [findingId];

  if (!includeResolved) {
    query += ' AND (is_resolved = false OR is_resolved IS NULL)';
  }

  query += ' ORDER BY created_at ASC';

  const result = await client.query(query, params);
  return result.rows.map(mapCommentRow);
}

export async function resolveComment(commentId: string, resolved: boolean): Promise<Comment | null> {
  const result = await client.query(
    `UPDATE comments SET is_resolved = $1 WHERE id = $2 RETURNING *`,
    [resolved, commentId]
  );

  if (result.rows.length === 0) return null;
  return mapCommentRow(result.rows[0]);
}

function mapCommentRow(row: any): Comment {
  return {
    id: row.id,
    findingId: row.finding_id,
    userId: row.user_id,
    content: row.content,
    mentions: row.mentions || [],
    parentId: row.parent_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    isResolved: row.is_resolved,
  };
}

// ============== SLA Configuration ==============

export async function configureSLA(orgId: string, severity: 'critical' | 'high' | 'medium' | 'low', targetHours: number, escalationEnabled = false, escalationEmail?: string): Promise<SLAConfig> {
  const result = await client.query(
    `INSERT INTO sla_configs (org_id, severity, target_hours, escalation_enabled, escalation_email)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (org_id, severity)
     DO UPDATE SET target_hours = EXCLUDED.target_hours, escalation_enabled = EXCLUDED.escalation_enabled, escalation_email = EXCLUDED.escalation_email
     RETURNING *`,
    [orgId, severity, targetHours, escalationEnabled, escalationEmail]
  );

  return mapSLARow(result.rows[0]);
}

export async function getSLAConfigs(orgId: string): Promise<SLAConfig[]> {
  const result = await client.query('SELECT * FROM sla_configs WHERE org_id = $1', [orgId]);
  return result.rows.map(mapSLARow);
}

export async function checkSLABreachesForFinding(findingId: string): Promise<SLAConfig | null> {
  const findingResult = await client.query(
    `SELECT f.severity, f.workflow_state, f.created_at, p.org_id
     FROM findings f
     JOIN scans s ON s.id = f.scan_id
     JOIN projects p ON p.id = s.project_id
     WHERE f.id = $1`,
    [findingId]
  );

  if (findingResult.rows.length === 0) return null;

  const finding = findingResult.rows[0];
  if (finding.workflow_state === 'closed' || finding.workflow_state === 'false_positive' || finding.workflow_state === 'accepted_risk') {
    return null;
  }

  const slaResult = await client.query(
    'SELECT * FROM sla_configs WHERE org_id = $1 AND severity = $2',
    [finding.org_id, finding.severity]
  );

  if (slaResult.rows.length === 0) return null;

  const sla = slaResult.rows[0];
  const createdAt = new Date(finding.created_at);
  const targetDate = new Date(createdAt.getTime() + parseFloat(sla.target_hours) * 60 * 60 * 1000);

  if (new Date() > targetDate) {
    return mapSLARow(sla);
  }

  return null;
}

function mapSLARow(row: any): SLAConfig {
  return {
    id: row.id,
    orgId: row.org_id,
    severity: row.severity,
    targetHours: parseFloat(row.target_hours),
    escalationEnabled: row.escalation_enabled,
    escalationEmail: row.escalation_email,
  };
}

// ============== Risk Acceptance ==============

export async function requestRiskAcceptance(findingId: string, acceptedBy: string, reason: string, expiresAt?: Date): Promise<RiskAcceptance> {
  const result = await client.query(
    `INSERT INTO risk_acceptances (finding_id, accepted_by, reason, expires_at, status)
     VALUES ($1, $2, $3, $4, 'pending') RETURNING *`,
    [findingId, acceptedBy, reason, expiresAt]
  );

  return mapRiskAcceptanceRow(result.rows[0]);
}

export async function approveRiskAcceptance(acceptanceId: string, approverEmail: string): Promise<RiskAcceptance | null> {
  const result = await client.query(
    `UPDATE risk_acceptances SET status = 'approved', approver_email = $1, approved_at = NOW() WHERE id = $2 RETURNING *`,
    [approverEmail, acceptanceId]
  );

  if (result.rows.length === 0) return null;

  const acceptance = result.rows[0];

  await client.query(
    `UPDATE findings SET workflow_state = 'accepted_risk', workflow_updated_at = NOW() WHERE id = $1`,
    [acceptance.finding_id]
  );

  return mapRiskAcceptanceRow(result.rows[0]);
}

export async function rejectRiskAcceptance(acceptanceId: string, approverEmail: string): Promise<RiskAcceptance | null> {
  const result = await client.query(
    `UPDATE risk_acceptances SET status = 'rejected', approver_email = $1, approved_at = NOW() WHERE id = $2 RETURNING *`,
    [approverEmail, acceptanceId]
  );

  if (result.rows.length === 0) return null;
  return mapRiskAcceptanceRow(result.rows[0]);
}

export async function getFindingRiskAcceptance(findingId: string): Promise<RiskAcceptance | null> {
  const result = await client.query(
    `SELECT * FROM risk_acceptances WHERE finding_id = $1 AND status IN ('pending', 'approved') ORDER BY created_at DESC LIMIT 1`,
    [findingId]
  );
  return result.rows.length > 0 ? mapRiskAcceptanceRow(result.rows[0]) : null;
}

export async function getPendingRiskAcceptances(orgId: string): Promise<RiskAcceptance[]> {
  const result = await client.query(
    `SELECT ra.* FROM risk_acceptances ra
     JOIN findings f ON f.id = ra.finding_id
     JOIN scans s ON s.id = f.scan_id
     JOIN projects p ON p.id = s.project_id
     WHERE p.org_id = $1 AND ra.status = 'pending'
     ORDER BY ra.created_at DESC`,
    [orgId]
  );
  return result.rows.map(mapRiskAcceptanceRow);
}

function mapRiskAcceptanceRow(row: any): RiskAcceptance {
  return {
    id: row.id,
    findingId: row.finding_id,
    acceptedBy: row.accepted_by,
    acceptedAt: row.accepted_at,
    expiresAt: row.expires_at,
    reason: row.reason,
    approverEmail: row.approver_email,
    approvedAt: row.approved_at,
    status: row.status,
  };
}

// ============== Issue Tracker Integration ==============

export async function configureIssueTracker(config: {
  orgId: string;
  provider: 'jira' | 'linear' | 'asana' | 'notion' | 'github';
  name: string;
  config: IssueTrackerConfig['config'];
  enabled?: boolean;
}): Promise<IssueTrackerConfig> {
  const result = await client.query(
    `INSERT INTO issue_tracker_configs (org_id, provider, name, config, enabled)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [config.orgId, config.provider, config.name, JSON.stringify(config.config), config.enabled !== false]
  );

  return mapTrackerRow(result.rows[0]);
}

export async function getIssueTrackers(orgId: string, enabledOnly = false): Promise<IssueTrackerConfig[]> {
  let query = 'SELECT * FROM issue_tracker_configs WHERE org_id = $1';
  const params: any[] = [orgId];

  if (enabledOnly) {
    query += ' AND enabled = true';
  }

  query += ' ORDER BY created_at DESC';

  const result = await client.query(query, params);
  return result.rows.map(mapTrackerRow);
}

export async function syncFindingToIssue(findingId: string, trackerId: string, externalIssueId: string, externalIssueUrl?: string): Promise<void> {
  await client.query(
    `INSERT INTO issue_syncs (finding_id, tracker_id, external_issue_id, external_issue_url)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (finding_id, tracker_id)
     DO UPDATE SET external_issue_id = EXCLUDED.external_issue_id, external_issue_url = EXCLUDED.external_issue_url, last_synced_at = NOW()`,
    [findingId, trackerId, externalIssueId, externalIssueUrl]
  );
}

export async function getFindingIssueSyncs(findingId: string): Promise<Array<{ tracker: IssueTrackerConfig; sync: any }>> {
  const result = await client.query(
    `SELECT itc.*, is.*
     FROM issue_syncs is
     JOIN issue_tracker_configs itc ON itc.id = is.tracker_id
     WHERE is.finding_id = $1`,
    [findingId]
  );

  return result.rows.map(row => ({
    tracker: mapTrackerRow(row),
    sync: {
      id: row.id,
      externalIssueId: row.external_issue_id,
      externalIssueUrl: row.external_issue_url,
      lastSyncedAt: row.last_synced_at,
      syncStatus: row.sync_status,
    },
  }));
}

function mapTrackerRow(row: any): IssueTrackerConfig {
  return {
    id: row.id,
    orgId: row.org_id,
    provider: row.provider,
    name: row.name,
    config: row.config,
    enabled: row.enabled,
    createdAt: row.created_at,
  };
}

// ============== Collaboration Statistics ==============

export async function getCollaborationStats(orgId: string): Promise<{
  totalUsers: number;
  totalTeams: number;
  findingsByState: Record<string, number>;
  avgResolutionTimeHours: number;
  openRiskAcceptances: number;
  issueTrackersConfigured: number;
}> {
  const usersResult = await client.query(
    `SELECT COUNT(*) FROM users u
     JOIN team_members tm ON tm.user_id = u.id
     JOIN teams t ON t.id = tm.team_id
     WHERE t.org_id = $1`,
    [orgId]
  );

  const teamsResult = await client.query('SELECT COUNT(*) FROM teams WHERE org_id = $1', [orgId]);

  const stateResult = await client.query(
    `SELECT workflow_state, COUNT(*) as count FROM findings
     JOIN scans s ON s.id = findings.scan_id
     JOIN projects p ON p.id = s.project_id
     WHERE p.org_id = $1
     GROUP BY workflow_state`,
    [orgId]
  );

  const resolutionResult = await client.query(
    `SELECT AVG(EXTRACT(EPOCH FROM (workflow_updated_at - created_at)) / 3600) as avg_hours
     FROM findings
     JOIN scans s ON s.id = findings.scan_id
     JOIN projects p ON p.id = s.project_id
     WHERE p.org_id = $1 AND workflow_state = 'closed'`,
    [orgId]
  );

  const acceptancesResult = await client.query(
    `SELECT COUNT(*) FROM risk_acceptances WHERE status = 'pending'`
  );

  const trackersResult = await client.query(
    `SELECT COUNT(*) FROM issue_tracker_configs WHERE org_id = $1`,
    [orgId]
  );

  const findingsByState: Record<string, number> = {};
  for (const row of stateResult.rows) {
    findingsByState[row.workflow_state] = parseInt(row.count);
  }

  return {
    totalUsers: parseInt(usersResult.rows[0]?.count || '0'),
    totalTeams: parseInt(teamsResult.rows[0]?.count || '0'),
    findingsByState,
    avgResolutionTimeHours: parseFloat(resolutionResult.rows[0]?.avg_hours || '0'),
    openRiskAcceptances: parseInt(acceptancesResult.rows[0]?.count || '0'),
    issueTrackersConfigured: parseInt(trackersResult.rows[0]?.count || '0'),
  };
}
