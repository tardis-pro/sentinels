// Collaboration API Routes - Issue #6
import { FastifyInstance } from 'fastify';
import {
  createUser,
  getUser,
  listUsers,
  createOrganization,
  createTeam,
  addTeamMember,
  getTeam,
  listTeams,
  assignFinding,
  unassignFinding,
  getFindingAssignment,
  transitionFindingState,
  getFindingWorkflowHistory,
  getFindingsByState,
  addComment,
  updateComment,
  deleteComment,
  getFindingComments,
  resolveComment,
  configureSLA,
  getSLAConfigs,
  requestRiskAcceptance,
  approveRiskAcceptance,
  rejectRiskAcceptance,
  getPendingRiskAcceptances,
  configureIssueTracker,
  getIssueTrackers,
  syncFindingToIssue,
  getFindingIssueSyncs,
  getCollaborationStats,
  createCollaborationTables,
} from './index';

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

export async function collaborationRoutes(fastify: FastifyInstance) {
  fastify.addHook('onReady', async () => {
    await createCollaborationTables();
  });

  // === User Management ===

  fastify.get('/users', async (request, reply) => {
    const users = await listUsers();
    return { users, total: users.length };
  });

  fastify.get('/users/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const user = await getUser(id);
    if (!user) {
      reply.status(404).send({ error: 'User not found' });
      return;
    }
    return user;
  });

  fastify.post('/users', async (request, reply) => {
    const { email, name, avatarUrl } = request.body as { email: string; name: string; avatarUrl?: string };
    const user = await createUser(email, name, avatarUrl);
    reply.status(201).send(user);
  });

  // === Organizations & Teams ===

  fastify.post('/organizations', async (request, reply) => {
    const { name, slug } = request.body as { name: string; slug: string };
    const org = await createOrganization(name, slug);
    reply.status(201).send(org);
  });

  fastify.get('/teams', async (request, reply) => {
    const { orgId } = request.query as { orgId?: string };
    const teams = await listTeams(orgId);
    return { teams, total: teams.length };
  });

  fastify.post('/teams', async (request, reply) => {
    const { orgId, name, description } = request.body as { orgId: string; name: string; description?: string };
    const team = await createTeam(orgId, name, description);
    reply.status(201).send(team);
  });

  fastify.post('/teams/:id/members', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { userId, role } = request.body as { userId: string; role?: 'owner' | 'admin' | 'member' | 'viewer' };
    await addTeamMember(id, userId, role);
    reply.status(201).send({ success: true });
  });

  fastify.get('/teams/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const team = await getTeam(id);
    if (!team) {
      reply.status(404).send({ error: 'Team not found' });
      return;
    }
    return team;
  });

  // === Finding Assignment ===

  fastify.post('/findings/:id/assign', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { assignedTo, assignedBy, reason } = request.body as { assignedTo: string; assignedBy: string; reason?: string };
    const assignment = await assignFinding(id, assignedTo, assignedBy, reason);
    return assignment;
  });

  fastify.post('/findings/:id/unassign', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { unassignedBy } = request.body as { unassignedBy: string };
    await unassignFinding(id, unassignedBy);
    return { success: true };
  });

  fastify.get('/findings/:id/assignment', async (request, reply) => {
    const { id } = request.params as { id: string };
    const assignment = await getFindingAssignment(id);
    return { assignment };
  });

  // === Workflow State Management ===

  fastify.post('/findings/:id/transition', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { toState, changedBy, comment } = request.body as { toState: string; changedBy: string; comment?: string };
    const result = await transitionFindingState(id, toState as any, changedBy, comment);
    if (!result.success) {
      reply.status(400).send({ error: result.error });
      return;
    }
    return { success: true };
  });

  fastify.get('/findings/:id/workflow', async (request, reply) => {
    const { id } = request.params as { id: string };
    const history = await getFindingWorkflowHistory(id);
    return { history, total: history.length };
  });

  fastify.get('/findings/state/:state', async (request, reply) => {
    const { state } = request.params as { state: string };
    const findings = await getFindingsByState(state as any);
    return { findings, total: findings.length };
  });

  // === Comments ===

  fastify.post('/findings/:id/comments', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { userId, content, parentId } = request.body as { userId: string; content: string; parentId?: string };
    const comment = await addComment(id, userId, content, parentId);
    reply.status(201).send(comment);
  });

  fastify.get('/findings/:id/comments', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { includeResolved } = request.query as { includeResolved?: string };
    const comments = await getFindingComments(id, includeResolved === 'true');
    return { comments, total: comments.length };
  });

  fastify.patch('/comments/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { content } = request.body as { content: string };
    const comment = await updateComment(id, content);
    if (!comment) {
      reply.status(404).send({ error: 'Comment not found' });
      return;
    }
    return comment;
  });

  fastify.delete('/comments/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const deleted = await deleteComment(id);
    if (!deleted) {
      reply.status(404).send({ error: 'Comment not found' });
      return;
    }
    reply.status(204).send();
  });

  fastify.post('/comments/:id/resolve', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { resolved } = request.body as { resolved?: boolean };
    const comment = await resolveComment(id, resolved !== false);
    if (!comment) {
      reply.status(404).send({ error: 'Comment not found' });
      return;
    }
    return comment;
  });

  // === SLA Configuration ===

  fastify.post('/sla', async (request, reply) => {
    const { orgId, severity, targetHours, escalationEnabled, escalationEmail } = request.body as {
      orgId: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      targetHours: number;
      escalationEnabled?: boolean;
      escalationEmail?: string;
    };
    const sla = await configureSLA(orgId, severity, targetHours, escalationEnabled, escalationEmail);
    reply.status(201).send(sla);
  });

  fastify.get('/sla', async (request, reply) => {
    const { orgId } = request.query as { orgId: string };
    if (!isUuid(orgId)) {
      reply.status(400).send({ error: 'orgId must be a valid UUID' });
      return;
    }
    const configs = await getSLAConfigs(orgId);
    return { configs };
  });

  // === Risk Acceptance ===

  fastify.post('/risk-acceptance', async (request, reply) => {
    const { findingId, acceptedBy, reason, expiresAt } = request.body as {
      findingId: string;
      acceptedBy: string;
      reason: string;
      expiresAt?: string;
    };
    const acceptance = await requestRiskAcceptance(findingId, acceptedBy, reason, expiresAt ? new Date(expiresAt) : undefined);
    reply.status(201).send(acceptance);
  });

  fastify.post('/risk-acceptance/:id/approve', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { approverEmail } = request.body as { approverEmail: string };
    const acceptance = await approveRiskAcceptance(id, approverEmail);
    if (!acceptance) {
      reply.status(404).send({ error: 'Risk acceptance not found' });
      return;
    }
    return acceptance;
  });

  fastify.post('/risk-acceptance/:id/reject', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { approverEmail } = request.body as { approverEmail: string };
    const acceptance = await rejectRiskAcceptance(id, approverEmail);
    if (!acceptance) {
      reply.status(404).send({ error: 'Risk acceptance not found' });
      return;
    }
    return acceptance;
  });

  fastify.get('/risk-acceptance/pending', async (request, reply) => {
    const { orgId } = request.query as { orgId: string };
    if (!isUuid(orgId)) {
      reply.status(400).send({ error: 'orgId must be a valid UUID' });
      return;
    }
    const acceptances = await getPendingRiskAcceptances(orgId);
    return { acceptances, total: acceptances.length };
  });

  // === Issue Tracker Integration ===

  fastify.post('/issue-trackers', async (request, reply) => {
    const { orgId, provider, name, config, enabled } = request.body as {
      orgId: string;
      provider: 'jira' | 'linear' | 'asana' | 'notion' | 'github';
      name: string;
      config: any;
      enabled?: boolean;
    };
    const tracker = await configureIssueTracker({ orgId, provider, name, config, enabled });
    reply.status(201).send(tracker);
  });

  fastify.get('/issue-trackers', async (request, reply) => {
    const { orgId, enabledOnly } = request.query as { orgId: string; enabledOnly?: string };
    if (!isUuid(orgId)) {
      reply.status(400).send({ error: 'orgId must be a valid UUID' });
      return;
    }
    const trackers = await getIssueTrackers(orgId, enabledOnly === 'true');
    return { trackers, total: trackers.length };
  });

  fastify.post('/findings/:id/sync-issue', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { trackerId, externalIssueId, externalIssueUrl } = request.body as {
      trackerId: string;
      externalIssueId: string;
      externalIssueUrl?: string;
    };
    await syncFindingToIssue(id, trackerId, externalIssueId, externalIssueUrl);
    return { success: true };
  });

  fastify.get('/findings/:id/issue-syncs', async (request, reply) => {
    const { id } = request.params as { id: string };
    const syncs = await getFindingIssueSyncs(id);
    return { syncs, total: syncs.length };
  });

  // === Collaboration Statistics ===

  fastify.get('/collaboration/stats', async (request, reply) => {
    const { orgId } = request.query as { orgId: string };
    if (!isUuid(orgId)) {
      reply.status(400).send({ error: 'orgId must be a valid UUID' });
      return;
    }
    const stats = await getCollaborationStats(orgId);
    return stats;
  });
}
