import { FastifyInstance } from 'fastify';
import {
  createPolicy,
  getPolicyById,
  listPolicies,
  updatePolicy,
  deletePolicy,
  evaluateFindingAgainstPolicies,
  evaluateProjectCompliance,
  seedBuiltInPolicies,
  getComplianceFrameworks,
  createComplianceFramework,
  getPolicyStatistics,
  connectPolicyDb,
  type Policy,
  type PolicyCategory,
  type EnforcementAction,
} from './service';

export async function policyRoutes(fastify: FastifyInstance) {
  // Ensure database connection on startup
  fastify.addHook('onReady', async () => {
    await connectPolicyDb();
  });

  // =========================================================================
  // Policy CRUD
  // =========================================================================

  // GET /api/policies - List all policies
  fastify.get<{
    Querystring: {
      category?: PolicyCategory;
      enabled?: string;
      projectId?: string;
      limit?: string;
      offset?: string;
    };
  }>('/policies', async (request, reply) => {
    try {
      const { category, enabled, projectId, limit, offset } = request.query;
      
      const policies = await listPolicies({
        category,
        enabled: enabled !== undefined ? enabled === 'true' : undefined,
        projectId,
        limit: limit ? parseInt(limit) : undefined,
        offset: offset ? parseInt(offset) : undefined,
      });

      return policies;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to list policies' });
    }
  });

  // GET /api/policies/statistics - Get policy statistics
  fastify.get('/policies/statistics', async (request, reply) => {
    try {
      const stats = await getPolicyStatistics();
      return stats;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get policy statistics' });
    }
  });

  // GET /api/policies/:id - Get a specific policy
  fastify.get<{ Params: { id: string } }>('/policies/:id', async (request, reply) => {
    try {
      const { id } = request.params;
      const policy = await getPolicyById(id);
      
      if (!policy) {
        reply.status(404).send({ error: 'Policy not found' });
        return;
      }

      return policy;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get policy' });
    }
  });

  // POST /api/policies - Create a new policy
  fastify.post<{
    Body: {
      name: string;
      description: string;
      category: PolicyCategory;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
      regoPolicy: string;
      enabled?: boolean;
      enforcementAction: EnforcementAction;
      tags?: string[];
      projectId?: string;
    };
  }>('/policies', async (request, reply) => {
    try {
      const { name, description, category, severity, regoPolicy, enabled, enforcementAction, tags, projectId } = request.body;

      if (!name || !description || !category || !severity || !regoPolicy || !enforcementAction) {
        reply.status(400).send({ 
          error: 'Missing required fields: name, description, category, severity, regoPolicy, enforcementAction' 
        });
        return;
      }

      const policy = await createPolicy({
        name,
        description,
        category,
        severity,
        regoPolicy,
        enabled,
        enforcementAction,
        tags,
        projectId,
      });

      reply.status(201).send(policy);
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to create policy' });
    }
  });

  // PUT /api/policies/:id - Update a policy
  fastify.put<{
    Params: { id: string };
    Body: Partial<{
      name: string;
      description: string;
      category: PolicyCategory;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
      regoPolicy: string;
      enabled: boolean;
      enforcementAction: EnforcementAction;
      tags: string[];
    }>;
  }>('/policies/:id', async (request, reply) => {
    try {
      const { id } = request.params;
      const updates = request.body;

      const policy = await updatePolicy(id, updates);

      if (!policy) {
        reply.status(404).send({ error: 'Policy not found' });
        return;
      }

      return policy;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to update policy' });
    }
  });

  // DELETE /api/policies/:id - Delete a policy
  fastify.delete<{ Params: { id: string } }>('/policies/:id', async (request, reply) => {
    try {
      const { id } = request.params;
      const deleted = await deletePolicy(id);

      if (!deleted) {
        reply.status(404).send({ error: 'Policy not found' });
        return;
      }

      reply.status(204).send();
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to delete policy' });
    }
  });

  // =========================================================================
  // Policy Evaluation
  // =========================================================================

  // POST /api/policies/evaluate/finding - Evaluate a finding against policies
  fastify.post<{
    Params: { findingId: string };
    Body: {
      projectId: string;
      policyIds?: string[];
    };
  }>('/policies/evaluate/finding/:findingId', async (request, reply) => {
    try {
      const { findingId } = request.params;
      const { projectId, policyIds } = request.body;

      if (!projectId) {
        reply.status(400).send({ error: 'Missing required field: projectId' });
        return;
      }

      const evaluations = await evaluateFindingAgainstPolicies(findingId, projectId, policyIds);
      return evaluations;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to evaluate finding' });
    }
  });

  // POST /api/policies/evaluate/project - Evaluate project compliance
  fastify.post<{
    Body: {
      projectId: string;
      frameworkName?: string;
    };
  }>('/policies/evaluate/project', async (request, reply) => {
    try {
      const { projectId, frameworkName } = request.body;

      if (!projectId) {
        reply.status(400).send({ error: 'Missing required field: projectId' });
        return;
      }

      const compliance = await evaluateProjectCompliance(projectId, frameworkName);
      return compliance;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to evaluate project compliance' });
    }
  });

  // POST /api/policies/evaluate/batch - Batch evaluate multiple findings
  fastify.post<{
    Body: {
      findingIds: string[];
      projectId: string;
      policyIds?: string[];
    };
  }>('/policies/evaluate/batch', async (request, reply) => {
    try {
      const { findingIds, projectId, policyIds } = request.body;

      if (!findingIds || !projectId || findingIds.length === 0) {
        reply.status(400).send({ error: 'Missing required fields: findingIds, projectId' });
        return;
      }

      const results = await Promise.all(
        findingIds.map(findingId => 
          evaluateFindingAgainstPolicies(findingId, projectId, policyIds)
        )
      );

      return {
        totalFindings: findingIds.length,
        totalEvaluations: results.flat(),
        summary: {
          passed: results.flat().filter(e => e.passed).length,
          failed: results.flat().filter(e => !e.passed).length,
        },
      };
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to batch evaluate findings' });
    }
  });

  // =========================================================================
  // Compliance Frameworks
  // =========================================================================

  // GET /api/policies/compliance/frameworks - List compliance frameworks
  fastify.get('/policies/compliance/frameworks', async (request, reply) => {
    try {
      const frameworks = await getComplianceFrameworks();
      return frameworks;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get compliance frameworks' });
    }
  });

  // POST /api/policies/compliance/frameworks - Create a compliance framework
  fastify.post<{
    Body: {
      name: string;
      description: string;
      controls: Array<{
        id?: string;
        name: string;
        description: string;
        policyIds?: string[];
      }>;
    };
  }>('/policies/compliance/frameworks', async (request, reply) => {
    try {
      const { name, description, controls } = request.body;

      if (!name || !description || !controls) {
        reply.status(400).send({ error: 'Missing required fields: name, description, controls' });
        return;
      }

      const framework = await createComplianceFramework({ name, description, controls });
      reply.status(201).send(framework);
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to create compliance framework' });
    }
  });

  // =========================================================================
  // Policy Templates
  // =========================================================================

  // POST /api/policies/templates/seed - Seed built-in policy templates
  fastify.post('/policies/templates/seed', async (request, reply) => {
    try {
      const policies = await seedBuiltInPolicies();
      return {
        message: `Seeded ${policies.length} built-in policies`,
        policies,
      };
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to seed policy templates' });
    }
  });
}
