import { describe, it, expect, beforeEach, afterEach, vi } from 'bun:test';
import Fastify, { FastifyInstance } from 'fastify';

// Mock pg module before any imports
const mockQuery = vi.fn();
const mockConnect = vi.fn();
const mockEnd = vi.fn();

vi.doMock('pg', () => ({
  Client: vi.fn().mockImplementation(() => ({
    connect: mockConnect,
    query: mockQuery,
    end: mockEnd,
  })),
}));

// Mock BullMQ and Redis
vi.doMock('bullmq', () => ({
  Queue: vi.fn().mockImplementation(() => ({
    add: vi.fn().mockResolvedValue({ id: 'job-1' }),
    close: vi.fn().mockResolvedValue(undefined),
  })),
  Worker: vi.fn().mockImplementation(() => ({
    on: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  })),
}));

vi.doMock('ioredis', () => ({
  default: vi.fn().mockImplementation(() => ({
    disconnect: vi.fn().mockResolvedValue(undefined),
  })),
}));

// Mock events
vi.doMock('../src/events', () => ({
  emitScanEvent: vi.fn(),
}));

describe('API Endpoints', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = Fastify({ logger: false });

    // Register routes manually
    const { parsers, SUPPORTED_SCANNERS } = await import('../src/parsers');
    const {
      createProject,
      listProjects,
      getProjectById,
      createScan,
      getScanById,
      listScansByProject,
      listScanRuns,
      listScanRunsByScanIds,
      listFindings,
      createScanRun,
    } = await import('../src/db');

    const { scannerQueue } = await import('../src/queue');

    // Project routes
    app.post('/projects', async (request, reply) => {
      const { name, path } = request.body as { name: string; path: string };
      const project = await createProject(name, path);
      reply.status(201).send(project);
    });

    app.get('/projects', async (request, reply) => {
      const projects = await listProjects();
      reply.send(projects);
    });

    // Scan routes
    app.post('/scans', async (request, reply) => {
      const { projectId, scanners } = request.body as { projectId: string; scanners: typeof SUPPORTED_SCANNERS };
      if (!scanners || scanners.length === 0) {
        reply.status(400).send({ error: 'Select at least one scanner' });
        return;
      }

      const project = await getProjectById(projectId);
      if (!project) {
        reply.status(404).send({ error: 'Project not found' });
        return;
      }

      const scanRecord = await createScan(projectId, scanners);

      for (const scannerType of scanners) {
        const run = await createScanRun(scanRecord.id, scannerType);
        await scannerQueue.add('scan-job', {
          scanId: scanRecord.id,
          scanRunId: run.id,
          hostPath: project.path,
          scannerType,
        });
      }

      reply.status(202).send(scanRecord);
    });

    app.get('/scans/:id', async (request, reply) => {
      const { id } = request.params as { id: string };
      const scan = await getScanById(id);
      if (!scan) {
        reply.status(404).send({ error: 'Scan not found' });
        return;
      }
      reply.send(scan);
    });

    app.get('/projects/:id/scans', async (request, reply) => {
      const { id } = request.params as { id: string };
      const scans = await listScansByProject(id);
      const scanIds = scans.map((s) => s.id);
      const runs = await listScanRunsByScanIds(scanIds);
      const runsByScan = runs.reduce<Record<string, typeof runs>>((acc, run) => {
        acc[run.scan_id] = acc[run.scan_id] || [];
        acc[run.scan_id].push(run);
        return acc;
      }, {});

      const payload = scans.map((scan) => ({
        ...scan,
        runs: runsByScan[scan.id] || [],
      }));

      reply.send(payload);
    });

    app.get('/scans/:id/runs', async (request, reply) => {
      const { id } = request.params as { id: string };
      const runs = await listScanRuns(id);
      reply.send(runs);
    });

    app.get('/findings', async (request, reply) => {
      const { severity, type } = request.query as { severity?: string; type?: string };
      const rows = await listFindings(severity, type);
      reply.send(rows);
    });
  });

  afterEach(async () => {
    await app.close();
  });

  describe('POST /projects', () => {
    it('should create a new project and return 201', async () => {
      const mockProject = {
        id: 'test-uuid',
        name: 'Test Project',
        path: '/path/to/project',
        created_at: '2024-01-01T00:00:00Z',
      };
      mockQuery.mockResolvedValue({ rows: [mockProject] });

      const response = await app.inject({
        method: 'POST',
        url: '/projects',
        payload: { name: 'Test Project', path: '/path/to/project' },
      });

      expect(response.statusCode).toBe(201);
      expect(response.json()).toEqual(mockProject);
      expect(mockQuery).toHaveBeenCalledWith(
        'INSERT INTO projects (name, path) VALUES ($1, $2) RETURNING id, name, path, created_at',
        ['Test Project', '/path/to/project']
      );
    });

    it('should return 400 for missing name', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/projects',
        payload: { path: '/path' },
      });

      expect(response.statusCode).toBe(400);
    });

    it('should return 400 for missing path', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/projects',
        payload: { name: 'Test' },
      });

      expect(response.statusCode).toBe(400);
    });

    it('should return 400 for empty body', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/projects',
        payload: {},
      });

      expect(response.statusCode).toBe(400);
    });
  });

  describe('GET /projects', () => {
    it('should return list of projects', async () => {
      const mockProjects = [
        { id: '1', name: 'Project 1', path: '/path1', created_at: '2024-01-01' },
        { id: '2', name: 'Project 2', path: '/path2', created_at: '2024-01-02' },
      ];
      mockQuery.mockResolvedValue({ rows: mockProjects });

      const response = await app.inject({
        method: 'GET',
        url: '/projects',
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual(mockProjects);
    });

    it('should return empty array when no projects exist', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const response = await app.inject({
        method: 'GET',
        url: '/projects',
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual([]);
    });
  });

  describe('POST /scans', () => {
    it('should create a new scan and return 202', async () => {
      const mockProject = { id: 'project-id', name: 'Test', path: '/path' };
      const mockScan = {
        id: 'scan-id',
        project_id: 'project-id',
        scanners: ['trivy'],
        status: 'queued',
      };
      const mockScanRun = {
        id: 'run-id',
        scan_id: 'scan-id',
        scanner_name: 'trivy',
        status: 'pending',
      };

      mockQuery.mockImplementation((query) => {
        if (query.includes('projects')) return { rows: [mockProject] };
        if (query.includes('scans') && query.includes('INSERT')) return { rows: [mockScan] };
        if (query.includes('scan_runs') && query.includes('INSERT')) return { rows: [mockScanRun] };
        return { rows: [] };
      });

      const response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { projectId: 'project-id', scanners: ['trivy'] },
      });

      expect(response.statusCode).toBe(202);
      expect(response.json()).toEqual(mockScan);
    });

    it('should return 400 when no scanners provided', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { projectId: 'project-id', scanners: [] },
      });

      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error: 'Select at least one scanner' });
    });

    it('should return 404 when project not found', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { projectId: 'non-existent', scanners: ['trivy'] },
      });

      expect(response.statusCode).toBe(404);
      expect(response.json()).toEqual({ error: 'Project not found' });
    });
  });

  describe('GET /scans/:id', () => {
    it('should return scan by ID', async () => {
      const mockScan = {
        id: 'scan-id',
        project_id: 'project-id',
        scanners: ['trivy'],
        status: 'running',
      };
      mockQuery.mockResolvedValue({ rows: [mockScan] });

      const response = await app.inject({
        method: 'GET',
        url: '/scans/scan-id',
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual(mockScan);
    });

    it('should return 404 when scan not found', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const response = await app.inject({
        method: 'GET',
        url: '/scans/non-existent',
      });

      expect(response.statusCode).toBe(404);
      expect(response.json()).toEqual({ error: 'Scan not found' });
    });
  });

  describe('GET /projects/:id/scans', () => {
    it('should return scan history for a project with runs', async () => {
      const mockScans = [
        { id: 'scan-1', project_id: 'project-id', status: 'completed' },
        { id: 'scan-2', project_id: 'project-id', status: 'running' },
      ];
      const mockRuns = [
        { id: 'run-1', scan_id: 'scan-1', scanner_name: 'trivy', status: 'completed' },
        { id: 'run-2', scan_id: 'scan-2', scanner_name: 'trivy', status: 'running' },
      ];

      mockQuery.mockImplementation((query) => {
        if (query.includes('scans') && !query.includes('scan_runs')) {
          return { rows: mockScans };
        }
        if (query.includes('scan_runs')) {
          return { rows: mockRuns };
        }
        return { rows: [] };
      });

      const response = await app.inject({
        method: 'GET',
        url: '/projects/project-id/scans',
      });

      expect(response.statusCode).toBe(200);
      const result = response.json();
      expect(result).toHaveLength(2);
      expect(result[0].runs).toHaveLength(1);
      expect(result[1].runs).toHaveLength(1);
    });

    it('should handle scans without runs', async () => {
      const mockScans = [{ id: 'scan-1', project_id: 'project-id', status: 'pending' }];

      mockQuery.mockResolvedValue({ rows: mockScans });

      const response = await app.inject({
        method: 'GET',
        url: '/projects/project-id/scans',
      });

      expect(response.statusCode).toBe(200);
      const result = response.json();
      expect(result[0].runs).toEqual([]);
    });
  });

  describe('GET /scans/:id/runs', () => {
    it('should return scan runs for a scan', async () => {
      const mockRuns = [
        { id: 'run-1', scan_id: 'scan-id', scanner_name: 'trivy' },
        { id: 'run-2', scan_id: 'scan-id', scanner_name: 'semgrep' },
      ];
      mockQuery.mockResolvedValue({ rows: mockRuns });

      const response = await app.inject({
        method: 'GET',
        url: '/scans/scan-id/runs',
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual(mockRuns);
    });
  });

  describe('GET /findings', () => {
    it('should return all findings without filters', async () => {
      const mockFindings = [
        { id: 'f1', severity: 'HIGH', scanner_name: 'trivy' },
        { id: 'f2', severity: 'MEDIUM', scanner_name: 'semgrep' },
      ];
      mockQuery.mockResolvedValue({ rows: mockFindings });

      const response = await app.inject({
        method: 'GET',
        url: '/findings',
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual(mockFindings);
    });

    it('should filter findings by severity', async () => {
      mockQuery.mockResolvedValue({ rows: [{ id: 'f1', severity: 'HIGH' }] });

      const response = await app.inject({
        method: 'GET',
        url: '/findings?severity=HIGH',
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual([{ id: 'f1', severity: 'HIGH' }]);
    });

    it('should filter findings by scanner type', async () => {
      mockQuery.mockResolvedValue({ rows: [{ id: 'f1', scanner_name: 'trivy' }] });

      const response = await app.inject({
        method: 'GET',
        url: '/findings?type=trivy',
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual([{ id: 'f1', scanner_name: 'trivy' }]);
    });

    it('should filter findings by both severity and type', async () => {
      mockQuery.mockResolvedValue({ rows: [{ id: 'f1', severity: 'CRITICAL', scanner_name: 'trivy' }] });

      const response = await app.inject({
        method: 'GET',
        url: '/findings?severity=CRITICAL&type=trivy',
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual([{ id: 'f1', severity: 'CRITICAL', scanner_name: 'trivy' }]);
    });
  });

  describe('Response Format', () => {
    it('should return proper JSON content type', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const response = await app.inject({
        method: 'GET',
        url: '/projects',
      });

      expect(response.headers['content-type']).toContain('application/json');
    });

    it('should return proper status codes', async () => {
      // 201 for successful creation
      mockQuery.mockResolvedValue({ rows: [{ id: 'test', name: 'Test', path: '/path', created_at: '2024-01-01' }] });
      let response = await app.inject({
        method: 'POST',
        url: '/projects',
        payload: { name: 'Test', path: '/path' },
      });
      expect(response.statusCode).toBe(201);

      // 202 for accepted async operations
      mockQuery.mockImplementation((query) => {
        if (query.includes('projects')) return { rows: [{ id: 'project-id', name: 'Test', path: '/path' }] };
        if (query.includes('scans') && query.includes('INSERT')) return { rows: [{ id: 'scan-id', project_id: 'project-id', scanners: ['trivy'], status: 'queued' }] };
        if (query.includes('scan_runs')) return { rows: [{ id: 'run-id', scan_id: 'scan-id', scanner_name: 'trivy', status: 'pending' }] };
        return { rows: [] };
      });

      response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { projectId: 'project-id', scanners: ['trivy'] },
      });
      expect(response.statusCode).toBe(202);

      // 200 for successful reads
      mockQuery.mockResolvedValue({ rows: [] });
      response = await app.inject({
        method: 'GET',
        url: '/projects',
      });
      expect(response.statusCode).toBe(200);
    });
  });
});
