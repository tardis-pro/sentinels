import { describe, it, expect, beforeEach, vi, Mock } from 'bun:test';

// Create mock functions first
const mockQuery = vi.fn();
const mockConnect = vi.fn();
const mockEnd = vi.fn();

// Mock the pg module
vi.doMock('pg', () => ({
  Client: vi.fn().mockImplementation(() => ({
    connect: mockConnect,
    query: mockQuery,
    end: mockEnd,
  })),
}));

// Test the db functions by importing them after mocking
describe('Database Operations', () => {
  let createProject: any;
  let listProjects: any;
  let getProjectById: any;
  let createScan: any;
  let getScanById: any;
  let listScansByProject: any;
  let createScanRun: any;
  let listScanRuns: any;
  let listScanRunsByScanIds: any;
  let listFindings: any;
  let updateScanStatus: any;
  let markScanFailed: any;
  let updateScanRunStatus: any;
  let areAllScanRunsFinished: any;
  let insertFindings: any;
  let connectDb: any;
  let createTables: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    // Reset modules to get fresh imports with mocks
    vi.resetModules();

    // Re-setup mocks
    vi.doMock('pg', () => ({
      Client: vi.fn().mockImplementation(() => ({
        connect: mockConnect,
        query: mockQuery,
        end: mockEnd,
      })),
    }));

    // Import db module
    const db = await import('../src/db');
    createProject = db.createProject;
    listProjects = db.listProjects;
    getProjectById = db.getProjectById;
    createScan = db.createScan;
    getScanById = db.getScanById;
    listScansByProject = db.listScansByProject;
    createScanRun = db.createScanRun;
    listScanRuns = db.listScanRuns;
    listScanRunsByScanIds = db.listScanRunsByScanIds;
    listFindings = db.listFindings;
    updateScanStatus = db.updateScanStatus;
    markScanFailed = db.markScanFailed;
    updateScanRunStatus = db.updateScanRunStatus;
    areAllScanRunsFinished = db.areAllScanRunsFinished;
    insertFindings = db.insertFindings;
    connectDb = db.connectDb;
    createTables = db.createTables;
  });

  describe('connectDb', () => {
    it('should connect to database', async () => {
      mockConnect.mockResolvedValue(undefined);
      await connectDb();
      expect(mockConnect).toHaveBeenCalled();
    });
  });

  describe('createTables', () => {
    it('should execute create tables query', async () => {
      mockQuery.mockResolvedValue({ rows: [] });
      await createTables();
      expect(mockQuery).toHaveBeenCalled();
      const queryCall = mockQuery.mock.calls[0][0];
      expect(queryCall).toContain('CREATE TABLE IF NOT EXISTS projects');
      expect(queryCall).toContain('CREATE TABLE IF NOT EXISTS scans');
      expect(queryCall).toContain('CREATE TABLE IF NOT EXISTS scan_runs');
      expect(queryCall).toContain('CREATE TABLE IF NOT EXISTS findings');
    });
  });

  describe('Project Operations', () => {
    describe('createProject', () => {
      it('should create a new project', async () => {
        const mockProject = {
          id: 'test-uuid',
          name: 'Test Project',
          path: '/path/to/project',
          created_at: '2024-01-01T00:00:00Z',
        };
        mockQuery.mockResolvedValue({ rows: [mockProject] });

        const result = await createProject('Test Project', '/path/to/project');

        expect(mockQuery).toHaveBeenCalledWith(
          'INSERT INTO projects (name, path) VALUES ($1, $2) RETURNING id, name, path, created_at',
          ['Test Project', '/path/to/project']
        );
        expect(result).toEqual(mockProject);
      });
    });

    describe('listProjects', () => {
      it('should return all projects ordered by created_at desc', async () => {
        const mockProjects = [
          { id: '1', name: 'Project 1', path: '/path1', created_at: '2024-01-02T00:00:00Z' },
          { id: '2', name: 'Project 2', path: '/path2', created_at: '2024-01-01T00:00:00Z' },
        ];
        mockQuery.mockResolvedValue({ rows: mockProjects });

        const result = await listProjects();

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT id, name, path, created_at FROM projects ORDER BY created_at DESC'
        );
        expect(result).toEqual(mockProjects);
      });

      it('should return empty array when no projects exist', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await listProjects();

        expect(result).toEqual([]);
      });
    });

    describe('getProjectById', () => {
      it('should return project when found', async () => {
        const mockProject = { id: 'test-id', name: 'Test', path: '/path', created_at: '2024-01-01' };
        mockQuery.mockResolvedValue({ rows: [mockProject] });

        const result = await getProjectById('test-id');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT id, name, path, created_at FROM projects WHERE id = $1',
          ['test-id']
        );
        expect(result).toEqual(mockProject);
      });

      it('should return null when project not found', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await getProjectById('non-existent-id');

        expect(result).toBeNull();
      });
    });
  });

  describe('Scan Operations', () => {
    describe('createScan', () => {
      it('should create a new scan with queued status', async () => {
        const mockScan = {
          id: 'scan-uuid',
          project_id: 'project-id',
          scanners: ['trivy', 'semgrep'],
          status: 'queued',
          error_log: null,
          started_at: null,
          completed_at: null,
          created_at: '2024-01-01T00:00:00Z',
        };
        mockQuery.mockResolvedValue({ rows: [mockScan] });

        const result = await createScan('project-id', ['trivy', 'semgrep']);

        expect(mockQuery).toHaveBeenCalledWith(
          'INSERT INTO scans (project_id, scanners, status) VALUES ($1, $2, $3) RETURNING id, project_id, scanners, status, error_log, started_at, completed_at, created_at',
          ['project-id', ['trivy', 'semgrep'], 'queued']
        );
        expect(result).toEqual(mockScan);
      });
    });

    describe('getScanById', () => {
      it('should return scan when found', async () => {
        const mockScan = { id: 'scan-id', project_id: 'project-id', status: 'running' };
        mockQuery.mockResolvedValue({ rows: [mockScan] });

        const result = await getScanById('scan-id');

        expect(mockQuery).toHaveBeenCalledWith('SELECT * FROM scans WHERE id = $1', ['scan-id']);
        expect(result).toEqual(mockScan);
      });

      it('should return null when scan not found', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await getScanById('non-existent');

        expect(result).toBeNull();
      });
    });

    describe('listScansByProject', () => {
      it('should return scans for a project ordered by created_at desc', async () => {
        const mockScans = [
          { id: 'scan-1', project_id: 'project-id', status: 'completed' },
          { id: 'scan-2', project_id: 'project-id', status: 'running' },
        ];
        mockQuery.mockResolvedValue({ rows: mockScans });

        const result = await listScansByProject('project-id');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM scans WHERE project_id = $1 ORDER BY created_at DESC',
          ['project-id']
        );
        expect(result).toEqual(mockScans);
      });

      it('should return empty array when no scans exist for project', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await listScansByProject('project-without-scans');

        expect(result).toEqual([]);
      });
    });
  });

  describe('Scan Run Operations', () => {
    describe('createScanRun', () => {
      it('should create a new scan run with pending status', async () => {
        const mockScanRun = {
          id: 'run-uuid',
          scan_id: 'scan-id',
          scanner_name: 'trivy',
          status: 'pending',
          error_log: null,
          findings_count: 0,
          started_at: null,
          completed_at: null,
          created_at: '2024-01-01T00:00:00Z',
        };
        mockQuery.mockResolvedValue({ rows: [mockScanRun] });

        const result = await createScanRun('scan-id', 'trivy');

        expect(mockQuery).toHaveBeenCalledWith(
          `INSERT INTO scan_runs (scan_id, scanner_name, status)
           VALUES ($1, $2, $3)
           RETURNING id, scan_id, scanner_name, status, error_log, findings_count, started_at, completed_at, created_at`,
          ['scan-id', 'trivy', 'pending']
        );
        expect(result).toEqual(mockScanRun);
      });
    });

    describe('listScanRuns', () => {
      it('should return scan runs for a scan ordered by created_at desc', async () => {
        const mockRuns = [
          { id: 'run-1', scan_id: 'scan-id', scanner_name: 'trivy' },
          { id: 'run-2', scan_id: 'scan-id', scanner_name: 'semgrep' },
        ];
        mockQuery.mockResolvedValue({ rows: mockRuns });

        const result = await listScanRuns('scan-id');

        expect(mockQuery).toHaveBeenCalledWith(
          `SELECT id, scan_id, scanner_name, status, error_log, findings_count, started_at, completed_at, created_at
           FROM scan_runs
           WHERE scan_id = $1
           ORDER BY created_at DESC`,
          ['scan-id']
        );
        expect(result).toEqual(mockRuns);
      });
    });

    describe('listScanRunsByScanIds', () => {
      it('should return scan runs for multiple scan IDs', async () => {
        const mockRuns = [
          { id: 'run-1', scan_id: 'scan-1', scanner_name: 'trivy' },
          { id: 'run-2', scan_id: 'scan-2', scanner_name: 'semgrep' },
        ];
        mockQuery.mockResolvedValue({ rows: mockRuns });

        const result = await listScanRunsByScanIds(['scan-1', 'scan-2']);

        expect(mockQuery).toHaveBeenCalledWith(
          `SELECT id, scan_id, scanner_name, status, error_log, findings_count, started_at, completed_at, created_at
           FROM scan_runs
           WHERE scan_id = ANY($1::uuid[])
           ORDER BY created_at DESC`,
          [['scan-1', 'scan-2']]
        );
        expect(result).toEqual(mockRuns);
      });

      it('should return empty array for empty scan IDs array', async () => {
        const result = await listScanRunsByScanIds([]);

        expect(result).toEqual([]);
        expect(mockQuery).not.toHaveBeenCalled();
      });
    });
  });

  describe('Findings Operations', () => {
    describe('listFindings', () => {
      it('should return all findings when no filters provided', async () => {
        const mockFindings = [
          { id: 'f1', severity: 'HIGH', scanner_name: 'trivy' },
          { id: 'f2', severity: 'MEDIUM', scanner_name: 'semgrep' },
        ];
        mockQuery.mockResolvedValue({ rows: mockFindings });

        const result = await listFindings();

        expect(mockQuery).toHaveBeenCalledWith('SELECT * FROM findings WHERE 1=1 ORDER BY created_at DESC', []);
        expect(result).toEqual(mockFindings);
      });

      it('should filter findings by severity', async () => {
        const mockFindings = [{ id: 'f1', severity: 'HIGH', scanner_name: 'trivy' }];
        mockQuery.mockResolvedValue({ rows: mockFindings });

        const result = await listFindings('HIGH');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM findings WHERE 1=1 AND severity = $1 ORDER BY created_at DESC',
          ['HIGH']
        );
        expect(result).toEqual(mockFindings);
      });

      it('should filter findings by scanner name', async () => {
        const mockFindings = [{ id: 'f1', severity: 'HIGH', scanner_name: 'trivy' }];
        mockQuery.mockResolvedValue({ rows: mockFindings });

        const result = await listFindings(undefined, 'trivy');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM findings WHERE 1=1 AND scanner_name = $1 ORDER BY created_at DESC',
          ['trivy']
        );
        expect(result).toEqual(mockFindings);
      });

      it('should filter findings by both severity and scanner name', async () => {
        const mockFindings = [{ id: 'f1', severity: 'HIGH', scanner_name: 'trivy' }];
        mockQuery.mockResolvedValue({ rows: mockFindings });

        const result = await listFindings('HIGH', 'trivy');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM findings WHERE 1=1 AND severity = $1 AND scanner_name = $2 ORDER BY created_at DESC',
          ['HIGH', 'trivy']
        );
        expect(result).toEqual(mockFindings);
      });
    });

    describe('insertFindings', () => {
      it('should insert multiple findings into database', async () => {
        const findings = [
          {
            scanner_name: 'trivy',
            scanner_version: '0.45.0',
            rule_id: 'CVE-2023-0001',
            fingerprint: 'abc123',
            severity: 'HIGH',
            file_path: 'package.json',
            start_line: 10,
            end_line: 10,
            title: 'Test Finding',
            description: 'Test description',
            remediation: 'Fix it',
            cwe_ids: ['CWE-123'],
            cve_ids: ['CVE-2023-0001'],
            raw_data: { test: 'data' },
          },
        ];
        mockQuery.mockResolvedValue({ rows: [] });

        await insertFindings('scan-id', findings);

        expect(mockQuery).toHaveBeenCalled();
        const insertCall = mockQuery.mock.calls[0];
        expect(insertCall[0]).toContain('INSERT INTO findings');
      });

      it('should handle empty findings array without querying database', async () => {
        await insertFindings('scan-id', []);

        // First call should be the insert for empty array, which returns early
        // Second call would be if we continued, but we return early
        expect(mockQuery).not.toHaveBeenCalled();
      });
    });
  });

  describe('Status Update Operations', () => {
    describe('updateScanStatus', () => {
      it('should update scan status to running', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        await updateScanStatus('scan-id', 'running', new Date());

        expect(mockQuery).toHaveBeenCalled();
        const updateCall = mockQuery.mock.calls[0];
        expect(updateCall[0]).toContain('UPDATE scans SET');
        expect(updateCall[0]).toContain('status = $2');
      });

      it('should handle undefined optional parameters', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        await updateScanStatus('scan-id', 'running');

        const updateCall = mockQuery.mock.calls[0];
        expect(updateCall[0]).toBe('UPDATE scans SET status = $2 WHERE id = $1');
        expect(updateCall[1]).toEqual(['scan-id', 'running']);
      });
    });

    describe('markScanFailed', () => {
      it('should mark scan as failed with error log and completed_at timestamp', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        await markScanFailed('scan-id', 'Scan failed due to error');

        expect(mockQuery).toHaveBeenCalled();
        const updateCall = mockQuery.mock.calls[0];
        expect(updateCall[0]).toContain('status = $2');
        expect(updateCall[0]).toContain('completed_at = $3');
        expect(updateCall[0]).toContain('error_log = $4');
      });
    });

    describe('updateScanRunStatus', () => {
      it('should update scan run status with findings count', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        await updateScanRunStatus('run-id', 'completed', undefined, new Date(), undefined, 5);

        const updateCall = mockQuery.mock.calls[0];
        expect(updateCall[0]).toContain('UPDATE scan_runs SET');
        expect(updateCall[0]).toContain('status = $2');
        expect(updateCall[0]).toContain('findings_count = $5');
      });
    });

    describe('areAllScanRunsFinished', () => {
      it('should return true when all scan runs are completed', async () => {
        mockQuery.mockResolvedValue({ rows: [{ remaining: 0 }] });

        const result = await areAllScanRunsFinished('scan-id');

        expect(mockQuery).toHaveBeenCalledWith(
          `SELECT COUNT(*)::int AS remaining
           FROM scan_runs
           WHERE scan_id = $1 AND status NOT IN ('completed', 'failed')`,
          ['scan-id']
        );
        expect(result).toBe(true);
      });

      it('should return false when scan runs are still pending', async () => {
        mockQuery.mockResolvedValue({ rows: [{ remaining: 2 }] });

        const result = await areAllScanRunsFinished('scan-id');

        expect(result).toBe(false);
      });
    });
  });

  describe('Complex Queries', () => {
    it('should handle finding severe vulnerabilities by project', async () => {
      const mockFindings = [
        { id: 'f1', severity: 'CRITICAL', scanner_name: 'trivy' },
        { id: 'f2', severity: 'HIGH', scanner_name: 'clair' },
      ];
      mockQuery.mockResolvedValue({ rows: mockFindings });

      const result = await listFindings('CRITICAL');

      expect(result).toEqual(mockFindings);
    });

    it('should handle multiple scan runs for a scan', async () => {
      const mockRuns = [
        { id: 'run-1', scan_id: 'scan-id', scanner_name: 'trivy', status: 'completed', findings_count: 10 },
        { id: 'run-2', scan_id: 'scan-id', scanner_name: 'semgrep', status: 'running' },
        { id: 'run-3', scan_id: 'scan-id', scanner_name: 'bandit', status: 'failed', error_log: 'Timeout' },
      ];
      mockQuery.mockResolvedValue({ rows: mockRuns });

      const result = await listScanRuns('scan-id');

      expect(result).toHaveLength(3);
    });
  });

  describe('Data Integrity', () => {
    it('should properly serialize arrays for PostgreSQL', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      await createScan('project-id', ['trivy', 'semgrep', 'bandit']);

      const insertCall = mockQuery.mock.calls[0];
      expect(insertCall[1][1]).toEqual(['trivy', 'semgrep', 'bandit']);
    });

    it('should handle UUID types correctly', async () => {
      const mockProject = { id: '550e8400-e29b-41d4-a716-446655440000', name: 'Test', path: '/path', created_at: '2024-01-01' };
      mockQuery.mockResolvedValue({ rows: [mockProject] });

      const result = await createProject('Test', '/path');

      expect(result.id).toBe('550e8400-e29b-41d4-a716-446655440000');
    });
  });
});
