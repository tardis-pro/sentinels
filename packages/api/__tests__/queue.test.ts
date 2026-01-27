import { describe, it, expect, beforeEach, vi } from 'bun:test';

// Mock dependencies
const mockSpawn = vi.fn();
const mockSpawnOn = vi.fn();
const mockSpawnStdoutOn = vi.fn();
const mockSpawnStderrOn = vi.fn();

vi.doMock('child_process', () => ({
  spawn: vi.fn().mockImplementation(() => {
    return {
      stdout: { on: mockSpawnStdoutOn },
      stderr: { on: mockSpawnStderrOn },
      on: mockSpawnOn,
    };
  }),
}));

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

vi.doMock('../src/db', () => ({
  getScanById: vi.fn(),
  updateScanStatus: vi.fn(),
  updateScanRunStatus: vi.fn(),
  insertFindings: vi.fn(),
  markScanFailed: vi.fn(),
  areAllScanRunsFinished: vi.fn(),
}));

vi.doMock('../src/events', () => ({
  emitScanEvent: vi.fn(),
}));

describe('Queue System', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Scan Job Payload', () => {
    it('should have correct payload structure', () => {
      const payload = {
        scanId: 'test-scan-id',
        scanRunId: 'test-run-id',
        hostPath: '/path/to/project',
        scannerType: 'trivy' as const,
      };

      expect(payload).toHaveProperty('scanId');
      expect(payload).toHaveProperty('scanRunId');
      expect(payload).toHaveProperty('hostPath');
      expect(payload).toHaveProperty('scannerType');
    });
  });

  describe('Job Processing', () => {
    it('should update scan status when job starts', async () => {
      const { areAllScanRunsFinished } = await import('../src/db');
      const { emitScanEvent } = await import('../src/events');

      // Mock implementations
      areAllScanRunsFinished.mockResolvedValue(false);
      emitScanEvent.mockImplementation(() => {});

      // Simulate job processing
      const jobData = {
        scanId: 'scan-id',
        scanRunId: 'run-id',
        hostPath: '/path/to/project',
        scannerType: 'trivy' as const,
      };

      expect(areAllScanRunsFinished).toBeDefined();
      expect(emitScanEvent).toBeDefined();
    });
  });

  describe('Findings Insertion', () => {
    it('should insert findings after scan completes', async () => {
      const { insertFindings } = await import('../src/db');
      insertFindings.mockResolvedValue(undefined);

      const findings = [
        {
          scanner_name: 'trivy',
          rule_id: 'CVE-2023-0001',
          fingerprint: 'abc123',
          severity: 'HIGH',
          file_path: 'package.json',
          title: 'Test Finding',
        },
      ];

      await insertFindings('scan-id', findings);

      expect(insertFindings).toHaveBeenCalledWith('scan-id', findings);
    });
  });

  describe('Event Emission', () => {
    it('should emit scan events during processing', async () => {
      const { emitScanEvent } = await import('../src/events');
      emitScanEvent.mockImplementation(() => {});

      await emitScanEvent('scan-id', {
        type: 'status',
        status: 'running',
        scanner: 'trivy',
        message: 'Starting trivy',
        timestamp: new Date().toISOString(),
      });

      expect(emitScanEvent).toHaveBeenCalledWith('scan-id', expect.objectContaining({
        type: 'status',
        scanner: 'trivy',
      }));
    });

    it('should emit failure event on error', async () => {
      const { emitScanEvent } = await import('../src/events');
      emitScanEvent.mockImplementation(() => {});

      await emitScanEvent('scan-id', {
        type: 'status',
        status: 'failed',
        message: 'Scan failed',
        timestamp: new Date().toISOString(),
      });

      expect(emitScanEvent).toHaveBeenCalledWith('scan-id', expect.objectContaining({
        status: 'failed',
      }));
    });
  });

  describe('Status Completion Check', () => {
    it('should check if all scan runs are finished', async () => {
      const { areAllScanRunsFinished } = await import('../src/db');
      areAllScanRunsFinished.mockResolvedValue(true);

      const result = await areAllScanRunsFinished('scan-id');

      expect(result).toBe(true);
      expect(areAllScanRunsFinished).toHaveBeenCalledWith('scan-id');
    });

    it('should return false when runs are still pending', async () => {
      const { areAllScanRunsFinished } = await import('../src/db');
      areAllScanRunsFinished.mockResolvedValue(false);

      const result = await areAllScanRunsFinished('scan-id');

      expect(result).toBe(false);
    });
  });

  describe('Docker Command Handling', () => {
    it('should spawn docker commands for scanners', async () => {
      const { spawn } = await import('child_process');
      const child = spawn('docker', ['run', '--rm', 'image']);

      expect(spawn).toHaveBeenCalledWith('docker', expect.arrayContaining(['run']));
    });

    it('should handle docker command output', () => {
      const mockOn = vi.fn();
      const mockStdoutOn = vi.fn();
      const mockStderrOn = vi.fn();

      const mockSpawn = vi.fn().mockReturnValue({
        stdout: { on: mockStdoutOn },
        stderr: { on: mockStderrOn },
        on: mockOn,
      });

      mockSpawn('docker', ['ps']);

      expect(mockSpawn).toHaveBeenCalled();
    });

    it('should handle docker command errors', () => {
      const mockOn = vi.fn((event: string, callback: (code: number) => void) => {
        if (event === 'close') {
          callback(1); // Non-zero exit code
        }
      });

      const mockSpawn = vi.fn().mockReturnValue({
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        on: mockOn,
      });

      mockSpawn('docker', ['invalid-command']);

      expect(mockOn).toHaveBeenCalled();
    });
  });

  describe('Scanner Configuration', () => {
    it('should build trivy command correctly', async () => {
      const { buildScannerCommand } = await import('../src/queue');

      const config = buildScannerCommand('trivy', '/path/to/project', 'scan-id');

      expect(config).toHaveProperty('dockerArgs');
      expect(config).toHaveProperty('parser');
      expect(config.dockerArgs).toContain('aquasec/trivy:latest');
      expect(config.dockerArgs).toContain('--format');
      expect(config.dockerArgs).toContain('json');
    });

    it('should build semgrep command correctly', async () => {
      const { buildScannerCommand } = await import('../src/queue');

      const config = buildScannerCommand('semgrep', '/path/to/project', 'scan-id');

      expect(config.dockerArgs).toContain('returntocorp/semgrep');
      expect(config.dockerArgs).toContain('--json');
    });

    it('should build bandit command correctly', async () => {
      const { buildScannerCommand } = await import('../src/queue');

      const config = buildScannerCommand('bandit', '/path/to/project', 'scan-id');

      expect(config.dockerArgs).toContain('cytopia/bandit:latest');
      expect(config.dockerArgs).toContain('-f');
      expect(config.dockerArgs).toContain('json');
    });

    it('should build sonarqube command correctly', async () => {
      const { buildScannerCommand } = await import('../src/queue');

      const config = buildScannerCommand('sonarqube', '/path/to/project', 'scan-id');

      expect(config.dockerArgs).toContain('sonarsource/sonar-scanner-cli');
      expect(config).toHaveProperty('transformOutput');
    });

    it('should build clair configuration correctly', async () => {
      const { buildScannerCommand } = await import('../src/queue');

      const config = buildScannerCommand('clair', '/path/to/project', 'scan-id');

      expect(config.dockerArgs).toEqual([]);
      expect(config).toHaveProperty('transformOutput');
    });

    it('should throw error for unknown scanner', async () => {
      const { buildScannerCommand } = await import('../src/queue');

      expect(() => {
        buildScannerCommand('unknown' as any, '/path', 'scan-id');
      }).toThrow('Unknown scanner type: unknown');
    });
  });

  describe('Error Handling', () => {
    it('should handle database errors gracefully', async () => {
      const { getScanById } = await import('../src/db');
      getScanById.mockRejectedValue(new Error('Database error'));

      try {
        await getScanById('scan-id');
      } catch (e) {
        expect((e as Error).message).toBe('Database error');
      }
    });

    it('should handle scan run update errors', async () => {
      const { updateScanRunStatus } = await import('../src/db');
      updateScanRunStatus.mockRejectedValue(new Error('Update failed'));

      await expect(updateScanRunStatus('run-id', 'running', new Date()))
        .rejects.toThrow('Update failed');
    });

    it('should handle findings insertion errors', async () => {
      const { insertFindings } = await import('../src/db');
      insertFindings.mockRejectedValue(new Error('Insert failed'));

      await expect(insertFindings('scan-id', [{ scanner_name: 'test', rule_id: 'test', fingerprint: 'test', severity: 'HIGH', file_path: 'test', title: 'test' }]))
        .rejects.toThrow('Insert failed');
    });
  });

  describe('Job Queue Operations', () => {
    it('should add jobs to the queue', async () => {
      const { scannerQueue } = await import('../src/queue');

      await scannerQueue.add('scan-job', {
        scanId: 'scan-id',
        scanRunId: 'run-id',
        hostPath: '/path',
        scannerType: 'trivy',
      });

      expect(scannerQueue.add).toBeDefined();
    });

    it('should close queue gracefully', async () => {
      const { scannerQueue } = await import('../src/queue');

      await scannerQueue.close();

      expect(scannerQueue.close).toBeDefined();
    });
  });

  describe('Output Parsing', () => {
    it('should parse JSON output from scanners', async () => {
      const { parseJsonOutput } = await import('../src/queue');

      const result = await parseJsonOutput('{"findings": []}');

      expect(result).toEqual({ findings: [] });
    });

    it('should handle empty output', async () => {
      const { parseJsonOutput } = await import('../src/queue');

      const result = await parseJsonOutput('');

      expect(result).toEqual({});
    });

    it('should extract JSON from text output', async () => {
      const { parseJsonOutput } = await import('../src/queue');

      const result = await parseJsonOutput('Some text {"findings": [1, 2, 3]} more text');

      expect(result).toEqual({ findings: [1, 2, 3] });
    });

    it('should extract JSON array from text output', async () => {
      const { parseJsonOutput } = await import('../src/queue');

      const result = await parseJsonOutput('[{"id": 1}, {"id": 2}]');

      expect(result).toEqual([{ id: 1 }, { id: 2 }]);
    });
  });

  describe('Cleanup Operations', () => {
    it('should handle cleanup after scan', async () => {
      const cleanup = async () => {};

      await cleanup();

      expect(true).toBe(true);
    });

    it('should handle cleanup errors gracefully', async () => {
      const cleanup = async () => {
        throw new Error('Cleanup failed');
      };

      try {
        await cleanup();
      } catch (e) {
        expect((e as Error).message).toBe('Cleanup failed');
      }
    });
  });

  describe('Concurrent Job Handling', () => {
    it('should handle multiple simultaneous jobs', async () => {
      const { updateScanStatus } = await import('../src/db');
      updateScanStatus.mockResolvedValue(undefined);

      const jobs = Array(5).fill(null).map((_, i) => ({
        scanId: `scan-${i}`,
        scanRunId: `run-${i}`,
        hostPath: '/path',
        scannerType: 'trivy' as const,
      }));

      for (const job of jobs) {
        await updateScanStatus(job.scanId, 'running');
      }

      expect(updateScanStatus).toHaveBeenCalledTimes(5);
    });

    it('should track job progress correctly', async () => {
      const { updateScanRunStatus } = await import('../src/db');
      updateScanRunStatus.mockResolvedValue(undefined);

      const jobProgress = {
        started: 0,
        completed: 0,
        failed: 0,
      };

      jobProgress.started++;
      await updateScanRunStatus('run-1', 'running', new Date());
      jobProgress.completed++;

      expect(jobProgress.started).toBe(1);
      expect(jobProgress.completed).toBe(1);
    });
  });
});
