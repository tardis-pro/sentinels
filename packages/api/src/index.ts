import Fastify from 'fastify';
import cors from '@fastify/cors';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  connectDb,
  createProject,
  createScan,
  createScanRun,
  createTables,
  getProjectById,
  getScanById,
  getFindingsByScanId,
  getProjectPathByScanId,
  listFindings,
  listProjects,
  listScanRuns,
  listScanRunsByScanIds,
  listScansByProject,
} from './db';
import { aiRoutes } from './ai/routes';
import { createAITables } from './ai/db';
import { scannerQueue } from './queue';
import { SupportedScanner } from './parsers';
import { policyRoutes } from './policies';
import { analyticsRoutes } from './analytics';
import { webhookRoutes } from './webhooks';
import { buildCapabilityManifest } from './capabilities';
import { collaborationRoutes } from './collaboration/routes';

const fastify = Fastify({
  logger: true,
});

const capabilityManifest = buildCapabilityManifest();

fastify.register(cors, {
  origin: true, // Allow all origins for this local-first tool
});

// Register policy routes
fastify.register(policyRoutes);

// Register analytics routes
fastify.register(analyticsRoutes);

// Register webhook routes
fastify.register(webhookRoutes);

// Register collaboration routes
fastify.register(collaborationRoutes);

fastify.get('/_capabilities', async (_request) => {
  const groups = Object.entries(capabilityManifest).map(([name, entries]) => ({
    name,
    count: Object.keys(entries).length,
  }));

  return {
    totalGroups: groups.length,
    groups,
  };
});

// Register new codebase
fastify.post('/projects', async (request, reply) => {
  const { name, path } = request.body as { name: string; path: string };
  const project = await createProject(name, path);
  reply.status(201).send(project);
});

// List projects
fastify.get('/projects', async (_request, reply) => {
  const projects = await listProjects();
  reply.send(projects);
});

// Get single project
fastify.get('/projects/:id', async (request, reply) => {
  const { id } = request.params as { id: string };
  const project = await getProjectById(id);
  if (!project) {
    reply.status(404).send({ error: 'Project not found' });
    return;
  }
  reply.send(project);
});

// Trigger scan
fastify.post('/scans', async (request, reply) => {
  const { projectId, scanners } = request.body as { projectId: string; scanners: SupportedScanner[] };
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

// Get status & summary for a scan
fastify.get('/scans/:id', async (request, reply) => {
  const { id } = request.params as { id: string };
  const scan = await getScanById(id);
  if (!scan) {
    reply.status(404).send({ error: 'Scan not found' });
    return;
  }
  reply.send(scan);
});

// Scan runs for a project (history)
fastify.get('/projects/:id/scans', async (request, reply) => {
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

fastify.get('/scans/:id/runs', async (request, reply) => {
  const { id } = request.params as { id: string };
  const runs = await listScanRuns(id);
  reply.send(runs);
});

// Global search findings
fastify.get('/findings', async (request, reply) => {
  const { severity, type } = request.query as { severity?: string; type?: string };
  const rows = await listFindings(severity, type);
  reply.send(rows);
});

// Get findings by scan ID
fastify.get('/scans/:id/findings', async (request, reply) => {
  const { id } = request.params as { id: string };
  const rows = await getFindingsByScanId(id);

  const projectPath = (await getProjectPathByScanId(id)) || '';

  const fileCache = new Map<string, string[]>();
  const sonarCache = new Map<string, string[]>();

  const readSonarSourceLines = async (component: string): Promise<string[] | null> => {
    if (!component) {
      return null;
    }
    if (sonarCache.has(component)) {
      return sonarCache.get(component) || null;
    }

    try {
      const baseUrl = process.env.SONARQUBE_URL || 'http://sonarqube:9000';
      const token = process.env.SONAR_TOKEN || process.env.SONARQUBE_TOKEN;
      const username = process.env.SONARQUBE_USERNAME || 'admin';
      const password = process.env.SONARQUBE_PASSWORD || 'Admin@123123';
      const authCandidates = [
        token ? `${token}:` : '',
        `${username}:${password}`,
      ].filter(Boolean);

      for (const authValue of authCandidates) {
        const res = await fetch(
          `${baseUrl}/api/sources/raw?key=${encodeURIComponent(component)}`,
          {
            headers: {
              Authorization: `Basic ${Buffer.from(authValue).toString('base64')}`,
            },
          }
        );

        if (!res.ok) {
          continue;
        }

        const content = await res.text();
        const lines = content.split(/\r?\n/);
        sonarCache.set(component, lines);
        return lines;
      }

      return null;
    } catch {
      return null;
    }
  };

  const readLines = async (filePathValue: string): Promise<string[] | null> => {
    if (!path.isAbsolute(filePathValue) && !projectPath) {
      return null;
    }

    const resolvedPath = path.isAbsolute(filePathValue)
      ? filePathValue
      : path.resolve(projectPath, filePathValue);

    if (fileCache.has(resolvedPath)) {
      return fileCache.get(resolvedPath) || null;
    }

    try {
      const content = await fs.readFile(resolvedPath, 'utf8');
      const lines = content.split(/\r?\n/);
      fileCache.set(resolvedPath, lines);
      return lines;
    } catch {
      return null;
    }
  };

  const enriched = await Promise.all(
    rows.map(async (row: any) => {
      if (row.scanner_name !== 'sonarqube' || !row.file_path || !row.start_line) {
        return row;
      }

      const lines =
        (await readLines(row.file_path)) ||
        (await readSonarSourceLines((row.raw_data?.component as string) || ''));
      if (!lines) {
        return row;
      }

      const startLine = Math.max(1, Number(row.start_line) || 1);
      const endLine = Math.max(startLine, Number(row.end_line) || startLine);
      const contextStart = Math.max(1, startLine - 3);
      const contextEnd = Math.min(lines.length, endLine + 3);
      const snippet = lines.slice(contextStart - 1, contextEnd).join('\n');

      return {
        ...row,
        code_snippet: snippet,
        snippet_start_line: contextStart,
        snippet_end_line: contextEnd,
      };
    })
  );

  reply.send(enriched);
});

// Register AI routes
fastify.register(aiRoutes);

async function start() {
  try {
    await connectDb();
    await createTables();
    await createAITables(); // Create AI-specific tables
    await fastify.listen({ port: 4000, host: '0.0.0.0' });
    console.log(`API listening on http://0.0.0.0:4000`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
