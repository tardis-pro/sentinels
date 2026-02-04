# Sentinel — Technical Design Specification

**Status:** Phase 2 Complete - Feature Implementation  
**Type:** Application Security Orchestration (ASOC)  
**Architecture:** Local-First, Containerized, Microservices

---

## 1. Executive Summary

**Sentinel** is a local-first, self-hosted security scanning orchestrator. It unifies disparate security tools (Trivy, Semgrep, Grype, ZAP) into a single orchestration engine, normalizing their outputs into a standardized database for unified reporting and tracking.

**Core Philosophy:**
* **Local-First:** Data never leaves the user's infrastructure.
* **Scanner Agnostic:** Normalized "Unified Finding Interface" regardless of the underlying tool.
* **Containerized:** Zero-dependency installation (Docker-out-of-Docker pattern).
* **AI-Enhanced:** LLM-powered vulnerability analysis and remediation suggestions.
* **Collaborative:** Team-based triage, workflow management, and integration with issue trackers.

---

## 2. Implemented Features (12 Issues Complete)

| # | Feature | Status | PR | Description |
|---|---------|--------|-----|-------------|
| 1 | AI-Powered Vulnerability Analysis | ✅ Complete | #16 | LLM-based finding analysis, smart prioritization, remediation suggestions |
| 2 | GitOps & CI/CD Pipeline Integration | ✅ Complete | #17 | GitHub/GitLab/Bitbucket webhooks, PR scanning, commit status |
| 3 | Analytics Dashboard | ✅ Complete | #13 | Security posture scoring, trends, compliance frameworks |
| 4 | Policy Engine (OPA/Rego) | ✅ Complete | #15 | Policy-as-code with Rego policies, compliance evaluation |
| 5 | Custom Scanner Plugin Framework | ✅ Complete | #21 | Plugin SDK, Docker sandboxing, public/private registries |
| 6 | Team Collaboration & Triage | ✅ Complete | #18 | Workflow states, assignments, comments, SLA tracking, Jira/Linear/Asana |
| 7 | SBOM Generation & Supply Chain | ✅ Complete | #22 | SPDX/CycloneDX SBOMs, SLSA compliance, container provenance |
| 8 | Auto-Remediation PR Generation | ✅ Complete | #23 | AI-powered fix generation, automated PR creation, safe automation controls |
| 9 | Webhook Integration Hub | ✅ Complete | #14 | Slack/Teams/Jira/PagerDuty integrations, webhook management |
| 10 | Scan Scheduling & Monitoring | ✅ Complete | #19 | Cron-based scheduling, health monitoring, SLA tracking, alerting |
| 11 | IDE Integration (VS Code) | ✅ Complete | #24 | Inline findings, real-time scanning, quick fixes |
| 12 | Intelligent Finding Deduplication | ✅ Complete | #20 | Fingerprint generation, similarity scoring, finding clusters |

---

## 3. High-Level Architecture

### System Diagram
```text
┌─────────────────────────────────────────────────────────────────┐
│                         Browser UI                              │
│            (Next.js 14 App Router + Tailwind/Shadcn)            │
└─────────────────────────────┬───────────────────────────────────┘
                               │ REST / SSE / WebSocket
┌─────────────────────────────▼───────────────────────────────────┐
│                      API Gateway                                │
│                (Fastify + BullMQ Producer)                      │
│                                                                 │
│   ┌─────────────┬─────────────┬─────────────┬─────────────────┐ │
│   │  AI Service │  Policy     │  Dedupe     │  Collaboration  │ │
│   │             │  Engine     │  Service    │  Service        │ │
│   └─────────────┴─────────────┴─────────────┴─────────────────┘ │
└───────┬─────────────┬─────────────┬─────────────────────────────┘
        │             │             │
        │      ┌──────▼──────┐      │
        │      │   Redis     │◄─────┘ Job Queue + WebSocket
        │      └──────┬──────┘
        │             │
┌───────▼─────────────▼───────────────────────────────────────────┐
│                     Worker Service                              │
│              (BullMQ Consumer + Docker Client)                  │
│                                                                 │
│   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│   │  Trivy  │   │ Semgrep │   │  Grype  │   │   ZAP   │   │ Custom  │
│   │         │   │         │   │         │   │         │   │ Plugins │
│   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘
│        │             │             │             │             │
└────────┴─────────────┴──────┬──────┴─────────────┴──────────────┘
                               │ Normalized Data
                    ┌──────────▼──────────┐
                    │     PostgreSQL      │
                    │   (Unified Store)   │
                    └─────────────────────┘
```

### Technology Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend** | Next.js 14 | React Server Components, App Router |
| **Backend** | Fastify | Low overhead, native Zod validation |
| **Queue** | BullMQ + Redis | Job scheduling, real-time updates |
| **Database** | PostgreSQL 15 | Relational + JSONB for raw evidence |
| **AI** | Ollama / OpenAI / Anthropic | LLM-powered analysis |
| **Runtime** | Docker (DooD) | Ephemeral scanner containers |
| **IDE** | VS Code Extension | In-editor security findings |

---

## 4. Extended Database Schema

### Core Tables

```sql
-- Projects (repos/directories to scan)
CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  path TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scan runs
CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  scanners TEXT[],
  status TEXT DEFAULT 'pending',
  error_log TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

-- Unified Findings
CREATE TABLE findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  scanner_name TEXT NOT NULL,
  scanner_version TEXT,
  rule_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  severity VARCHAR(10) NOT NULL,
  file_path TEXT NOT NULL,
  start_line INT,
  end_line INT,
  title TEXT NOT NULL,
  description TEXT,
  remediation TEXT,
  cwe_ids TEXT[],
  cve_ids TEXT[],
  raw_data JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Finding deduplication
CREATE TABLE finding_fingerprints (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID REFERENCES findings(id),
  fingerprint TEXT NOT NULL,
  version INT DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE finding_clusters (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  representative_finding_id UUID,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Collaboration
CREATE TABLE finding_workflow_states (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID REFERENCES findings(id),
  state TEXT NOT NULL DEFAULT 'new',
  assigned_to UUID,
  transitioned_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE finding_comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID REFERENCES findings(id),
  user_id UUID,
  body TEXT NOT NULL,
  mentions TEXT[],
  parent_comment_id UUID,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- AI Analysis
CREATE TABLE ai_analyses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID REFERENCES findings(id),
  analysis_type TEXT NOT NULL,
  result JSONB NOT NULL,
  model TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Policies (OPA/Rego)
CREATE TABLE policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT,
  category TEXT NOT NULL,
  severity VARCHAR(10),
  rego_policy TEXT NOT NULL,
  enforcement_action TEXT DEFAULT 'block',
  enabled BOOLEAN DEFAULT true
);

-- SLSA Attestations
CREATE TABLE slsa_attestations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID REFERENCES projects(id),
  build_level INT NOT NULL,
  provenance JSONB NOT NULL,
  verified BOOLEAN DEFAULT false
);

-- SBOM Storage
CREATE TABLE sboms (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID REFERENCES projects(id),
  format TEXT NOT NULL,
  document JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## 5. API Endpoints

### Core Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/projects` | Register new codebase |
| `GET` | `/projects` | List projects |
| `POST` | `/scans` | Trigger scan |
| `GET` | `/scans/:id` | Get status & summary |

### AI & Analysis
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/ai/analyze` | Analyze finding with LLM |
| `POST` | `/ai/analyze-batch` | Batch analyze findings |
| `POST` | `/ai/similar` | Find similar findings |

### Collaboration
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `PATCH` | `/findings/:id/state` | Transition workflow state |
| `POST` | `/findings/:id/assign` | Assign finding to user |
| `POST` | `/findings/:id/comments` | Add comment with @mentions |

### Deduplication
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/deduplication/clusters` | List finding clusters |
| `POST` | `/deduplication/clusters/:id/merge` | Merge clusters |
| `GET` | `/deduplication/stats` | Deduplication metrics |

### Scheduling
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/schedules` | Create scan schedule |
| `GET` | `/health` | Scan health status |
| `GET` | `/sla/status` | SLA compliance status |

### Plugins
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/plugins` | List available plugins |
| `POST` | `/plugins/install` | Install plugin |
| `POST` | `/plugins/:id/execute` | Execute plugin scan |

### IDE Integration
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `WS` | `/api/ws/ide` | WebSocket for real-time updates |
| `POST` | `/ide/scan` | Trigger IDE scan |
| `GET` | `/ide/findings/:file` | Get findings for file |

---

## 6. Plugin Architecture

### Plugin Types
- **Scanner Plugins**: Custom security scanners
- **Parser Plugins**: Output format parsers
- **Enrichment Plugins**: Finding enrichment
- **Notification Plugins**: Alert channels
- **Report Plugins**: Custom report formats

### Plugin SDK Interface
```typescript
interface ScannerPlugin {
  metadata: PluginMetadata;
  configSchema: JSONSchema;
  scan(context: ScanContext): Promise<Finding[]>;
  validateConfig(config: any): ValidationResult;
}

interface PluginRuntime {
  execute(plugin: Plugin, context: ScanContext): Promise<PluginResult>;
  enforceLimits(resourceLimits: ResourceLimits): void;
  isolate(): SandboxEnvironment;
}
```

---

## 7. Integration Matrix

### Git Providers
| Provider | Webhooks | PR Scanning | Commit Status | API |
|----------|----------|-------------|---------------|-----|
| GitHub | ✅ | ✅ | ✅ | Octokit |
| GitLab | ✅ | ✅ | ✅ | REST API |
| Bitbucket | ✅ | ✅ | ✅ | REST API |

### Issue Trackers
| Provider | Create Issues | Sync Status | Comments |
|----------|---------------|-------------|----------|
| Jira | ✅ | ✅ | ✅ |
| Linear | ✅ | ✅ | ✅ |
| Asana | ✅ | ✅ | ✅ |
| Notion | ✅ | ✅ | ✅ |
| GitHub Issues | ✅ | ✅ | ✅ |

### Notification Channels
| Channel | Alerts | Findings | Reports |
|---------|--------|----------|---------|
| Slack | ✅ | ✅ | ✅ |
| Teams | ✅ | ✅ | ✅ |
| Email | ✅ | ✅ | ✅ |
| PagerDuty | ✅ | ✅ | ❌ |
| Webhooks | ✅ | ✅ | ✅ |

---

## 8. Security Model

### Encryption
- **Secrets at Rest**: AES-256-GCM encryption for tokens and secrets
- **SSRF Protection**: URL validation for API endpoints
- **Input Validation**: Zod schema validation on all endpoints

### Plugin Sandboxing
- **Docker-based Isolation**: Plugins run in containers
- **Resource Limits**: CPU, memory, and timeout constraints
- **Network Isolation**: No external network access by default

### Access Control
- **Project-based**: RBAC at project level
- **Finding States**: Workflow transitions with validation
- **API Authentication**: Bearer token authentication

---

## 9. Infrastructure (docker-compose.yml)

```yaml
services:
  ui:
    build: ./packages/ui
    ports:
      - "3000:3000"
    environment:
      - API_URL=http://api:4000

  api:
    build: ./packages/api
    ports:
      - "4000:4000"
    environment:
      - DATABASE_URL=postgres://sentinel:sentinel@postgres:5432/sentinel
      - REDIS_URL=redis://redis:6379
      - HOST_PROJECT_ROOT=${PWD}/projects
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./projects:/app/projects
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:18-alpine
    environment:
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: sentinel
      POSTGRES_DB: sentinel
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine

volumes:
  pgdata:
```

---

## 10. Development Status

### Completed ✅
- [x] Core scanning infrastructure (Trivy, Semgrep, Bandit, Clair, SonarQube)
- [x] Finding normalization and storage
- [x] Real-time progress updates via SSE
- [x] AI-powered vulnerability analysis
- [x] Policy engine with OPA/Rego support
- [x] GitOps and CI/CD integration
- [x] Analytics dashboard with compliance frameworks
- [x] Webhook integration hub
- [x] Finding deduplication engine
- [x] Team collaboration and triage workflows
- [x] Scan scheduling and monitoring
- [x] Plugin framework with sandboxing
- [x] SBOM generation and SLSA compliance
- [x] Auto-remediation PR generation
- [x] VS Code extension

### In Progress 🔄
- None - All planned features complete

### Planned 📋
- [ ] Multi-tenant support
- [ ] Advanced role-based access control
- [ ] Enterprise SSO integration
- [ ] Custom compliance frameworks UI
- [ ] Additional IDE integrations (JetBrains, Vim/Neovim)
- [ ] GraphQL API for complex queries

---

## 11. Risks & Mitigations

1. **Large Output Parsing:**
   - *Risk:* Massive scan output crashes Node.js memory
   - *Mitigation:* Streaming JSON parsers (`stream-json`)

2. **Docker Rate Limits:**
   - *Risk:* Pulling `trivy:latest` repeatedly blocks IP
   - *Mitigation:* Local image cache, version pinning

3. **Zombie Containers:**
   - *Risk:* API crash leaves scanners running
   - *Mitigation:* `--rm` flag, cleanup startup script

4. **AI Token Costs:**
   - *Risk:* Unlimited LLM usage increases costs
   - *Mitigation:* Caching, rate limits, local Ollama option

5. **Plugin Security:**
   - *Risk:* Malicious plugins compromise system
   - *Mitigation:* Docker sandboxing, code signing, permissions system

---

## 12. Quick Start

```bash
# Clone and setup
git clone https://github.com/tardis-pro/sentinels
cd sentinels

# Start infrastructure
docker compose up --build

# Access dashboard
open http://localhost:3000

# Create project and run scan
curl -X POST http://localhost:4000/projects \
  -H "Content-Type: application/json" \
  -d '{"name": "my-app", "path": "/path/to/code"}'

# Install VS Code extension
# Search "Sentinel Security" in VS Code marketplace
```

---

*Document Version: 2.0*  
*Last Updated: 2026-02-04*  
*Status: Phase 2 Complete*
