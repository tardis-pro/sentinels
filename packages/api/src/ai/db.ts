import { client, connectDb } from '../db';
import { Client } from 'pg';

// Database extensions for AI analysis
export async function createAITables(): Promise<void> {
  await connectDb();
  
  await client.query(`
    -- AI Analyses cache table
    CREATE TABLE IF NOT EXISTS ai_analyses (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      fingerprint TEXT NOT NULL UNIQUE,
      finding_rule_id TEXT NOT NULL,
      finding_file TEXT NOT NULL,
      severity VARCHAR(10) NOT NULL,
      analysis JSONB NOT NULL,
      suggestions JSONB NOT NULL,
      prioritization JSONB NOT NULL,
      metadata JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    -- Create index for fingerprint lookups
    CREATE INDEX IF NOT EXISTS idx_ai_analyses_fingerprint ON ai_analyses(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_ai_analyses_finding ON ai_analyses(finding_rule_id, finding_file);
    CREATE INDEX IF NOT EXISTS idx_ai_analyses_severity ON ai_analyses(severity);

    -- Finding embeddings for similarity search (requires pgvector extension)
    CREATE EXTENSION IF NOT EXISTS vector;

    CREATE TABLE IF NOT EXISTS finding_embeddings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
      embedding vector(768),
      title_embedding vector(768),
      description_embedding vector(768),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    -- Create index for similarity search
    CREATE INDEX IF NOT EXISTS idx_finding_embeddings ON finding_embeddings 
      USING ivfflat (embedding vector_cosine_ops) 
      WITH (lists = 100);

    -- AI chat sessions for conversational remediation
    CREATE TABLE IF NOT EXISTS ai_chat_sessions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
      finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
      messages JSONB NOT NULL DEFAULT '[]',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_ai_chat_sessions_project ON ai_chat_sessions(project_id);
    CREATE INDEX IF NOT EXISTS idx_ai_chat_sessions_finding ON ai_chat_sessions(finding_id);

    -- AI feedback for continuous improvement
    CREATE TABLE IF NOT EXISTS ai_feedback (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      analysis_id UUID REFERENCES ai_analyses(id) ON DELETE CASCADE,
      feedback_type VARCHAR(20) NOT NULL,
      rating INTEGER CHECK (rating >= 1 AND rating <= 5),
      comment TEXT,
      was_accurate BOOLEAN,
      suggestion_was_helpful BOOLEAN,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_ai_feedback_analysis ON ai_feedback(analysis_id);
  `);
  
  console.log('AI tables created successfully');
}

// Save AI analysis to database
export async function saveAIAnalysis(params: {
  fingerprint: string;
  findingRuleId: string;
  findingFile: string;
  severity: string;
  analysis: any;
  suggestions: any;
  prioritization: any;
  metadata: any;
}): Promise<void> {
  await client.query(
    `INSERT INTO ai_analyses 
      (fingerprint, finding_rule_id, finding_file, severity, analysis, suggestions, prioritization, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (fingerprint) DO UPDATE SET
      analysis = EXCLUDED.analysis,
      suggestions = EXCLUDED.suggestions,
      prioritization = EXCLUDED.prioritization,
      metadata = EXCLUDED.metadata,
      created_at = NOW()`,
    [
      params.fingerprint,
      params.findingRuleId,
      params.findingFile,
      params.severity,
      JSON.stringify(params.analysis),
      JSON.stringify(params.suggestions),
      JSON.stringify(params.prioritization),
      JSON.stringify(params.metadata),
    ]
  );
}

// Get AI analysis by fingerprint
export async function getAIAnalysis(fingerprint: string): Promise<any | null> {
  const result = await client.query(
    'SELECT * FROM ai_analyses WHERE fingerprint = $1',
    [fingerprint]
  );
  return result.rows[0] || null;
}

// Save finding embedding
export async function saveFindingEmbedding(params: {
  findingId: string;
  embedding: number[];
  titleEmbedding?: number[];
  descriptionEmbedding?: number[];
}): Promise<void> {
  await client.query(
    `INSERT INTO finding_embeddings (finding_id, embedding, title_embedding, description_embedding)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (finding_id) DO UPDATE SET
      embedding = EXCLUDED.embedding,
      title_embedding = EXCLUDED.title_embedding,
      description_embedding = EXCLUDED.description_embedding,
      created_at = NOW()`,
    [
      params.findingId,
      `[${params.embedding.join(',')}]`,
      params.titleEmbedding ? `[${params.titleEmbedding.join(',')}]` : null,
      params.descriptionEmbedding ? `[${params.descriptionEmbedding.join(',')}]` : null,
    ]
  );
}

// Create chat session
export async function createChatSession(projectId: string, findingId?: string): Promise<string> {
  const result = await client.query(
    'INSERT INTO ai_chat_sessions (project_id, finding_id) VALUES ($1, $2) RETURNING id',
    [projectId, findingId || null]
  );
  return result.rows[0].id;
}

// Add message to chat session
export async function addChatMessage(
  sessionId: string,
  role: 'user' | 'assistant',
  content: string
): Promise<void> {
  await client.query(
    `UPDATE ai_chat_sessions 
     SET messages = messages || $1::jsonb, updated_at = NOW()
     WHERE id = $2`,
    [{ role, content, timestamp: new Date().toISOString() }, sessionId]
  );
}

// Get chat session
export async function getChatSession(sessionId: string): Promise<any | null> {
  const result = await client.query(
    'SELECT * FROM ai_chat_sessions WHERE id = $1',
    [sessionId]
  );
  return result.rows[0] || null;
}

// Save AI feedback
export async function saveAIFeedback(params: {
  analysisId: string;
  feedbackType: string;
  rating?: number;
  comment?: string;
  wasAccurate?: boolean;
  suggestionWasHelpful?: boolean;
}): Promise<void> {
  await client.query(
    `INSERT INTO ai_feedback 
      (analysis_id, feedback_type, rating, comment, was_accurate, suggestion_was_helpful)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      params.analysisId,
      params.feedbackType,
      params.rating,
      params.comment,
      params.wasAccurate,
      params.suggestionWasHelpful,
    ]
  );
}
