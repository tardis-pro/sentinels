import { AIAnalysisConfig, AIAnalysisResult, FindingContext } from '../types';

/**
 * Ollama Provider for local LLM inference
 * Supports models like llama3.2, codellama, mistral
 */
export class OllamaProvider {
  provider = 'ollama' as const;
  private config: AIAnalysisConfig;
  private baseUrl: string;

  constructor(config: AIAnalysisConfig) {
    this.config = config;
    this.baseUrl = config.baseUrl || 'http://localhost:11434';
  }

  async isAvailable(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`, {
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async analyzeFinding(context: FindingContext): Promise<string> {
    const prompt = this.buildAnalysisPrompt(context);
    return this.complete(prompt);
  }

  async generateRemediation(context: FindingContext): Promise<string> {
    const prompt = this.buildRemediationPrompt(context);
    return this.complete(prompt);
  }

  async generateEmbedding(text: string): Promise<number[]> {
    const response = await fetch(`${this.baseUrl}/api/embeddings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.config.embeddingModel || 'nomic-embed-text',
        prompt: text,
      }),
    });

    if (!response.ok) {
      throw new Error(`Ollama embedding failed: ${response.statusText}`);
    }

    const data = await response.json();
    return data.embedding;
  }

  async generateEmbeddings(texts: string[]): Promise<number[][]> {
    return Promise.all(texts.map(text => this.generateEmbedding(text)));
  }

  async countTokens(text: string): Promise<number> {
    // Rough estimate: ~4 characters per token for English text
    return Math.ceil(text.length / 4);
  }

  async close(): Promise<void> {
    // Ollama doesn't require explicit closing
  }

  private async complete(prompt: string): Promise<string> {
    const startTime = Date.now();

    const response = await fetch(`${this.baseUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.config.model,
        prompt,
        stream: false,
        options: {
          temperature: this.config.temperature || 0.3,
          num_predict: this.config.maxTokens || 2048,
        },
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Ollama generation failed: ${error}`);
    }

    const data = await response.json();
    const processingTimeMs = Date.now() - startTime;

    // Log metrics
    console.log(`Ollama generation completed in ${processingTimeMs}ms, ${data.eval_count} tokens`);

    return data.response;
  }

  private buildAnalysisPrompt(context: FindingContext): string {
    return `
You are a senior security analyst. Analyze this vulnerability finding and provide insights.

## Vulnerability Details
- Title: ${context.title}
- Severity: ${context.severity}
- Scanner: ${context.scanner}
- Rule ID: ${context.ruleId}
- File: ${context.filePath}
- Language: ${context.language}
${context.cveIds?.length ? `- CVEs: ${context.cveIds.join(', ')}` : ''}
${context.cweIds?.length ? `- CWEs: ${context.cweIds.join(', ')}` : ''}

## Code Context
\`\`\`${context.language}
${context.codeSnippet}
\`\`\`

${context.description ? `## Description\n${context.description}\n` : ''}
${context.remediation ? `## Suggested Remediation\n${context.remediation}\n` : ''}

Provide a JSON response with:
1. explanation: Plain-English explanation of the vulnerability
2. attackVector: How an attacker could exploit this
3. impactAssessment: Business impact assessment
4. falsePositiveLikelihood: low/medium/high
5. confidence: 0-100

Respond with valid JSON only, no other text.
`;
  }

  private buildRemediationPrompt(context: FindingContext): string {
    return `
You are a senior security engineer. Generate remediation guidance for this vulnerability.

## Vulnerability Details
- Title: ${context.title}
- Severity: ${context.severity}
- Scanner: ${context.scanner}
- File: ${context.filePath}
- Language: ${context.language}
${context.projectType ? `- Project Type: ${context.projectType}` : ''}
${context.dependencies?.length ? `- Dependencies: ${context.dependencies.join(', ')}` : ''}

## Code Context
\`\`\`${context.language}
${context.codeSnippet}
\`\`\`

${context.description ? `## Description\n${context.description}\n` : ''}

Provide a JSON response with:
1. codeFix: Suggested code fix (if applicable)
2. remediationSteps: Array of step-by-step remediation instructions
3. libraryAlternatives: Array of safer library alternatives (if applicable)
4. configurationFix: Suggested configuration change (if applicable)

Respond with valid JSON only, no other text.
`;
  }
}
