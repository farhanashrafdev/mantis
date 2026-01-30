/**
 * mantis — Core Type Definitions
 *
 * All foundational interfaces and types for the mantis red-team toolkit.
 * These contracts define the boundaries between every module in the system.
 */

// ─── Enums ───────────────────────────────────────────────────────────────────

/** Attack category classification */
export enum AttackCategory {
    PromptInjection = 'prompt-injection',
    DataLeakage = 'data-leakage',
    Hallucination = 'hallucination',
    ToolExploit = 'tool-exploit',
}

/** Severity levels for findings */
export enum SeverityLevel {
    Critical = 'critical',
    High = 'high',
    Medium = 'medium',
    Low = 'low',
    Info = 'info',
}

/** Output format options */
export enum OutputFormat {
    Table = 'table',
    JSON = 'json',
    SARIF = 'sarif',
}

/** Plugin execution status */
export enum PluginStatus {
    Passed = 'passed',
    Failed = 'failed',
    Error = 'error',
    Skipped = 'skipped',
}

// ─── Plugin System ───────────────────────────────────────────────────────────

/** Metadata describing a plugin */
export interface PluginMeta {
    /** Unique plugin identifier, e.g. "prompt-injection/system-override" */
    id: string;
    /** Human-readable name */
    name: string;
    /** Brief description of what this plugin tests */
    description: string;
    /** Attack category this plugin belongs to */
    category: AttackCategory;
    /** Semantic version of the plugin */
    version: string;
    /** Plugin author */
    author: string;
    /** Tags for filtering and search */
    tags: string[];
}

/** A single attack prompt with its expected behavior definition */
export interface AttackPrompt {
    /** Unique identifier for this prompt within the plugin */
    id: string;
    /** The actual attack prompt text to send to the target */
    prompt: string;
    /** Human-readable description of the attack vector */
    description: string;
    /** Patterns that indicate the target is SECURE (resisted the attack) */
    securePatterns: RegExp[];
    /** Patterns that indicate the target is VULNERABLE (attack succeeded) */
    vulnerablePatterns: RegExp[];
    /** Expected severity if this attack succeeds */
    severity: SeverityLevel;
}

/**
 * Core plugin interface — every attack module must implement this.
 *
 * Plugins are self-contained test units that:
 * 1. Define attack prompts
 * 2. Execute them against the target via the LLM adapter
 * 3. Analyze responses for vulnerability indicators
 * 4. Return structured findings
 */
export interface Plugin {
    /** Plugin metadata */
    meta: PluginMeta;

    /** Array of attack prompts this plugin will execute */
    prompts: AttackPrompt[];

    /**
     * Initialize the plugin. Called once before execution.
     * Use for setup, validation, or loading external resources.
     */
    initialize(context: ScanContext): Promise<void>;

    /**
     * Execute all attack prompts against the target.
     * Returns an array of findings (empty if no vulnerabilities detected).
     */
    execute(context: ScanContext): Promise<Finding[]>;

    /**
     * Analyze a single response from the target LLM.
     * Called by the core engine for each prompt/response pair.
     */
    analyze(prompt: AttackPrompt, response: LLMResponse): FindingResult;

    /**
     * Cleanup after execution. Called once after all prompts are run.
     */
    teardown(): Promise<void>;
}

// ─── LLM Interaction ─────────────────────────────────────────────────────────

/** Configuration for the LLM adapter */
export interface LLMAdapterConfig {
    /** Target endpoint URL */
    targetUrl: string;
    /** HTTP method (default: POST) */
    method: 'GET' | 'POST' | 'PUT';
    /** Custom headers to include in requests */
    headers: Record<string, string>;
    /** Request timeout in milliseconds */
    timeoutMs: number;
    /** Maximum retries on failure */
    maxRetries: number;
    /** Delay between retries in milliseconds */
    retryDelayMs: number;
    /** Rate limiting: max requests per second */
    rateLimit: number;
    /** JSON path to the prompt field in the request body */
    promptField: string;
    /** JSON path to the response text in the response body */
    responseField: string;
    /** Optional authentication bearer token */
    authToken?: string;
}

/** Raw response from the target LLM application */
export interface LLMResponse {
    /** HTTP status code */
    statusCode: number;
    /** Response headers */
    headers: Record<string, string>;
    /** Raw response body (string) */
    rawBody: string;
    /** Parsed response text (extracted via responseField path) */
    text: string;
    /** Response time in milliseconds */
    responseTimeMs: number;
    /** Whether the request succeeded (2xx status) */
    success: boolean;
    /** Error message if request failed */
    error?: string;
}

/**
 * LLM Adapter interface — abstracts how mantis communicates with the target.
 *
 * The default implementation sends HTTP requests, but this can be extended
 * for WebSocket targets, gRPC, SDK-based interactions, etc.
 */
export interface LLMAdapter {
    /** Adapter configuration */
    config: LLMAdapterConfig;

    /** Send a single prompt to the target and return the response */
    sendPrompt(prompt: string): Promise<LLMResponse>;

    /** Send multiple prompts in sequence with rate limiting */
    sendBatch(prompts: string[]): Promise<LLMResponse[]>;

    /** Test connectivity to the target */
    healthCheck(): Promise<boolean>;
}

// ─── Findings ────────────────────────────────────────────────────────────────

/** Result of analyzing a single prompt/response pair */
export interface FindingResult {
    /** Whether a vulnerability was detected */
    vulnerable: boolean;
    /** Confidence score (0.0 – 1.0) */
    confidence: number;
    /** Evidence extracted from the response */
    evidence: string;
    /** Which patterns matched */
    matchedPatterns: string[];
}

/** A complete vulnerability finding */
export interface Finding {
    /** Unique finding identifier */
    id: string;
    /** Plugin that generated this finding */
    pluginId: string;
    /** Attack category */
    category: AttackCategory;
    /** Finding title */
    title: string;
    /** Detailed description of the vulnerability */
    description: string;
    /** Severity level */
    severity: SeverityLevel;
    /** ALVSS risk score (0–10) */
    riskScore: number;
    /** The attack prompt that triggered this finding */
    attackPrompt: string;
    /** The vulnerable response from the target */
    response: string;
    /** Evidence of the vulnerability */
    evidence: string;
    /** Confidence level (0.0 – 1.0) */
    confidence: number;
    /** Remediation guidance */
    remediation: string;
    /** CWE reference if applicable */
    cwe?: string;
    /** Timestamp of the finding */
    timestamp: string;
    /** Whether this finding was reproduced across multiple attempts */
    reproducible: boolean;
    /** Number of attempts made */
    attempts: number;
    /** Number of successful exploitations */
    successes: number;
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

/** Input dimensions for ALVSS scoring */
export interface ScoringDimensions {
    /** Exploitability: how easy is it to reproduce? (0–10) */
    exploitability: number;
    /** Impact: what's the blast radius? (0–10) */
    impact: number;
    /** Data sensitivity: does it expose PII, secrets, or IP? (0–10) */
    dataSensitivity: number;
    /** Reproducibility: does it succeed consistently? (0–10) */
    reproducibility: number;
    /** Model compliance: does the refusal mechanism engage? (0–10) */
    modelCompliance: number;
}

/** ALVSS scoring weights */
export interface ScoringWeights {
    exploitability: number;
    impact: number;
    dataSensitivity: number;
    reproducibility: number;
    modelCompliance: number;
}

/** Complete scoring result for a finding */
export interface ScoringResult {
    /** Final weighted score (0–10) */
    score: number;
    /** Mapped severity level */
    severity: SeverityLevel;
    /** Individual dimension scores */
    dimensions: ScoringDimensions;
    /** Weights used for calculation */
    weights: ScoringWeights;
    /** Human-readable breakdown */
    breakdown: string;
}

// ─── Scan Context ────────────────────────────────────────────────────────────

/** Scan-wide context passed to every plugin */
export interface ScanContext {
    /** Unique scan session identifier */
    scanId: string;
    /** Target URL */
    targetUrl: string;
    /** LLM adapter instance for communicating with the target */
    adapter: LLMAdapter;
    /** Active scan configuration */
    config: ScanConfig;
    /** Which modules/plugins to run (empty = all) */
    moduleFilter: string[];
    /** Minimum severity threshold to report */
    severityThreshold: SeverityLevel;
    /** Scan start timestamp */
    startedAt: string;
    /** Logger instance */
    logger: Logger;
}

/** Minimal logger interface */
export interface Logger {
    debug(message: string, ...args: unknown[]): void;
    info(message: string, ...args: unknown[]): void;
    warn(message: string, ...args: unknown[]): void;
    error(message: string, ...args: unknown[]): void;
}

// ─── Scan Config ─────────────────────────────────────────────────────────────

/** Top-level scan configuration (maps to mantis.config.yaml) */
export interface ScanConfig {
    /** Target configuration */
    target: {
        url: string;
        method: 'GET' | 'POST' | 'PUT';
        headers: Record<string, string>;
        promptField: string;
        responseField: string;
        authToken?: string;
    };
    /** Module selection */
    modules: {
        include: string[];
        exclude: string[];
    };
    /** Scan behavior */
    scan: {
        timeoutMs: number;
        maxRetries: number;
        retryDelayMs: number;
        rateLimit: number;
        severityThreshold: SeverityLevel;
        reproducibilityAttempts: number;
    };
    /** Output configuration */
    output: {
        format: OutputFormat;
        file?: string;
        verbose: boolean;
        redactResponses: boolean;
    };
    /** Scoring configuration */
    scoring: {
        weights: ScoringWeights;
    };
}

// ─── Report ──────────────────────────────────────────────────────────────────

/** Complete scan report */
export interface ScanReport {
    /** Report metadata */
    meta: {
        scanId: string;
        targetUrl: string;
        startedAt: string;
        completedAt: string;
        durationMs: number;
        mantisVersion: string;
        pluginsExecuted: number;
        totalPromptsSent: number;
    };
    /** Summary statistics */
    summary: {
        totalFindings: number;
        criticalCount: number;
        highCount: number;
        mediumCount: number;
        lowCount: number;
        infoCount: number;
        overallRiskScore: number;
        overallSeverity: SeverityLevel;
        categoryScores: Record<AttackCategory, number>;
    };
    /** All individual findings */
    findings: Finding[];
    /** Per-plugin execution results */
    pluginResults: PluginExecutionResult[];
}

/** Execution result for a single plugin */
export interface PluginExecutionResult {
    pluginId: string;
    pluginName: string;
    category: AttackCategory;
    status: PluginStatus;
    findings: Finding[];
    promptsExecuted: number;
    durationMs: number;
    error?: string;
}

// ─── Reporter ────────────────────────────────────────────────────────────────

/** Reporter interface — formats scan results for output */
export interface Reporter {
    /** Output format this reporter handles */
    format: OutputFormat;

    /** Generate formatted output from a scan report */
    generate(report: ScanReport): string;

    /** Write output to a file */
    writeToFile(report: ScanReport, filePath: string): Promise<void>;
}
