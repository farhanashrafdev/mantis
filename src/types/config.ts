/**
 * mantis — Configuration Schema Types
 *
 * Type definitions matching mantis.config.yaml structure.
 * Used by the config loader for validation and type safety.
 */

import type { OutputFormat, SeverityLevel, ScoringWeights } from './types.js';

/** Root configuration file structure */
export interface MantisConfigFile {
    /** Config file version for forward compatibility */
    version: '1.0';

    /** Target application settings */
    target: TargetConfig;

    /** Module/plugin selection */
    modules?: ModuleConfig;

    /** Scan behavior settings */
    scan?: ScanBehaviorConfig;

    /** Output settings */
    output?: OutputConfig;

    /** Scoring model settings */
    scoring?: ScoringConfig;

    /** Profile presets */
    profiles?: Record<string, ProfileConfig>;
}

/** Target application configuration */
export interface TargetConfig {
    /** Target endpoint URL */
    url: string;
    /** HTTP method for sending prompts */
    method?: 'GET' | 'POST' | 'PUT';
    /** Custom request headers */
    headers?: Record<string, string>;
    /** JSON path to the prompt field in request body (dot notation) */
    promptField?: string;
    /** JSON path to the response field in response body (dot notation) */
    responseField?: string;
    /** Bearer token for authentication (prefer env var MANTIS_AUTH_TOKEN) */
    authToken?: string;
}

/** Module selection configuration */
export interface ModuleConfig {
    /** Plugin IDs to include (empty = all) */
    include?: string[];
    /** Plugin IDs to exclude */
    exclude?: string[];
}

/** Scan behavior configuration */
export interface ScanBehaviorConfig {
    /** Request timeout in milliseconds (default: 30000) */
    timeoutMs?: number;
    /** Max retries on request failure (default: 2) */
    maxRetries?: number;
    /** Delay between retries in ms (default: 1000) */
    retryDelayMs?: number;
    /** Max requests per second (default: 10) */
    rateLimit?: number;
    /** Minimum severity to include in report (default: low) */
    severityThreshold?: SeverityLevel;
    /** Number of attempts to verify reproducibility (default: 3) */
    reproducibilityAttempts?: number;
}

/** Output configuration */
export interface OutputConfig {
    /** Output format (default: table) */
    format?: OutputFormat;
    /** Output file path (default: stdout) */
    file?: string;
    /** Verbose output with full responses (default: false) */
    verbose?: boolean;
    /** Redact sensitive data in output (default: true) */
    redactResponses?: boolean;
}

/** Scoring model configuration */
export interface ScoringConfig {
    /** Custom ALVSS weights (must sum to 1.0) */
    weights?: Partial<ScoringWeights>;
}

/** Named profile preset — overrides specific config sections */
export interface ProfileConfig {
    /** Profile description */
    description?: string;
    /** Override module selection */
    modules?: ModuleConfig;
    /** Override scan behavior */
    scan?: ScanBehaviorConfig;
    /** Override output settings */
    output?: OutputConfig;
}

// ─── Defaults ────────────────────────────────────────────────────────────────

/** Default configuration values */
export const CONFIG_DEFAULTS: Required<Omit<MantisConfigFile, 'version' | 'target' | 'profiles'>> = {
    modules: {
        include: [],
        exclude: [],
    },
    scan: {
        timeoutMs: 30_000,
        maxRetries: 2,
        retryDelayMs: 1_000,
        rateLimit: 10,
        severityThreshold: 'low' as SeverityLevel,
        reproducibilityAttempts: 3,
    },
    output: {
        format: 'table' as OutputFormat,
        verbose: false,
        redactResponses: true,
    },
    scoring: {
        weights: {
            exploitability: 0.30,
            impact: 0.25,
            dataSensitivity: 0.20,
            reproducibility: 0.15,
            modelCompliance: 0.10,
        },
    },
};
