/**
 * mantis — Configuration Loader
 *
 * Loads, validates, and merges configuration from:
 *   1. Default values (built-in)
 *   2. Configuration file (mantis.config.yaml)
 *   3. CLI arguments (highest priority)
 *   4. Environment variables
 *
 * Supports named profiles for different scan scenarios.
 */

import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type {
    MantisConfigFile,
    TargetConfig,
    ModulesConfig,
    ScanBehaviorConfig,
    OutputConfig,
    ScoringConfig,
} from '../types/config.js';
import { CONFIG_DEFAULTS } from '../types/config.js';
import type { ScanConfig } from '../types/types.js';

/** Possible config file names (checked in order) */
const CONFIG_FILE_NAMES = [
    'mantis.config.yaml',
    'mantis.config.yml',
    '.mantis.yaml',
    '.mantis.yml',
];

/**
 * ConfigLoader — load and merge configuration from all sources.
 */
export class ConfigLoader {
    private configDir: string;

    constructor(configDir: string = process.cwd()) {
        this.configDir = configDir;
    }

    /**
     * Load configuration from file.
     * Returns null if no config file found.
     */
    async loadFile(explicitPath?: string): Promise<MantisConfigFile | null> {
        const filePath = explicitPath
            ? resolve(this.configDir, explicitPath)
            : this.findConfigFile();

        if (!filePath) return null;

        try {
            const content = await readFile(filePath, 'utf-8');
            const parsed = parseYaml(content) as MantisConfigFile;
            this.validate(parsed, filePath);
            return parsed;
        } catch (error) {
            if (error instanceof ConfigValidationError) throw error;
            const msg = error instanceof Error ? error.message : String(error);
            throw new ConfigValidationError(
                filePath,
                `Failed to parse configuration: ${msg}`,
            );
        }
    }

    /**
     * Build a ScanConfig by merging defaults + file config + CLI args.
     * Priority: CLI args > config file > defaults
     */
    async buildConfig(options: {
        configPath?: string;
        profile?: string;
        cliOverrides?: Partial<ScanConfig>;
    }): Promise<ScanConfig> {
        // 1. Start with defaults
        const config: ScanConfig = {
            target: {
                url: '',
                method: CONFIG_DEFAULTS.target.method,
                headers: { ...CONFIG_DEFAULTS.target.headers },
                promptField: CONFIG_DEFAULTS.target.promptField,
                responseField: CONFIG_DEFAULTS.target.responseField,
            },
            modules: {
                include: [...CONFIG_DEFAULTS.modules.include],
                exclude: [...CONFIG_DEFAULTS.modules.exclude],
            },
            scan: { ...CONFIG_DEFAULTS.scan },
            output: { ...CONFIG_DEFAULTS.output },
            scoring: {
                weights: { ...CONFIG_DEFAULTS.scoring.weights },
            },
        };

        // 2. Merge config file
        const fileConfig = await this.loadFile(options.configPath);
        if (fileConfig) {
            this.mergeFileConfig(config, fileConfig);

            // 3. Apply profile if specified
            if (options.profile && fileConfig.profiles) {
                const profile = fileConfig.profiles[options.profile];
                if (!profile) {
                    const available = Object.keys(fileConfig.profiles).join(', ');
                    throw new ConfigValidationError(
                        options.configPath ?? 'config',
                        `Profile "${options.profile}" not found. Available: ${available}`,
                    );
                }
                this.mergeProfile(config, profile);
            }
        }

        // 4. Apply CLI overrides (highest priority)
        if (options.cliOverrides) {
            this.mergeCLIOverrides(config, options.cliOverrides);
        }

        // 5. Apply environment variables
        this.applyEnvVars(config);

        return config;
    }

    /** Find the config file in the config directory */
    private findConfigFile(): string | null {
        for (const name of CONFIG_FILE_NAMES) {
            const fullPath = resolve(this.configDir, name);
            if (existsSync(fullPath)) return fullPath;
        }
        return null;
    }

    /** Validate the parsed config file */
    private validate(config: MantisConfigFile, filePath: string): void {
        if (config.scoring?.weights) {
            const w = config.scoring.weights;
            const sum =
                (w.exploitability ?? 0) +
                (w.impact ?? 0) +
                (w.dataSensitivity ?? 0) +
                (w.reproducibility ?? 0) +
                (w.modelCompliance ?? 0);

            if (sum > 0 && Math.abs(sum - 1.0) > 0.01) {
                throw new ConfigValidationError(
                    filePath,
                    `Scoring weights must sum to 1.0, got ${sum.toFixed(3)}`,
                );
            }
        }
    }

    /** Merge file config into scan config */
    private mergeFileConfig(config: ScanConfig, file: MantisConfigFile): void {
        // Target
        if (file.target) {
            if (file.target.url) config.target.url = file.target.url;
            if (file.target.method) config.target.method = file.target.method;
            if (file.target.headers) config.target.headers = { ...config.target.headers, ...file.target.headers };
            if (file.target.promptField) config.target.promptField = file.target.promptField;
            if (file.target.responseField) config.target.responseField = file.target.responseField;
            if (file.target.authToken) config.target.authToken = file.target.authToken;
        }

        // Modules
        if (file.modules) {
            if (file.modules.include) config.modules.include = [...file.modules.include];
            if (file.modules.exclude) config.modules.exclude = [...file.modules.exclude];
        }

        // Scan
        if (file.scan) {
            if (file.scan.timeoutMs !== undefined) config.scan.timeoutMs = file.scan.timeoutMs;
            if (file.scan.maxRetries !== undefined) config.scan.maxRetries = file.scan.maxRetries;
            if (file.scan.retryDelayMs !== undefined) config.scan.retryDelayMs = file.scan.retryDelayMs;
            if (file.scan.rateLimit !== undefined) config.scan.rateLimit = file.scan.rateLimit;
            if (file.scan.severityThreshold) config.scan.severityThreshold = file.scan.severityThreshold;
            if (file.scan.reproducibilityAttempts !== undefined) config.scan.reproducibilityAttempts = file.scan.reproducibilityAttempts;
        }

        // Output
        if (file.output) {
            if (file.output.format) config.output.format = file.output.format;
            if (file.output.file) config.output.file = file.output.file;
            if (file.output.verbose !== undefined) config.output.verbose = file.output.verbose;
            if (file.output.redactResponses !== undefined) config.output.redactResponses = file.output.redactResponses;
        }

        // Scoring
        if (file.scoring?.weights) {
            config.scoring.weights = { ...config.scoring.weights, ...file.scoring.weights };
        }
    }

    /** Merge a named profile into scan config */
    private mergeProfile(config: ScanConfig, profile: Record<string, unknown>): void {
        const p = profile as Partial<{
            modules: Partial<ModulesConfig>;
            scan: Partial<ScanBehaviorConfig>;
            output: Partial<OutputConfig>;
            scoring: Partial<ScoringConfig>;
        }>;

        if (p.modules) {
            if (p.modules.include) config.modules.include = [...p.modules.include];
            if (p.modules.exclude) config.modules.exclude = [...p.modules.exclude];
        }

        if (p.scan) {
            Object.assign(config.scan, p.scan);
        }

        if (p.output) {
            Object.assign(config.output, p.output);
        }

        if (p.scoring?.weights) {
            config.scoring.weights = { ...config.scoring.weights, ...p.scoring.weights };
        }
    }

    /** Merge CLI overrides */
    private mergeCLIOverrides(config: ScanConfig, overrides: Partial<ScanConfig>): void {
        if (overrides.target) {
            if (overrides.target.url) config.target.url = overrides.target.url;
            if (overrides.target.method) config.target.method = overrides.target.method;
            if (overrides.target.promptField) config.target.promptField = overrides.target.promptField;
            if (overrides.target.responseField) config.target.responseField = overrides.target.responseField;
            if (overrides.target.authToken) config.target.authToken = overrides.target.authToken;
        }

        if (overrides.modules) {
            if (overrides.modules.include?.length) config.modules.include = overrides.modules.include;
            if (overrides.modules.exclude?.length) config.modules.exclude = overrides.modules.exclude;
        }

        if (overrides.scan) {
            Object.assign(config.scan, overrides.scan);
        }

        if (overrides.output) {
            Object.assign(config.output, overrides.output);
        }
    }

    /** Apply environment variable overrides */
    private applyEnvVars(config: ScanConfig): void {
        if (process.env['MANTIS_AUTH_TOKEN'] && !config.target.authToken) {
            config.target.authToken = process.env['MANTIS_AUTH_TOKEN'];
        }
        if (process.env['MANTIS_TARGET_URL'] && !config.target.url) {
            config.target.url = process.env['MANTIS_TARGET_URL'];
        }
        if (process.env['MANTIS_FORMAT']) {
            config.output.format = process.env['MANTIS_FORMAT'] as ScanConfig['output']['format'];
        }
    }
}

/**
 * Configuration validation error.
 */
export class ConfigValidationError extends Error {
    constructor(
        public readonly filePath: string,
        message: string,
    ) {
        super(`Configuration error in ${filePath}: ${message}`);
        this.name = 'ConfigValidationError';
    }
}
