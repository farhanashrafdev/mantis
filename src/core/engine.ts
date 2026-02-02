/**
 * mantis — Core Engine
 *
 * Orchestrates the entire scan lifecycle:
 * 1. Resolve configuration
 * 2. Initialize LLM adapter
 * 3. Discover and load plugins
 * 4. Execute plugins against the target
 * 5. Collect and score findings
 * 6. Generate report
 */

import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { PluginRegistry } from './plugin-registry.js';
import { HttpAdapter } from '../adapters/http-adapter.js';
import type {
    Plugin,
    Finding,
    ScanContext,
    ScanConfig,
    ScanReport,
    PluginExecutionResult,
    Logger,
    AttackCategory,
    SeverityLevel,
    PluginStatus,
} from '../types/types.js';

/** Default logger implementation */
function createDefaultLogger(verbose: boolean): Logger {
    return {
        debug: (msg: string, ...args: unknown[]) => {
            if (verbose) console.debug(`[DEBUG] ${msg}`, ...args);
        },
        info: (msg: string, ...args: unknown[]) => {
            console.info(`[INFO] ${msg}`, ...args);
        },
        warn: (msg: string, ...args: unknown[]) => {
            console.warn(`[WARN] ${msg}`, ...args);
        },
        error: (msg: string, ...args: unknown[]) => {
            console.error(`[ERROR] ${msg}`, ...args);
        },
    };
}

/** Severity level to numeric priority for filtering */
const SEVERITY_PRIORITY: Record<SeverityLevel, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
};

/** Engine events for lifecycle hooks */
export interface EngineEvents {
    onScanStart?: (context: ScanContext) => void;
    onPluginStart?: (plugin: Plugin) => void;
    onPluginComplete?: (result: PluginExecutionResult) => void;
    onFinding?: (finding: Finding) => void;
    onScanComplete?: (report: ScanReport) => void;
}

/**
 * CoreEngine — the heart of mantis.
 *
 * Usage:
 *   const engine = new CoreEngine(config);
 *   const report = await engine.scan();
 */
export class CoreEngine {
    private registry: PluginRegistry;
    private config: ScanConfig;
    private logger: Logger;
    private events: EngineEvents;

    constructor(config: ScanConfig, events: EngineEvents = {}) {
        this.config = config;
        this.registry = new PluginRegistry();
        this.logger = createDefaultLogger(config.output.verbose);
        this.events = events;
    }

    /**
     * Execute a full security scan against the target.
     * Returns a complete ScanReport with all findings.
     */
    async scan(): Promise<ScanReport> {
        const scanId = randomUUID();
        const startedAt = new Date().toISOString();

        this.logger.info(`Starting scan ${scanId} against ${this.config.target.url}`);

        // 1. Initialize adapter
        const adapter = new HttpAdapter({
            targetUrl: this.config.target.url,
            method: this.config.target.method,
            headers: this.config.target.headers,
            promptField: this.config.target.promptField,
            responseField: this.config.target.responseField,
            authToken: this.config.target.authToken,
            timeoutMs: this.config.scan.timeoutMs,
            maxRetries: this.config.scan.maxRetries,
            retryDelayMs: this.config.scan.retryDelayMs,
            rateLimit: this.config.scan.rateLimit,
        });

        // 2. Health check
        this.logger.info('Testing connectivity to target...');
        const healthy = await adapter.healthCheck();
        if (!healthy) {
            this.logger.warn('Target health check failed — proceeding anyway');
        }

        // 3. Discover plugins
        const currentFile = fileURLToPath(import.meta.url);
        const projectRoot = dirname(dirname(currentFile));
        const pluginsDir = join(projectRoot, 'plugins');

        this.logger.info(`Discovering plugins from ${pluginsDir}`);
        await this.registry.discover(pluginsDir);
        this.logger.info(`Loaded ${this.registry.count} plugins`);

        // 4. Filter plugins
        const plugins = this.registry.getFiltered(
            this.config.modules.include,
            this.config.modules.exclude,
        );
        this.logger.info(`${plugins.length} plugins selected for execution`);

        // 5. Build scan context
        const context: ScanContext = {
            scanId,
            targetUrl: this.config.target.url,
            adapter,
            config: this.config,
            moduleFilter: this.config.modules.include,
            severityThreshold: this.config.scan.severityThreshold,
            startedAt,
            logger: this.logger,
        };

        this.events.onScanStart?.(context);

        // 6. Execute plugins
        const pluginResults: PluginExecutionResult[] = [];
        const allFindings: Finding[] = [];
        let totalPromptsSent = 0;

        for (const plugin of plugins) {
            const result = await this.executePlugin(plugin, context);
            pluginResults.push(result);
            totalPromptsSent += result.promptsExecuted;

            // Filter findings by severity threshold
            const filteredFindings = result.findings.filter(
                (f) => SEVERITY_PRIORITY[f.severity] >= SEVERITY_PRIORITY[this.config.scan.severityThreshold],
            );
            allFindings.push(...filteredFindings);

            for (const finding of filteredFindings) {
                this.events.onFinding?.(finding);
            }

            this.events.onPluginComplete?.(result);
        }

        // 7. Build report
        const completedAt = new Date().toISOString();
        const report = this.buildReport(
            scanId,
            startedAt,
            completedAt,
            plugins.length,
            totalPromptsSent,
            allFindings,
            pluginResults,
        );

        this.events.onScanComplete?.(report);
        this.logger.info(`Scan complete. ${allFindings.length} findings detected.`);

        return report;
    }

    /**
     * Execute a single plugin and capture its results.
     */
    private async executePlugin(
        plugin: Plugin,
        context: ScanContext,
    ): Promise<PluginExecutionResult> {
        const startTime = Date.now();

        this.logger.info(`Executing plugin: ${plugin.meta.name} (${plugin.meta.id})`);
        this.events.onPluginStart?.(plugin);

        try {
            // Initialize
            await plugin.initialize(context);

            // Execute
            const findings = await plugin.execute(context);

            // Teardown
            await plugin.teardown();

            const durationMs = Date.now() - startTime;
            this.logger.info(
                `Plugin ${plugin.meta.id} completed: ${findings.length} findings in ${durationMs}ms`,
            );

            return {
                pluginId: plugin.meta.id,
                pluginName: plugin.meta.name,
                category: plugin.meta.category,
                status: 'passed' as PluginStatus,
                findings,
                promptsExecuted: plugin.prompts.length,
                durationMs,
            };
        } catch (error) {
            const durationMs = Date.now() - startTime;
            const errorMsg = error instanceof Error ? error.message : String(error);

            this.logger.error(`Plugin ${plugin.meta.id} failed: ${errorMsg}`);

            return {
                pluginId: plugin.meta.id,
                pluginName: plugin.meta.name,
                category: plugin.meta.category,
                status: 'error' as PluginStatus,
                findings: [],
                promptsExecuted: 0,
                durationMs,
                error: errorMsg,
            };
        }
    }

    /**
     * Build the final scan report from collected data.
     */
    private buildReport(
        scanId: string,
        startedAt: string,
        completedAt: string,
        pluginsExecuted: number,
        totalPromptsSent: number,
        findings: Finding[],
        pluginResults: PluginExecutionResult[],
    ): ScanReport {
        const durationMs =
            new Date(completedAt).getTime() - new Date(startedAt).getTime();

        // Count by severity
        const criticalCount = findings.filter((f) => f.severity === 'critical').length;
        const highCount = findings.filter((f) => f.severity === 'high').length;
        const mediumCount = findings.filter((f) => f.severity === 'medium').length;
        const lowCount = findings.filter((f) => f.severity === 'low').length;
        const infoCount = findings.filter((f) => f.severity === 'info').length;

        // Overall risk score (average of all finding scores, or 0 if none)
        const overallRiskScore =
            findings.length > 0
                ? findings.reduce((sum, f) => sum + f.riskScore, 0) / findings.length
                : 0;

        // Category scores
        const categoryScores = {} as Record<AttackCategory, number>;
        for (const category of Object.values({
            pi: 'prompt-injection' as AttackCategory,
            dl: 'data-leakage' as AttackCategory,
            hal: 'hallucination' as AttackCategory,
            te: 'tool-exploit' as AttackCategory,
        })) {
            const catFindings = findings.filter((f) => f.category === category);
            categoryScores[category] =
                catFindings.length > 0
                    ? catFindings.reduce((sum, f) => sum + f.riskScore, 0) / catFindings.length
                    : 0;
        }

        // Overall severity
        const overallSeverity: SeverityLevel =
            overallRiskScore >= 9
                ? 'critical'
                : overallRiskScore >= 7
                    ? 'high'
                    : overallRiskScore >= 4
                        ? 'medium'
                        : 'low';

        return {
            meta: {
                scanId,
                targetUrl: this.config.target.url,
                startedAt,
                completedAt,
                durationMs,
                mantisVersion: '0.1.0',
                pluginsExecuted,
                totalPromptsSent,
            },
            summary: {
                totalFindings: findings.length,
                criticalCount,
                highCount,
                mediumCount,
                lowCount,
                infoCount,
                overallRiskScore: Math.round(overallRiskScore * 10) / 10,
                overallSeverity,
                categoryScores,
            },
            findings,
            pluginResults,
        };
    }

    /** Get the plugin registry (for CLI plugin list command) */
    getRegistry(): PluginRegistry {
        return this.registry;
    }

    /** Load plugins from a specific directory */
    async loadPlugins(pluginsDir: string): Promise<void> {
        await this.registry.discover(pluginsDir);
    }
}
