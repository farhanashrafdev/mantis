/**
 * mantis — Scan Command
 *
 * The primary command: scans a target LLM application for security vulnerabilities.
 *
 * Usage:
 *   mantis scan --target https://app.com/api/chat
 *   mantis scan --target https://app.com/api/chat --modules prompt-injection --format json
 *   mantis scan --config mantis.config.yaml --profile aggressive
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { CoreEngine } from '../../core/engine.js';
import { printBanner, printLegalWarning } from '../banner.js';
import type {
    ScanConfig,
    Finding,
    PluginExecutionResult,
    ScanReport} from '../../types/types.js';
import {
    SeverityLevel,
    OutputFormat
} from '../../types/types.js';
import { CONFIG_DEFAULTS } from '../../types/config.js';

/** Build the default scan config from CLI arguments */
function buildScanConfig(options: Record<string, unknown>): ScanConfig {
    const target = options['target'] as string;
    const format = (options['format'] as OutputFormat) ?? CONFIG_DEFAULTS.output.format;
    const modules = options['modules'] as string | undefined;
    const severity = (options['severityThreshold'] as SeverityLevel) ?? CONFIG_DEFAULTS.scan.severityThreshold;
    const output = options['output'] as string | undefined;
    const verbose = (options['verbose'] as boolean) ?? CONFIG_DEFAULTS.output.verbose;
    const rateLimit = options['rateLimit'] === undefined ? (CONFIG_DEFAULTS.scan.rateLimit || 10) : Number(options['rateLimit']);
    const timeout = options['timeout'] === undefined ? (CONFIG_DEFAULTS.scan.timeoutMs || 30000) : Number(options['timeout']);

    const includeModules = modules ? modules.split(',').map((m) => m.trim()) : [];

    return {
        target: {
            url: target,
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            promptField: (options['promptField'] as string) ?? 'prompt',
            responseField: (options['responseField'] as string) ?? 'response',
            authToken: (options['authToken'] as string) ?? process.env['MANTIS_AUTH_TOKEN'],
        },
        modules: {
            include: includeModules,
            exclude: [],
        },
        scan: {
            timeoutMs: timeout,
            maxRetries: CONFIG_DEFAULTS.scan.maxRetries ?? 3,
            retryDelayMs: CONFIG_DEFAULTS.scan.retryDelayMs ?? 1000,
            rateLimit,
            severityThreshold: severity,
            reproducibilityAttempts: CONFIG_DEFAULTS.scan.reproducibilityAttempts ?? 1,
        },
        output: {
            format,
            file: output,
            verbose,
            redactResponses: CONFIG_DEFAULTS.output.redactResponses ?? true,
        },
        scoring: {
            weights: {
                exploitability: CONFIG_DEFAULTS.scoring.weights?.exploitability ?? 0.30,
                impact: CONFIG_DEFAULTS.scoring.weights?.impact ?? 0.25,
                dataSensitivity: CONFIG_DEFAULTS.scoring.weights?.dataSensitivity ?? 0.20,
                reproducibility: CONFIG_DEFAULTS.scoring.weights?.reproducibility ?? 0.15,
                modelCompliance: CONFIG_DEFAULTS.scoring.weights?.modelCompliance ?? 0.10
            }
        },
    };
}

/** Severity to colored string */
function colorSeverity(severity: SeverityLevel): string {
    switch (severity) {
        case SeverityLevel.Critical: return chalk.bgRed.white.bold(` CRITICAL `);
        case SeverityLevel.High: return chalk.red.bold('HIGH');
        case SeverityLevel.Medium: return chalk.yellow.bold('MEDIUM');
        case SeverityLevel.Low: return chalk.blue('LOW');
        case SeverityLevel.Info: return chalk.gray('INFO');
        default: return chalk.gray('INFO');
    }
}

/** Print scan results summary to terminal */
function printScanSummary(report: ScanReport): void {
    console.log();
    console.log(chalk.bold.white('═══════════════════════════════════════════════════════════'));
    console.log(chalk.bold.white('  SCAN RESULTS'));
    console.log(chalk.bold.white('═══════════════════════════════════════════════════════════'));
    console.log();

    // Meta
    console.log(chalk.gray(`  Scan ID:    ${report.meta.scanId}`));
    console.log(chalk.gray(`  Target:     ${report.meta.targetUrl}`));
    console.log(chalk.gray(`  Duration:   ${report.meta.durationMs}ms`));
    console.log(chalk.gray(`  Plugins:    ${report.meta.pluginsExecuted}`));
    console.log(chalk.gray(`  Prompts:    ${report.meta.totalPromptsSent}`));
    console.log();

    // Summary
    console.log(chalk.bold.white('  RISK SUMMARY'));
    console.log(chalk.white('  ───────────────────────────────────────────────────────'));

    const riskColor = report.summary.overallRiskScore >= 7
        ? chalk.red
        : report.summary.overallRiskScore >= 4
            ? chalk.yellow
            : chalk.green;

    console.log(`  Overall Risk Score: ${riskColor.bold(report.summary.overallRiskScore.toString())} / 10  [${colorSeverity(report.summary.overallSeverity)}]`);
    console.log();

    // Category breakdown
    for (const [category, score] of Object.entries(report.summary.categoryScores)) {
        if (score > 0) {
            const catColor = score >= 7 ? chalk.red : score >= 4 ? chalk.yellow : chalk.green;
            console.log(`  ${chalk.white(category.padEnd(20))} ${catColor.bold(score.toFixed(1).padStart(4))} / 10`);
        }
    }
    console.log();

    // Severity counts
    console.log(chalk.bold.white('  FINDINGS'));
    console.log(chalk.white('  ───────────────────────────────────────────────────────'));
    if (report.summary.criticalCount > 0) {console.log(`  ${chalk.bgRed.white.bold(` ${report.summary.criticalCount} `)} Critical`);}
    if (report.summary.highCount > 0) {console.log(`  ${chalk.red.bold(report.summary.highCount.toString())}   High`);}
    if (report.summary.mediumCount > 0) {console.log(`  ${chalk.yellow.bold(report.summary.mediumCount.toString())}   Medium`);}
    if (report.summary.lowCount > 0) {console.log(`  ${chalk.blue(report.summary.lowCount.toString())}   Low`);}
    if (report.summary.infoCount > 0) {console.log(`  ${chalk.gray(report.summary.infoCount.toString())}   Info`);}
    console.log(`  ${chalk.bold(report.summary.totalFindings.toString())}   Total`);
    console.log();

    // Individual findings
    if (report.findings.length > 0) {
        console.log(chalk.bold.white('  DETAILED FINDINGS'));
        console.log(chalk.white('  ───────────────────────────────────────────────────────'));
        console.log();

        for (const finding of report.findings) {
            printFinding(finding);
        }
    }

    console.log(chalk.gray('═══════════════════════════════════════════════════════════'));
    console.log();
}

/** Print a single finding */
function printFinding(finding: Finding): void {
    console.log(`  ${colorSeverity(finding.severity)}  ${chalk.bold.white(finding.title)}`);
    console.log(chalk.gray(`  ${finding.pluginId} | Score: ${finding.riskScore}/10 | Confidence: ${(finding.confidence * 100).toFixed(0)}%`));
    console.log(chalk.white(`  ${finding.description}`));

    if (finding.evidence) {
        console.log(chalk.gray(`  Evidence: ${finding.evidence.substring(0, 200)}${finding.evidence.length > 200 ? '...' : ''}`));
    }

    if (finding.remediation) {
        console.log(chalk.cyan(`  ↳ ${finding.remediation}`));
    }

    if (finding.cwe) {
        console.log(chalk.gray(`  CWE: ${finding.cwe}`));
    }

    console.log();
}

/**
 * Create and return the scan command.
 */
export function createScanCommand(): Command {
    const scan = new Command('scan')
        .description('Scan a target LLM application for security vulnerabilities')
        .requiredOption('-t, --target <url>', 'Target LLM application URL')
        .option('-f, --format <format>', 'Output format: table, json, sarif', 'table')
        .option('-m, --modules <modules>', 'Comma-separated list of modules to run')
        .option('-o, --output <file>', 'Write output to file')
        .option('-s, --severity-threshold <level>', 'Minimum severity to report: critical, high, medium, low, info', 'low')
        .option('-p, --profile <name>', 'Configuration profile to use')
        .option('-c, --config <path>', 'Path to mantis.config.yaml')
        .option('--prompt-field <path>', 'JSON path for prompt in request body', 'prompt')
        .option('--response-field <path>', 'JSON path for response in response body', 'response')
        .option('--auth-token <token>', 'Bearer token for authentication (prefer MANTIS_AUTH_TOKEN env var)')
        .option('--rate-limit <rps>', 'Max requests per second', String(CONFIG_DEFAULTS.scan.rateLimit || 10))
        .option('--timeout <ms>', 'Request timeout in milliseconds', String(CONFIG_DEFAULTS.scan.timeoutMs || 30000))
        .option('-v, --verbose', 'Enable verbose output', false)
        .action(async (options) => {
            printBanner();
            printLegalWarning();

            const config = buildScanConfig(options);

            console.log(chalk.white(`  Target: ${chalk.bold(config.target.url)}`));
            console.log(chalk.white(`  Format: ${config.output.format}`));
            if (config.modules.include.length > 0) {
                console.log(chalk.white(`  Modules: ${config.modules.include.join(', ')}`));
            }
            console.log();

            const spinner = ora({
                text: 'Initializing scan engine...',
                color: 'red',
            }).start();

            try {
                const engine = new CoreEngine(config, {
                    onPluginStart: (plugin) => {
                        spinner.text = `Testing: ${plugin.meta.name}...`;
                    },
                    onPluginComplete: (result: PluginExecutionResult) => {
                        const icon = result.findings.length > 0 ? chalk.red('✗') : chalk.green('✓');
                        spinner.stop();
                        console.log(`  ${icon} ${result.pluginName} — ${result.findings.length} findings (${result.durationMs}ms)`);
                        spinner.start();
                    },
                    onFinding: () => {
                        // Finding tracking handled in summary
                    },
                });

                spinner.text = 'Loading attack plugins...';
                // Plugin discovery happens inside engine.scan()

                spinner.text = 'Executing attack modules...';
                const report = await engine.scan();

                spinner.stop();

                // Output based on format
                if (config.output.format === OutputFormat.JSON) {
                    const jsonOutput = JSON.stringify(report, null, 2);
                    if (config.output.file) {
                        const { writeFile } = await import('node:fs/promises');
                        await writeFile(config.output.file, jsonOutput, 'utf-8');
                        console.log(chalk.green(`\n  Report written to ${config.output.file}`));
                    } else {
                        console.log(jsonOutput);
                    }
                } else if (config.output.format === OutputFormat.SARIF) {
                    const { SARIFReporter } = await import('../../reporters/sarif-reporter.js');
                    const sarifReporter = new SARIFReporter();
                    const sarifOutput = sarifReporter.generate(report);
                    if (config.output.file) {
                        const { writeFile } = await import('node:fs/promises');
                        await writeFile(config.output.file, sarifOutput, 'utf-8');
                        console.log(chalk.green(`\n  SARIF report written to ${config.output.file}`));
                    } else {
                        console.log(sarifOutput);
                    }
                } else {
                    printScanSummary(report);
                }

                // Exit code based on findings
                const exitCode = report.summary.criticalCount > 0 || report.summary.highCount > 0 ? 1 : 0;
                process.exit(exitCode);

            } catch (error) {
                spinner.stop();
                const msg = error instanceof Error ? error.message : String(error);
                console.error(chalk.red(`\n  ✗ Scan failed: ${msg}`));
                process.exit(2);
            }
        });

    return scan;
}
