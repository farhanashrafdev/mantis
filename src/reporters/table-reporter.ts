/**
 * mantis — Table Reporter
 *
 * Renders scan results as a formatted CLI table with colors,
 * severity indicators, and summary statistics.
 *
 * Used for terminal output (default format).
 */

import Table from 'cli-table3';
import chalk from 'chalk';
import {
    ScanReport,
    Reporter,
    SeverityLevel,
    OutputFormat,
} from '../types/types.js';

/** Severity to display string with color */
function severityDisplay(severity: SeverityLevel): string {
    switch (severity) {
        case SeverityLevel.Critical: return chalk.bgRed.white.bold(' CRIT ');
        case SeverityLevel.High: return chalk.red.bold('HIGH');
        case SeverityLevel.Medium: return chalk.yellow.bold('MED ');
        case SeverityLevel.Low: return chalk.blue('LOW ');
        case SeverityLevel.Info: return chalk.gray('INFO');
        default: return chalk.gray('INFO');
    }
}

/** Risk score to colored display */
function scoreDisplay(score: number): string {
    const fixed = score.toFixed(1);
    if (score >= 9) return chalk.bgRed.white.bold(` ${fixed} `);
    if (score >= 7) return chalk.red.bold(fixed);
    if (score >= 4) return chalk.yellow.bold(fixed);
    return chalk.green(fixed);
}

/**
 * TableReporter — format scan results as CLI tables.
 */
export class TableReporter implements Reporter {
    name = 'table';
    format: OutputFormat = OutputFormat.Table;

    generate(report: ScanReport): string {
        const lines: string[] = [];

        // Header
        lines.push('');
        lines.push(chalk.bold.white('═══════════════════════════════════════════════════════════════════════════'));
        lines.push(chalk.bold.white('  MANTIS SCAN REPORT'));
        lines.push(chalk.bold.white('═══════════════════════════════════════════════════════════════════════════'));
        lines.push('');

        // Scan metadata
        const metaTable = new Table({
            chars: { 'top': '', 'top-mid': '', 'top-left': '', 'top-right': '', 'bottom': '', 'bottom-mid': '', 'bottom-left': '', 'bottom-right': '', 'left': '  ', 'left-mid': '', 'mid': '', 'mid-mid': '', 'right': '', 'right-mid': '', 'middle': ' │ ' },
            style: { 'padding-left': 0, 'padding-right': 0 },
        });

        metaTable.push(
            [chalk.gray('Scan ID'), chalk.white(report.meta.scanId)],
            [chalk.gray('Target'), chalk.white(report.meta.targetUrl)],
            [chalk.gray('Duration'), chalk.white(`${report.meta.durationMs}ms`)],
            [chalk.gray('Plugins Run'), chalk.white(report.meta.pluginsExecuted.toString())],
            [chalk.gray('Prompts Sent'), chalk.white(report.meta.totalPromptsSent.toString())],
            [chalk.gray('Started At'), chalk.white(report.meta.startedAt)],
            [chalk.gray('Completed At'), chalk.white(report.meta.completedAt)],
        );
        lines.push(metaTable.toString());
        lines.push('');

        // Risk summary
        const riskColor = report.summary.overallRiskScore >= 7
            ? chalk.red
            : report.summary.overallRiskScore >= 4
                ? chalk.yellow
                : chalk.green;

        lines.push(chalk.bold.white('  RISK ASSESSMENT'));
        lines.push(chalk.gray('  ─────────────────────────────────────────────────────────────'));

        const riskTable = new Table({
            chars: { 'top': '', 'top-mid': '', 'top-left': '', 'top-right': '', 'bottom': '', 'bottom-mid': '', 'bottom-left': '', 'bottom-right': '', 'left': '  ', 'left-mid': '', 'mid': '', 'mid-mid': '', 'right': '', 'right-mid': '', 'middle': ' │ ' },
            style: { 'padding-left': 0, 'padding-right': 0 },
        });

        riskTable.push(
            [chalk.bold('Overall Risk'), `${riskColor.bold(report.summary.overallRiskScore.toString())} / 10  [${severityDisplay(report.summary.overallSeverity)}]`],
        );

        // Add category scores
        for (const [cat, score] of Object.entries(report.summary.categoryScores)) {
            if (score > 0) {
                riskTable.push([chalk.gray(cat), scoreDisplay(score)]);
            }
        }

        lines.push(riskTable.toString());
        lines.push('');

        // Severity distribution
        lines.push(chalk.bold.white('  FINDINGS DISTRIBUTION'));
        lines.push(chalk.gray('  ─────────────────────────────────────────────────────────────'));

        const distTable = new Table({
            chars: { 'top': '', 'top-mid': '', 'top-left': '', 'top-right': '', 'bottom': '', 'bottom-mid': '', 'bottom-left': '', 'bottom-right': '', 'left': '  ', 'left-mid': '', 'mid': '', 'mid-mid': '', 'right': '', 'right-mid': '', 'middle': ' │ ' },
            style: { 'padding-left': 0, 'padding-right': 0 },
        });

        type SeverityKey = 'criticalCount' | 'highCount' | 'mediumCount' | 'lowCount' | 'infoCount';
        const severityData: { label: string; key: SeverityKey; sev: SeverityLevel }[] = [
            { label: 'Critical', key: 'criticalCount', sev: SeverityLevel.Critical },
            { label: 'High', key: 'highCount', sev: SeverityLevel.High },
            { label: 'Medium', key: 'mediumCount', sev: SeverityLevel.Medium },
            { label: 'Low', key: 'lowCount', sev: SeverityLevel.Low },
            { label: 'Info', key: 'infoCount', sev: SeverityLevel.Info },
        ];

        for (const { key, sev } of severityData) {
            const count = report.summary[key];
            if (count > 0) {
                const bar = '█'.repeat(Math.min(count * 2, 40));
                distTable.push([severityDisplay(sev), chalk.bold(count.toString()), chalk.gray(bar)]);
            }
        }
        distTable.push([chalk.bold('Total'), chalk.bold(report.summary.totalFindings.toString()), '']);

        lines.push(distTable.toString());
        lines.push('');

        // Detailed findings
        if (report.findings.length > 0) {
            lines.push(chalk.bold.white('  DETAILED FINDINGS'));
            lines.push(chalk.gray('  ─────────────────────────────────────────────────────────────'));
            lines.push('');

            const findingsTable = new Table({
                head: [
                    chalk.bold('#'),
                    chalk.bold('Severity'),
                    chalk.bold('Score'),
                    chalk.bold('Plugin'),
                    chalk.bold('Title'),
                    chalk.bold('Confidence'),
                ],
                colWidths: [5, 10, 8, 30, 35, 12],
                style: { head: [], border: ['gray'] },
                wordWrap: true,
            });

            report.findings.forEach((f, i) => {
                findingsTable.push([
                    (i + 1).toString(),
                    severityDisplay(f.severity),
                    scoreDisplay(f.riskScore),
                    f.pluginId,
                    f.title,
                    `${(f.confidence * 100).toFixed(0)}%`,
                ]);
            });

            lines.push(findingsTable.toString());
            lines.push('');

            // Remediation summary
            const remediations = [...new Set(report.findings.filter((f) => f.remediation).map((f) => f.remediation!))];
            if (remediations.length > 0) {
                lines.push(chalk.bold.white('  REMEDIATION GUIDANCE'));
                lines.push(chalk.gray('  ─────────────────────────────────────────────────────────────'));
                remediations.forEach((r, i) => {
                    lines.push(`  ${chalk.cyan(`${i + 1}.`)} ${r}`);
                });
                lines.push('');
            }
        } else {
            lines.push(chalk.green.bold('  ✓ No vulnerabilities found!'));
            lines.push('');
        }

        lines.push(chalk.gray('═══════════════════════════════════════════════════════════════════════════'));
        lines.push('');

        return lines.join('\n');
    }

    async writeToFile(report: ScanReport, outputPath: string): Promise<void> {
        const { writeFile } = await import('node:fs/promises');
        // Strip ANSI for file output
        const content = this.generate(report);
        const stripped = content.replace(/\x1b\[[0-9;]*m/g, '');
        await writeFile(outputPath, stripped, 'utf-8');
    }
}
