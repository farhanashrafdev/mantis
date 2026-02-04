/**
 * mantis — Report Command
 *
 * Re-generate reports from a previous scan's JSON output.
 * Useful for converting between formats without re-scanning.
 *
 * Usage:
 *   mantis report --input scan-results.json --format table
 *   mantis report --input scan-results.json --format sarif --output results.sarif
 */

import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import chalk from 'chalk';
import { printCompactBanner } from '../banner.js';
import type { ScanReport } from '../../types/types.js';

export function createReportCommand(): Command {
    const report = new Command('report')
        .description('Re-generate a report from previous scan JSON output')
        .requiredOption('-i, --input <file>', 'Path to scan results JSON file')
        .option('-f, --format <format>', 'Output format: table, json, sarif', 'table')
        .option('-o, --output <file>', 'Write output to file')
        .action(async (options) => {
            printCompactBanner();

            const inputPath = options['input'] as string;
            const format = options['format'] as string;
            const outputPath = options['output'] as string | undefined;

            try {
                const raw = await readFile(inputPath, 'utf-8');
                const report = JSON.parse(raw) as ScanReport;

                console.log(chalk.gray(`  Loaded scan ${report.meta.scanId}`));
                console.log(chalk.gray(`  ${report.summary.totalFindings} findings from ${report.meta.pluginsExecuted} plugins`));
                console.log();

                // Format conversion will be handled by the reporting engine (Commit 10)
                // For now, output the JSON
                const output = JSON.stringify(report, null, 2);

                if (outputPath) {
                    await writeFile(outputPath, output, 'utf-8');
                    console.log(chalk.green(`  Report written to ${outputPath} (${format})`));
                } else {
                    console.log(output);
                }
            } catch (error) {
                const msg = error instanceof Error ? error.message : String(error);
                console.error(chalk.red(`  ✗ Failed to process report: ${msg}`));
                process.exit(2);
            }
        });

    return report;
}
