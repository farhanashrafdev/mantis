#!/usr/bin/env node

/**
 * mantis — CLI Entry Point
 *
 * AI Red Team Toolkit — Automated LLM Security Testing
 *
 * Commands:
 *   mantis scan      — Scan a target LLM application
 *   mantis report    — Re-generate reports from scan data
 *   mantis plugin    — List and inspect attack plugins
 *   mantis config    — Manage configuration files
 */

import { Command } from 'commander';
import { createScanCommand } from './commands/scan.js';
import { createReportCommand } from './commands/report.js';
import { createPluginCommand } from './commands/plugin.js';
import { createConfigCommand } from './commands/config.js';

const program = new Command();

program
    .name('mantis')
    .description('AI Red Team Toolkit — Automated LLM Security Testing')
    .version('0.1.0', '-V, --version', 'Display mantis version')
    .addCommand(createScanCommand())
    .addCommand(createReportCommand())
    .addCommand(createPluginCommand())
    .addCommand(createConfigCommand());

/**
 * Exit Codes:
 *   0 — Scan completed, no critical/high findings
 *   1 — Scan completed, critical or high findings detected
 *   2 — Runtime error (bad config, network failure, etc.)
 */
(async () => {
    try {
        await program.parseAsync(process.argv);
    } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        console.error(`\n  ✗ Fatal: ${msg}`);
        process.exit(2);
    }
})();
