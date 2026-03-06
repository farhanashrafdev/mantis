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
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createScanCommand } from './commands/scan.js';
import { createReportCommand } from './commands/report.js';
import { createPluginCommand } from './commands/plugin.js';
import { createConfigCommand } from './commands/config.js';

/** Read version from package.json */
const version = ((): string => {
    try {
        const currentFile = fileURLToPath(import.meta.url);
        const pkgPath = join(dirname(dirname(currentFile)), '..', 'package.json');
        return (JSON.parse(readFileSync(pkgPath, 'utf-8')) as { version: string }).version;
    } catch {
        return '0.0.0';
    }
})();

const program = new Command();

program
    .name('mantis')
    .description('AI Red Team Toolkit — Automated LLM Security Testing')
    .version(version, '-V, --version', 'Display mantis version')
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
