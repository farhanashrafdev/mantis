/**
 * mantis — Config Command
 *
 * Initialize and manage configuration files.
 *
 * Usage:
 *   mantis config init                    — Generate default mantis.config.yaml
 *   mantis config init --target https://...  — Generate config with target pre-filled
 */

import { Command } from 'commander';
import { writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import chalk from 'chalk';
import { printCompactBanner } from '../banner.js';

const DEFAULT_CONFIG_TEMPLATE = (targetUrl?: string) => `# mantis — Configuration File
# Documentation: https://github.com/farhanashrafdev/mantis/docs/configuration.md

version: "1.0"

# Target LLM application
target:
  url: "${targetUrl ?? 'https://your-ai-app.com/api/chat'}"
  method: POST
  headers:
    Content-Type: application/json
  # JSON path to the prompt field in request body
  promptField: prompt
  # JSON path to the response field in response body
  responseField: response
  # Bearer token (prefer MANTIS_AUTH_TOKEN env var)
  # authToken: "your-token-here"

# Module selection (omit to run all)
modules:
  include: []
  exclude: []
  # Examples:
  # include: ["prompt-injection", "data-leakage"]
  # exclude: ["hallucination/confidence-mismatch"]

# Scan behavior
scan:
  timeoutMs: 30000
  maxRetries: 2
  retryDelayMs: 1000
  rateLimit: 10
  severityThreshold: low
  reproducibilityAttempts: 3

# Output settings
output:
  format: table    # table | json | sarif
  # file: ./mantis-report.json
  verbose: false
  redactResponses: true

# ALVSS Scoring weights (must sum to 1.0)
scoring:
  weights:
    exploitability: 0.30
    impact: 0.25
    dataSensitivity: 0.20
    reproducibility: 0.15
    modelCompliance: 0.10

# Named profiles for different scan scenarios
profiles:
  quick:
    description: "Fast scan with critical checks only"
    modules:
      include: ["prompt-injection/system-override", "data-leakage/secret-retrieval"]
    scan:
      severityThreshold: high
      reproducibilityAttempts: 1

  aggressive:
    description: "Full scan with all modules and high reproducibility"
    scan:
      rateLimit: 5
      reproducibilityAttempts: 5
      severityThreshold: info

  ci:
    description: "CI/CD-optimized scan"
    output:
      format: json
      redactResponses: true
    scan:
      severityThreshold: medium
      reproducibilityAttempts: 2
`;

export function createConfigCommand(): Command {
    const config = new Command('config')
        .description('Manage mantis configuration');

    config
        .command('init')
        .description('Generate a default mantis.config.yaml')
        .option('-t, --target <url>', 'Pre-fill target URL')
        .option('-o, --output <path>', 'Output file path', 'mantis.config.yaml')
        .action(async (options) => {
            printCompactBanner();

            const outputPath = options['output'] as string;
            const targetUrl = options['target'] as string | undefined;

            if (existsSync(outputPath)) {
                console.error(chalk.yellow(`  ⚠  ${outputPath} already exists. Use --output to specify a different path.`));
                process.exit(1);
            }

            const content = DEFAULT_CONFIG_TEMPLATE(targetUrl);
            await writeFile(outputPath, content, 'utf-8');

            console.log(chalk.green(`  ✓ Configuration file created: ${outputPath}`));
            console.log(chalk.gray(`  Edit the file to configure your target and scan settings.`));
            console.log();
            console.log(chalk.gray(`  Quick start:`));
            console.log(chalk.white(`    mantis scan --config ${outputPath}`));
        });

    return config;
}
