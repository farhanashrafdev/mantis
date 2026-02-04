/**
 * mantis — Plugin Command
 *
 * List, inspect, and validate installed attack plugins.
 *
 * Usage:
 *   mantis plugin list
 *   mantis plugin info prompt-injection/system-override
 *   mantis plugin validate ./custom-plugin.ts
 */

import { Command } from 'commander';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import chalk from 'chalk';
import { PluginRegistry } from '../../core/plugin-registry.js';
import { printCompactBanner } from '../banner.js';

/** Resolve the built-in plugins directory */
function getPluginsDir(): string {
    const currentFile = fileURLToPath(import.meta.url);
    return join(dirname(dirname(dirname(currentFile))), 'plugins');
}

export function createPluginCommand(): Command {
    const plugin = new Command('plugin')
        .description('Manage and inspect attack plugins');

    // mantis plugin list
    plugin
        .command('list')
        .description('List all available attack plugins')
        .option('--category <cat>', 'Filter by category')
        .action(async (options) => {
            printCompactBanner();

            const registry = new PluginRegistry();
            const pluginsDir = getPluginsDir();

            try {
                await registry.discover(pluginsDir);
            } catch (error) {
                const msg = error instanceof Error ? error.message : String(error);
                console.error(chalk.red(`  ✗ Plugin discovery failed: ${msg}`));
                process.exit(2);
            }

            const plugins = registry.getAll();
            const categoryFilter = options['category'] as string | undefined;

            if (plugins.length === 0) {
                console.log(chalk.yellow('  No plugins found.'));
                return;
            }

            console.log(chalk.bold.white(`  ${plugins.length} plugins loaded\n`));

            // Group by category
            const categories = registry.getCategories();
            for (const category of categories) {
                if (categoryFilter && category !== categoryFilter) continue;

                const catPlugins = registry.getByCategory(category);
                console.log(chalk.bold.redBright(`  ▸ ${category}`));

                for (const p of catPlugins) {
                    console.log(
                        `    ${chalk.white(p.meta.id.padEnd(45))} ${chalk.gray(p.meta.description.substring(0, 50))}  ${chalk.gray(`[${p.prompts.length} prompts]`)}`
                    );
                }
                console.log();
            }
        });

    // mantis plugin info <id>
    plugin
        .command('info <pluginId>')
        .description('Show detailed information about a specific plugin')
        .action(async (pluginId: string) => {
            printCompactBanner();

            const registry = new PluginRegistry();
            await registry.discover(getPluginsDir());

            const p = registry.getById(pluginId);
            if (!p) {
                console.error(chalk.red(`  ✗ Plugin not found: ${pluginId}`));
                console.log(chalk.gray(`  Run 'mantis plugin list' to see available plugins.`));
                process.exit(1);
            }

            console.log(chalk.bold.white(`  Plugin: ${p.meta.name}`));
            console.log(chalk.gray(`  ID:          ${p.meta.id}`));
            console.log(chalk.gray(`  Category:    ${p.meta.category}`));
            console.log(chalk.gray(`  Version:     ${p.meta.version}`));
            console.log(chalk.gray(`  Author:      ${p.meta.author}`));
            console.log(chalk.gray(`  Description: ${p.meta.description}`));
            console.log(chalk.gray(`  Tags:        ${p.meta.tags.join(', ')}`));
            console.log(chalk.gray(`  Prompts:     ${p.prompts.length}`));
            console.log();

            console.log(chalk.bold.white('  Attack Prompts:'));
            for (const prompt of p.prompts) {
                console.log(`    ${chalk.yellow('▸')} ${chalk.white(prompt.id)} — ${chalk.gray(prompt.description)}`);
            }
        });

    return plugin;
}
