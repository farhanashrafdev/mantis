/**
 * mantis — CLI Banner
 *
 * ASCII art banner with version info and legal/ethical warning.
 * Displayed on every scan invocation.
 */

import chalk from 'chalk';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

/** Read version from package.json once at module load */
const MANTIS_VERSION = ((): string => {
    try {
        const currentFile = fileURLToPath(import.meta.url);
        const pkgPath = join(dirname(dirname(currentFile)), '..', 'package.json');
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as { version: string };
        return pkg.version;
    } catch {
        return '0.0.0';
    }
})();

const ASCII_ART = `
${chalk.redBright(`  ███╗   ███╗ █████╗ ███╗   ██╗████████╗██╗███████╗`)}
${chalk.redBright(`  ████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝`)}
${chalk.redBright(`  ██╔████╔██║███████║██╔██╗ ██║   ██║   ██║███████╗`)}
${chalk.redBright(`  ██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██║╚════██║`)}
${chalk.redBright(`  ██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║███████║`)}
${chalk.redBright(`  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝`)}
`;

const TAGLINE = chalk.gray('  AI Red Team Toolkit — Automated LLM Security Testing');

const VERSION_LINE = chalk.gray(`  v${MANTIS_VERSION} | https://github.com/farhanashrafdev/mantis`);

const LEGAL_WARNING = `
${chalk.yellowBright('  ⚠  LEGAL & ETHICAL NOTICE')}
${chalk.yellow('  ─────────────────────────────────────────────────────────')}
${chalk.yellow('  This tool is designed for AUTHORIZED security testing only.')}
${chalk.yellow('  You MUST have explicit permission to test the target system.')}
${chalk.yellow('  Unauthorized testing may violate local laws and regulations.')}
${chalk.yellow('  The authors assume no liability for misuse of this tool.')}
${chalk.yellow('  ─────────────────────────────────────────────────────────')}
`;

/**
 * Print the full banner to stdout.
 * Called before every scan execution.
 */
export function printBanner(): void {
    console.log(ASCII_ART);
    console.log(TAGLINE);
    console.log(VERSION_LINE);
    console.log();
}

/**
 * Print the legal/ethical warning.
 * Called before scan execution.
 */
export function printLegalWarning(): void {
    console.log(LEGAL_WARNING);
}

/**
 * Print a compact one-line banner (for non-scan commands).
 */
export function printCompactBanner(): void {
    console.log(
        `${chalk.redBright('mantis')} ${chalk.gray(`v${MANTIS_VERSION}`)} ${chalk.gray('— AI Red Team Toolkit')}`
    );
    console.log();
}
