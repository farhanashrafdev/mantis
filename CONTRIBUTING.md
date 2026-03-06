# Contributing to Mantis

Thank you for your interest in contributing to Mantis! This guide covers everything you need to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/farhanashrafdev/mantis.git
cd mantis

# Install dependencies
npm install

# Verify everything works
npm run typecheck    # TypeScript compilation check
npm run lint         # ESLint
npm run test         # Vitest test suite
```

### Commands

| Command | Description |
|---------|-------------|
| `npm run build` | Compile TypeScript to `dist/` |
| `npm run dev -- scan --target URL` | Run from source via `tsx` |
| `npm run typecheck` | Type-check without emitting |
| `npm run lint` | Run ESLint |
| `npm run test` | Run test suite (single run) |
| `npm run test:watch` | Run tests in watch mode |

## Project Structure

```
src/
├── cli/           # CLI commands (Commander.js)
├── core/          # CoreEngine, PluginRegistry
├── adapters/      # LLM adapters (HTTP)
├── plugins/       # Attack modules (grouped by category)
│   ├── base-plugin.ts
│   ├── prompt-injection/
│   ├── data-leakage/
│   ├── hallucination/
│   └── tool-exploit/
├── scoring/       # ALVSS scoring engine
├── reporters/     # Table, JSON, SARIF output formatters
├── config/        # Configuration loader
└── types/         # TypeScript interfaces
```

## Code Standards

- **TypeScript strict mode** — `strict: true`, zero `any` types
- **Explicit return types** on all functions
- **Type imports** — `import type { Foo } from './bar.js'`
- **ESLint enforced** — `no-explicit-any: error`, `no-eval: error`, `no-new-func: error`

### Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Files | `kebab-case.ts` | `config-loader.ts` |
| Classes | `PascalCase` | `CoreEngine` |
| Functions/variables | `camelCase` | `loadConfig` |
| Constants | `UPPER_SNAKE_CASE` | `DEFAULT_TIMEOUT` |

## Writing Plugins

The easiest way to contribute is by adding attack plugins. See [docs/plugin-authoring.md](docs/plugin-authoring.md).

1. Create a file in `src/plugins/<category>/`
2. Extend `BasePlugin` and define `meta` + `prompts`
3. Export a default instance
4. Mantis auto-discovers the plugin

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(plugins): add SSRF detection plugin
fix(adapter): handle timeout in retry logic
docs: update plugin authoring guide
test(scoring): add ALVSS edge case tests
refactor(core): simplify plugin discovery
security: patch yaml parser vulnerability
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `master`: `git checkout -b feat/my-feature`
3. **Make focused, atomic commits** with conventional messages
4. **Run all checks:**
   ```bash
   npm run typecheck
   npm run lint
   npm run test
   ```
5. **Push** and open a PR against `master`

### PR Checklist

- [ ] TypeScript compiles without errors (`npm run typecheck`)
- [ ] ESLint passes with no warnings (`npm run lint`)
- [ ] Tests pass (`npm run test`)
- [ ] New plugins follow the `BasePlugin` pattern
- [ ] Documentation updated if applicable
- [ ] Commit messages follow Conventional Commits
- [ ] PR is focused — one logical change

### Review Process

- Every PR requires at least one maintainer review
- Squash merge to keep history clean
- Nit comments prefixed with `nit:` are optional to address

## Reporting Bugs

Open an [issue](https://github.com/farhanashrafdev/mantis/issues) with:

1. Steps to reproduce
2. Expected vs actual behavior
3. Node.js version (`node --version`)
4. Mantis version (`mantis --version`)
5. OS and environment

## Feature Requests

Open an issue with the `enhancement` label. Describe the use case and proposed solution.

## Security Vulnerabilities

**DO NOT** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
