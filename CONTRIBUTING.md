# Contributing to Mantis

Thank you for your interest in contributing to Mantis! This guide will help you get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/farhanashrafdev/mantis.git
cd mantis

# Install dependencies
npm install

# Run TypeScript type checking
npm run typecheck

# Run in development mode
npm run dev -- scan --target http://localhost:3000/api/chat
```

## Project Structure

```
src/
├── cli/           # CLI commands (Commander.js)
├── core/          # CoreEngine, PluginRegistry
├── adapters/      # LLM adapters (HTTP, etc.)
├── plugins/       # Attack modules
├── scoring/       # ALVSS scoring engine
├── reporters/     # Output formatters
├── config/        # Configuration loader
└── types/         # TypeScript interfaces
```

## Code Style

- **Language:** TypeScript 5.7+ with strict mode
- **Module System:** ESM (`"type": "module"`)
- **Target:** ES2022
- **Formatting:** Use your editor's TypeScript formatter
- **Naming:**
  - Files: `kebab-case.ts`
  - Classes: `PascalCase`
  - Functions/variables: `camelCase`
  - Constants: `UPPER_SNAKE_CASE`

## Writing Plugins

The easiest way to contribute is by adding attack plugins. See the [Plugin Authoring Guide](docs/plugin-authoring.md) for a step-by-step walkthrough.

**TL;DR:**

1. Create a file in `src/plugins/<category>/`
2. Extend `BasePlugin` and define `meta` + `prompts`
3. Export a default instance
4. That's it — Mantis auto-discovers the plugin

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new data-leakage plugin for PII detection
fix: handle timeout in HTTP adapter retry logic
docs: update plugin authoring guide
test: add unit tests for ALVSS scoring engine
refactor: simplify plugin registry discovery
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feat/my-feature`
3. **Make your changes** with clear commit messages
4. **Run checks:** `npm run typecheck`
5. **Push** and open a PR against `main`
6. **Describe** your changes in the PR body

### PR Checklist

- [ ] TypeScript compiles without errors (`npm run typecheck`)
- [ ] New plugins follow the `BasePlugin` pattern
- [ ] Documentation updated if applicable
- [ ] Commit messages follow Conventional Commits

## Reporting Bugs

Open an issue with:

1. **Steps to reproduce**
2. **Expected behavior**
3. **Actual behavior**
4. **Node.js version** (`node --version`)
5. **mantis version** (`mantis --version`)

## Feature Requests

Open an issue with the `enhancement` label. Describe the use case and proposed solution.

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
