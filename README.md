<div align="center">

# 🔒 Mantis

**Open-source CLI toolkit for automated red-teaming of LLM-powered applications**

[![CI](https://github.com/farhanashrafdev/mantis/actions/workflows/ci.yml/badge.svg)](https://github.com/farhanashrafdev/mantis/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-green.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org)
[![Docker](https://img.shields.io/badge/Docker-GHCR-blue.svg)](https://ghcr.io/farhanashrafdev/mantis)

*Detect prompt injection, data leakage, hallucination, and agent exploitation vulnerabilities in AI applications.*

[Quick Start](#quick-start) • [Attack Modules](#attack-modules) • [Architecture](#architecture) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## What is Mantis?

**Mantis** is an open-source, modular CLI tool for automated security testing of LLM-powered applications. Think **OWASP ZAP** meets **Burp Suite** — but purpose-built for the AI era.

Mantis systematically probes your AI applications for:

- 🔴 **Prompt Injection** — system prompt overrides, jailbreaks, instruction extraction
- 🟠 **Data Leakage** — secret extraction, hidden prompt exposure, memory exfiltration
- 🟡 **Hallucination** — fabricated entities, fake URLs, citation failures
- 🟣 **Tool/Agent Exploitation** — forced tool invocation, unauthorized actions, function manipulation

## Quick Start

### Installation

```bash
# npm (global)
npm install -g mantis-ai

# Or run with Docker
docker pull ghcr.io/farhanashrafdev/mantis:latest
```

### Run Your First Scan

```bash
mantis scan --target https://your-ai-app.com/api/chat --format table
```

### Using Docker

```bash
docker run --rm ghcr.io/farhanashrafdev/mantis:latest \
    scan --target https://your-ai-app.com/api/chat --format json
```

### Using a Config File

```bash
mantis scan --config mantis.config.yaml
```

### CI/CD Integration

```yaml
# .github/workflows/ai-security.yml
- name: Mantis AI Security Scan
  run: mantis scan --target ${{ secrets.AI_APP_URL }} --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed — no critical or high severity findings |
| `1` | Scan completed — critical or high severity findings detected |
| `2` | Runtime error (invalid config, network failure, etc.) |

## Attack Modules

| Module | Plugins | Attacks | Status |
|--------|---------|---------|--------|
| Prompt Injection | 4 | 20 | ✅ |
| Data Leakage | 4 | 16 | ✅ |
| Hallucination | 4 | 15 | ✅ |
| Tool/Agent Exploit | 4 | 16 | ✅ |
| **Total** | **16** | **67** | |

## Architecture

```mermaid
graph LR
    CLI["CLI"]
    CLI --> Engine["CoreEngine"]
    Engine --> Registry["PluginRegistry"]
    Registry --> PI["Prompt Injection<br/>4 plugins · 20 attacks"]
    Registry --> DL["Data Leakage<br/>4 plugins · 16 attacks"]
    Registry --> HL["Hallucination<br/>4 plugins · 15 attacks"]
    Registry --> TE["Tool Exploit<br/>4 plugins · 16 attacks"]
    Engine --> Adapter["HttpAdapter"]
    Adapter --> Target["Target LLM"]
    Engine --> Scoring["ALVSS Scorer"]
    Engine --> Reporter["Table · JSON · SARIF"]
```

For the full architecture breakdown, see [docs/architecture.md](docs/architecture.md).

## Risk Scoring

Mantis uses **ALVSS** (AI LLM Vulnerability Scoring System) — a CVSS-inspired scoring model tailored for AI applications:

| Dimension | Weight |
|-----------|--------|
| Exploitability | 30% |
| Impact | 25% |
| Data Sensitivity | 20% |
| Reproducibility | 15% |
| Model Compliance | 10% |

Scores map to severity: **Critical** (≥9) → **High** (≥7) → **Medium** (≥4) → **Low** (<4)

For the full scoring specification, see [docs/scoring-model.md](docs/scoring-model.md).

## Output Formats

- **Table** — colored terminal output for interactive use
- **JSON** — structured data for processing
- **SARIF** — GitHub Security tab integration

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Plugin Authoring Guide](docs/plugin-authoring.md)
- [Scoring Model](docs/scoring-model.md)
- [Configuration Reference](docs/configuration.md)

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 1 | Core engine, 4 attack categories, 67 attacks, CLI, JSON/table/SARIF reports, ALVSS scoring, config system, Docker, CI/CD | ✅ Complete |
| Phase 2 | Plugin marketplace, multi-model support, advanced rate limiting, scan replay | 📋 Planned |
| Phase 3 | Attack chaining, AI-assisted attacks, campaign mode, web dashboard | 📋 Planned |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

The easiest way to contribute is by [writing attack plugins](docs/plugin-authoring.md).

## Security

For reporting security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for the security community, by the security community.**

</div>
