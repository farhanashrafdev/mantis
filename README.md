<div align="center">

# 🔒 Mantis

**Open-source CLI toolkit for automated red-teaming of LLM-powered applications**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-green.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org)

*Detect prompt injection, data leakage, hallucination, and agent exploitation vulnerabilities in AI applications.*

[Quick Start](#quick-start) • [Attack Modules](#attack-modules) • [Documentation](#documentation) • [Contributing](#contributing)

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
npm install -g mantis-ai
```

### Run Your First Scan

```bash
mantis scan --target https://your-ai-app.com/api/chat --format table
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
```

## Attack Modules

| Module | Tests | Status |
|---|---|---|
| Prompt Injection | System override, instruction extraction, jailbreak, role confusion | ✅ Phase 1 |
| Data Leakage | Hidden prompts, secrets, API keys, memory/context | ✅ Phase 1 |
| Hallucination | Fake entities, citation check, fabricated URLs, confidence mismatch | ✅ Phase 1 |
| Tool/Agent Exploit | Forced invocation, connector abuse, unauthorized actions | ✅ Phase 1 |

## Risk Scoring

Mantis uses **ALVSS** (AI LLM Vulnerability Scoring System) — a CVSS-inspired scoring model tailored for AI applications:

| Dimension | Weight |
|---|---|
| Exploitability | 30% |
| Impact | 25% |
| Data Sensitivity | 20% |
| Reproducibility | 15% |
| Model Compliance | 10% |

Scores map to severity: **Critical** (≥9) → **High** (≥7) → **Medium** (≥4) → **Low** (<4)

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
|---|---|---|
| Phase 1 | Core engine, 4 attack categories, CLI, JSON/table reports | 🔄 In Progress |
| Phase 2 | SARIF, plugin marketplace, multi-model, rate limiting, replay | 📋 Planned |
| Phase 3 | Attack chaining, AI-assisted attacks, campaign mode, dashboard | 📋 Planned |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for the security community, by the security community.**

</div>
