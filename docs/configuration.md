# Configuration Reference

Mantis supports configuration via YAML file, CLI flags, environment variables, and named profiles.

## Priority Order

Configuration values are resolved in the following priority (highest wins):

```
Environment Variables  >  CLI Flags  >  Profile  >  YAML File  >  Built-in Defaults
```

## Config File

Mantis looks for configuration files in the current directory, checking these names in order:

1. `mantis.config.yaml`
2. `mantis.config.yml`
3. `.mantis.yaml`
4. `.mantis.yml`

Generate a starter config:

```bash
mantis config init
```

### Full Example

```yaml
version: "1.0"

target:
  url: https://your-ai-app.com/api/chat
  method: POST
  headers:
    Content-Type: application/json
    X-Custom-Header: value
  promptField: prompt         # JSON path for prompt in request body
  responseField: response     # JSON path for response in response body
  # authToken: "..."          # Prefer MANTIS_AUTH_TOKEN env var

modules:
  include: []                 # Empty = all modules (default)
  exclude:
    - hallucination/confidence-mismatch

scan:
  timeoutMs: 30000            # Request timeout (default: 30000)
  maxRetries: 2               # Retries on failure (default: 2)
  retryDelayMs: 1000          # Delay between retries (default: 1000)
  rateLimit: 10               # Max requests/second (default: 10)
  severityThreshold: low      # Minimum severity to report (default: low)
  reproducibilityAttempts: 3  # Verification attempts (default: 3)

output:
  format: table               # table | json | sarif (default: table)
  file: report.json           # Output to file (default: stdout)
  verbose: false              # Full response output (default: false)
  redactResponses: true       # Truncate responses (default: true)

scoring:
  weights:
    exploitability: 0.30
    impact: 0.25
    dataSensitivity: 0.20
    reproducibility: 0.15
    modelCompliance: 0.10

profiles:
  quick:
    description: Fast scan with reduced coverage
    modules:
      include:
        - prompt-injection/system-override
        - data-leakage/secret-retrieval
    scan:
      reproducibilityAttempts: 1
      rateLimit: 20

  aggressive:
    description: Full coverage, deep testing
    scan:
      reproducibilityAttempts: 5
      rateLimit: 5
      timeoutMs: 60000

  ci:
    description: CI-friendly with SARIF output
    output:
      format: sarif
      file: mantis-results.sarif
      verbose: false
    scan:
      reproducibilityAttempts: 2
```

## CLI Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--target <url>` | `-t` | Target LLM application URL | **required** |
| `--format <fmt>` | `-f` | Output format: `table`, `json`, `sarif` | `table` |
| `--modules <ids>` | `-m` | Comma-separated list of modules | all |
| `--output <file>` | `-o` | Write output to file | stdout |
| `--severity-threshold <lvl>` | `-s` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` | `low` |
| `--profile <name>` | `-p` | Use a named profile from config | — |
| `--config <path>` | `-c` | Path to config file | auto-detect |
| `--prompt-field <path>` | — | JSON path for prompt in request body | `prompt` |
| `--response-field <path>` | — | JSON path for response in response body | `response` |
| `--auth-token <token>` | — | Bearer auth token | env var |
| `--rate-limit <rps>` | — | Max requests per second | `10` |
| `--timeout <ms>` | — | Request timeout in ms | `30000` |
| `--verbose` | `-v` | Enable verbose output | `false` |

## Environment Variables

| Variable | Maps To | Description |
|----------|---------|-------------|
| `MANTIS_AUTH_TOKEN` | `target.authToken` | Bearer token for target authentication |
| `MANTIS_TARGET_URL` | `target.url` | Target application URL |
| `MANTIS_RATE_LIMIT` | `scan.rateLimit` | Max requests per second |
| `MANTIS_TIMEOUT` | `scan.timeoutMs` | Request timeout in ms |
| `MANTIS_FORMAT` | `output.format` | Output format |
| `MANTIS_VERBOSE` | `output.verbose` | Verbose output (`true`/`false`) |

## Built-in Profiles

### `quick`

Fast scan with reduced coverage. Runs only key plugins with 1 reproducibility attempt.

### `aggressive`

Full coverage with deep testing. 5 reproducibility attempts, lower rate limit, higher timeout.

### `ci`

CI/CD optimized. SARIF output to file, no verbose logging, 2 reproducibility attempts.

**Usage:**

```bash
mantis scan --target https://app.com/api --profile ci
```
