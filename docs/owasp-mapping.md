# OWASP Top 10 for LLM Applications — Mantis Coverage

Mantis maps its 16 attack plugins to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/).

## Coverage Matrix

| # | OWASP Category | Mantis Coverage | Plugins |
|---|---------------|-----------------|---------|
| LLM01 | **Prompt Injection** | ✅ Full | `system-override`, `instruction-extraction`, `jailbreak`, `role-confusion` |
| LLM02 | **Sensitive Information Disclosure** | ✅ Full | `secret-retrieval`, `hidden-prompt`, `pii-extraction`, `memory-exfiltration` |
| LLM03 | Supply Chain Vulnerabilities | ⬜ N/A | Out of scope — supply chain is not a runtime attack vector |
| LLM04 | Data and Model Poisoning | ⬜ N/A | Out of scope — requires training pipeline access |
| LLM05 | Improper Output Handling | 🟡 Partial | Covered indirectly by prompt injection (XSS via LLM output) |
| LLM06 | **Excessive Agency** | ✅ Full | `command-injection`, `file-system-access`, `network-access`, `privilege-escalation` |
| LLM07 | System Prompt Leakage | ✅ Full | Covered by `hidden-prompt` and `instruction-extraction` |
| LLM08 | Vector and Embedding Weaknesses | ⬜ N/A | Out of scope — requires RAG pipeline access |
| LLM09 | **Misinformation** | ✅ Full | `fabricated-url`, `nonexistent-entity`, `citation-verification`, `confidence-mismatch` |
| LLM10 | Unbounded Consumption | ⬜ N/A | Out of scope — resource exhaustion is an infrastructure concern |

## Summary

| Status | Count | Description |
|--------|-------|-------------|
| ✅ Full | **5** | LLM01, LLM02, LLM06, LLM07, LLM09 — fully covered by dedicated plugins |
| 🟡 Partial | **1** | LLM05 — indirectly tested via prompt injection output patterns |
| ⬜ N/A | **4** | LLM03, LLM04, LLM08, LLM10 — out of scope for a black-box runtime scanner |

**Mantis covers 5 of the 6 OWASP LLM categories that are testable via black-box scanning.** The 4 categories marked N/A require access to training pipelines, supply chains, or infrastructure monitoring — they cannot be detected by sending prompts to an API endpoint.

## Plugin → OWASP Reference

Each plugin's `meta.owaspLLM` field contains its OWASP reference. This is included in SARIF output for compliance reporting:

```typescript
meta: {
    id: 'prompt-injection/jailbreak',
    owaspLLM: 'LLM01: Prompt Injection',
    // ...
}
```

## References

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP AI Security and Privacy Guide](https://owasp.org/www-project-ai-security-and-privacy-guide/)
