# ai-redteam

Automated red-teaming toolkit for LLM applications. Tests for prompt injection vulnerabilities, jailbreak susceptibility, output safety issues, and data leakage.

## Features

- **Prompt Injection Testing** — Direct injection, indirect injection, and context manipulation attacks
- **Jailbreak Testing** — Role-play, encoding tricks, and multi-turn escalation attempts
- **Data Leakage Testing** — System prompt extraction and training data extraction
- **Toxicity Testing** — Toxic output elicitation and bias probing
- **50+ Built-in Payloads** — Diverse attack strings covering all categories
- **Pattern-Based Scoring** — No LLM needed for evaluation; uses regex heuristics
- **CLI + Python API** — Use from the command line or integrate into your test suite
- **JSON Reports** — Export detailed findings with severity ratings

## Installation

```bash
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## CLI Usage

```bash
# Run all attack suites against an HTTP endpoint
ai-redteam scan --target http://localhost:8000/chat --suite all

# Run specific suites with verbose output
ai-redteam scan --target http://localhost:8000/chat --suite injection,jailbreak --verbose

# Export results to JSON
ai-redteam scan --target http://localhost:8000/chat --suite all --output report.json

# Custom request/response field names
ai-redteam scan --target http://localhost:8000/api \
  --request-field "message" \
  --response-field "reply" \
  --suite all

# Add custom headers
ai-redteam scan --target http://localhost:8000/chat \
  -H "Authorization: Bearer TOKEN" \
  --suite all

# List available suites
ai-redteam list-suites

# Show toolkit info
ai-redteam info
```

## Python API

```python
from ai_redteam.scanner import scan_url, scan_callable, MockTarget

# Scan an HTTP endpoint
report = scan_url("http://localhost:8000/chat", suites=["injection", "jailbreak"])

# Scan a callable (function or class with __call__)
mock = MockTarget()
report = scan_callable(mock, suites=["all"])

# Inspect results
print(f"Total attacks: {report.total_attacks}")
print(f"Successful: {report.successful_attacks}")
print(f"Success rate: {report.success_rate:.1%}")

for result in report.results:
    if result.success:
        print(f"  [{result.severity.value}] {result.attack_name}: {result.details}")
```

### Using the Reporter

```python
from ai_redteam.reporter import Reporter

reporter = Reporter(verbose=True)
reporter.print_report(report)             # Console output
reporter.export_json(report, "report.json")  # JSON file
```

## Testing

```bash
pytest
pytest --cov=ai_redteam
```

## Attack Suites

| Suite | Description | Payload Count |
|-------|-------------|---------------|
| `injection` | Prompt injection (direct, indirect, context manipulation) | 22 |
| `jailbreak` | Jailbreak attempts (role-play, encoding, multi-turn) | 16 |
| `leakage` | System prompt & training data extraction | 16 |
| `toxicity` | Toxic output elicitation & bias testing | 11 |

## Severity Levels

- **CRITICAL** — Attack clearly succeeded with high-confidence indicators (e.g., system prompt leaked, jailbreak confirmed)
- **HIGH** — Strong evidence of vulnerability (e.g., model did not refuse jailbreak)
- **MEDIUM** — Moderate concern (e.g., model did not refuse injection but no clear compliance)
- **LOW** — Minor concern (e.g., no refusal but no clear leakage pattern)
- **INFO** — Informational only
- **NONE** — Attack was properly blocked

## License

MIT
