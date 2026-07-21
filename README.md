# Semgrep Custom Rule Pack

Custom Semgrep security rules built for a Go microservices, Java Spring, and
JavaScript codebase. Rules are based on **real findings** from production
SAST scans — not generic textbook examples.

> **Author:** Rahul Mohapatra — Application Security Engineer
> **github.com/RahulMohapatra1**

---

## What This Is

**25 custom Semgrep rules** across 4 files that go beyond what
`--config auto` provides:

| What cloud Semgrep gives you | What these custom rules give you |
|---|---|
| Generic message: "use Rewrite instead of Director" | Concrete explanation of why Director silently drops headers set on the request before it reaches the upstream |
| Generic: "AWS key detected" | Exact rotation steps + CloudTrail investigation instructions |
| Generic: "MD5 is weak" | Explains how an MD5 collision enables device-compliance bypass in a UEM context |
| Fixed severity, no context | Custom severity label in every message and metadata field |
| No fix guidance | Every rule includes the exact correct code pattern |
| No SSRF / missing-auth checks | Two rules covering exactly those gaps |

---

## Repo Structure

```
.
├── semgrep-rules/                ← rule YAMLs ONLY — nothing else goes here
│   ├── go-security.yml           ← 11 rules — Go microservices security
│   ├── secrets.yml               ← 5 rules — language-agnostic secrets detection
│   ├── java-spring.yml           ← 4 rules — Spring Boot / properties security
│   └── javascript-security.yml   ← 5 rules — JS/TS frontend security
├── .gitlab-ci.yml                ← CI/CD pipeline (Semgrep scan job)
└── README.md
```

> **Why this matters:** `--config ./semgrep-rules/` recursively loads every
> `.yml`/`.yaml` file in that folder as a rule config. If a CI file or other
> non-rule YAML ends up in there, Semgrep will try to parse it as a rule set
> and fail. Keep `semgrep-rules/` rule-files-only.

---

## Rules Summary

### go-security.yml — 11 rules

| Rule ID | Severity | What it catches |
|---|---|---|
| `custom-go-reverseproxy-director` | HIGH | ReverseProxy.Director dropping headers before they reach the upstream |
| `custom-go-weak-hash-md5` | HIGH | MD5 usage — enables device fingerprint collision attacks |
| `custom-go-weak-hash-sha1` | HIGH | SHA1 usage — broken since the SHAttered attack (2017) |
| `custom-go-error-modified-variable` | MEDIUM | Go error-handling anti-pattern causing nil pointer panics |
| `custom-go-jwt-parse-unverified` | CRITICAL | JWT parsed without signature verification |
| `custom-go-http-client-no-timeout` | MEDIUM | HTTP client with no timeout — goroutine leak / DoS risk |
| `custom-go-sql-injection` | CRITICAL | SQL query built with string concatenation |
| `custom-go-hardcoded-jwt-secret` | CRITICAL | JWT signing secret as a string literal |
| `custom-go-tls-insecure-skip-verify` | CRITICAL | `TLS InsecureSkipVerify: true` |
| `custom-go-ssrf-unvalidated-url` | HIGH | Request input used directly as an outbound URL (SSRF) |
| `custom-go-missing-auth-middleware` | MEDIUM | Route registered without an auth-middleware wrapper (heuristic, low confidence by design) |

### secrets.yml — 5 rules

| Rule ID | Severity | What it catches |
|---|---|---|
| `custom-secrets-aws-access-key-properties` | CRITICAL | AWS AKIA key in `.properties`/`.env` files, with rotation steps |
| `custom-secrets-aws-access-key-go` | CRITICAL | AWS AKIA key hardcoded in Go source files |
| `custom-secrets-generic-api-key-properties` | HIGH | Generic API keys in config files |
| `custom-secrets-jwt-secret-config` | CRITICAL | JWT signing secret in config files |
| `custom-secrets-private-key-pem` | CRITICAL | PEM private key blocks in any file |

### java-spring.yml — 4 rules

| Rule ID | Severity | What it catches |
|---|---|---|
| `custom-spring-actuator-fully-enabled` | CRITICAL | `management.endpoints.web.exposure.include=*` exposes `/env`, `/heapdump` |
| `custom-spring-security-disabled` | CRITICAL | `spring.security.enabled=false` |
| `custom-spring-db-password-hardcoded` | HIGH | Plaintext DB password in Spring datasource config |
| `custom-spring-http-internal-url` | MEDIUM | HTTP (not HTTPS) for internal service-to-service URLs |

### javascript-security.yml — 5 rules

| Rule ID | Severity | What it catches |
|---|---|---|
| `custom-js-prototype-pollution-loop` | HIGH | `for...in` loop without `hasOwnProperty` — prototype pollution |
| `custom-js-eval-injection` | CRITICAL | `eval()`, `new Function()`, or string-argument `setTimeout`/`setInterval` |
| `custom-js-jwt-in-localstorage` | HIGH | JWT/auth tokens stored in `localStorage` (XSS-readable) |
| `custom-js-document-write-xss` | HIGH | `innerHTML`/`document.write` with dynamic content — DOM XSS |
| `custom-js-numeric-role-hardcoded` | LOW | Magic-number role values instead of named constants |

---

## Installation

**1. Install Semgrep:**
```bash
pip install semgrep
```

**2. Clone this repo:**
```bash
git clone https://github.com/RahulMohapatra1/semgrep-rules.git
cd semgrep-rules
```

**3. Validate the rule pack loads correctly:**
```bash
semgrep scan --config ./semgrep-rules/ --validate
```

---

## Usage

```bash
# Custom rules only
semgrep scan --config ./semgrep-rules/ .

# Auto rules + custom rules (recommended)
semgrep scan --config auto --config ./semgrep-rules/ .

# One language / file only
semgrep scan --config ./semgrep-rules/go-security.yml .
semgrep scan --config ./semgrep-rules/secrets.yml .

# JSON output for reporting
semgrep scan --config ./semgrep-rules/ --json --output results.json .

# Block CI on findings (exit code 1 if any ERROR severity finding)
semgrep scan --config ./semgrep-rules/ --error .

# Scan a single file
semgrep scan --config ./semgrep-rules/go-security.yml services/UEMService.go

# Scan any external repo
semgrep scan --config ./semgrep-rules/ /path/to/any/other/repo
```

---

## CI/CD Integration

`.gitlab-ci.yml` at the repo root runs Semgrep with both the cloud auto
rules and this custom pack, and separates custom-rule findings into their
own `custom-findings.json` artifact with a summary (total / critical / high
/ medium counts) printed to the CI log.

```yaml
# The one line that matters:
semgrep scan --config auto --config ./semgrep-rules/ --json --output semgrep-results.json .
```

---

## Suppressing False Positives

```go
// nosemgrep: custom-go-weak-hash-md5
hash := md5.New()  // known false positive — non-security checksum only
```

```go
hash := md5.New()  // nosemgrep   (suppresses every rule on this line)
```

Structural exclusions (test files, vendored code, mocks) are handled per-rule
via `paths.exclude` in each rule's YAML.

---

## Design Notes

- **Severity labels in every message** — `[CRITICAL]`/`[HIGH]`/`[MEDIUM]`/`[LOW]`
  prefixes so severity is visible even in tools that don't surface metadata.
- **Confidence is honestly labeled** — rules built on naming-convention
  heuristics (like the missing-auth-middleware rule) are marked
  `confidence: LOW` and say so in the finding message, rather than
  overclaiming certainty.
- **Every rule includes exact fix code** — copy-paste ready, not just
  "don't do this."
- **Test/mock/vendor paths excluded** on every rule.
- **OWASP Top 10 (2021) + CWE mapping** on every rule for compliance reporting.

---

## References

- [Semgrep Rule Writing Guide](https://semgrep.dev/docs/writing-rules/overview/)
- [Semgrep Pattern Syntax](https://semgrep.dev/docs/writing-rules/pattern-syntax/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25 2022](https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25.html)

---

*For authorised security testing and internal use only.*
