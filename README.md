# 🛡️ ChimeraGuard // Multi-Vector DevSecOps Platform & Defense Arsenal

<div align="center">

[![npm version](https://img.shields.io/npm/v/chimeraguard.svg?color=10b981&style=for-the-badge)](https://www.npmjs.com/package/chimeraguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Tests: 186 Passed](https://img.shields.io/badge/Tests-186%20Passed%20(100%25)-10b981.svg?style=for-the-badge)](https://github.com/matheus-oliv-dev/ChimeraGuard)
[![Security Tools: 18 Engines](https://img.shields.io/badge/Arsenal-18%20Engines%20in%201%20CLI-blueviolet.svg?style=for-the-badge)](https://github.com/matheus-oliv-dev/ChimeraGuard)
[![Quality Gate](https://img.shields.io/badge/CI%2FCD-Quality%20Gate%20Ready-black.svg?style=for-the-badge)](https://github.com/matheus-oliv-dev/ChimeraGuard)

**The All-In-One DevSecOps, Edge Defense, SAST & Reconnaissance CLI.**  
*Consolidating 18 specialized security engines into a single, zero-dependency `npm install`.*

> ⚡ **Evolution Notice:** Formerly known as **ObsidianSec**. All existing commands (`npx obsidiansec ...`) continue to work seamlessly for backward compatibility!

</div>

---

## ⚡ Quick Start (No Install Needed)

Run any of the 14 tactical commands instantly using `npx`:

```bash
# 🔍 1. Complete Edge Audit (Headers, Cookies, CORS & MITRE Attack Chain)
npx chimeraguard audit https://your-website.com

# 🎯 2. Cloudflare & Origin Bypass Finder (Detects Real IP leaks via SPF, MX & Subdomains)
npx chimeraguard origin https://your-website.com

# 🐘 3. PHP Critical Vulnerability & EOL Auditor (CVE-2024-4577, CVE-2024-8926, phpinfo, .user.ini)
npx chimeraguard php https://your-website.com

# 🚨 4. Server CVE & Sensitive Exposure Scanner (Apache, Nginx, OpenSSL CVEs, .git, .env, Actuator)
npx chimeraguard vulns https://your-website.com

# 🔒 5. SSL/TLS Certificate & Protocol Security (SSL Labs Engine)
npx chimeraguard ssl https://your-website.com

# 🧬 4. Technology Stack Fingerprinting (Wappalyzer Engine: React, Next.js, Nginx, CDNs)
npx chimeraguard tech https://your-website.com

# 📡 5. HTTP Method Enumeration (Detects dangerous TRACE/XST, PUT, DELETE)
npx chimeraguard methods https://your-website.com

# 🔀 6. Open Redirect Detector (OWASP CWE-601 Parameter Fuzzing)
npx chimeraguard redirects https://your-website.com

# 🛡️ 7. Web Application Firewall Detector (22+ WAFs: Cloudflare, AWS WAF, Fastly, Fortinet)
npx chimeraguard waf https://your-website.com

# 🚪 8. TCP Port Scanner (37 Critical Ports: Redis, Mongo, MSSQL, Oracle, K8s, SMB, VNC)
npx chimeraguard ports your-server-ip-or-domain

# 🔐 9. Secret Hunter & SAST Local (45+ Patterns: AWS, Stripe, Supabase, Slack, Discord, PGP)
npx chimeraguard scan-dir ./

# 🎟️ 10. JWT Token Security Auditor (Detects alg: none, expiration & decodes claims)
npx chimeraguard jwt <your-jwt-token>

# 🌐 11. Passive Subdomain Reconnaissance (Certificate Transparency Logs)
npx chimeraguard subdomains your-domain.com

# 📧 12. DNS & Email Anti-Phishing Suite (SPF, DMARC, DNSSEC)
npx chimeraguard dns your-domain.com

# 🔑 13. Shannon Password Entropy & GPU Cluster Crack Time (Hashcat Model)
npx chimeraguard entropy "YourPasswordHere"

# ⚙️ 14. Generate Scope & AI Budget Config Template
npx chimeraguard init-config
```

---

## 📋 Command Arsenal Matrix

| Command | Category | Engine / Reference | Key Capabilities |
|---|---|---|---|
| `audit <url>` | Edge Security | Mozilla Observatory / Burp | CSP, HSTS, X-Frame-Options, Cookie flags, CORS, MITRE ATT&CK Graph |
| `origin <url>` | Perimeter Defense | Shodan / DoH Recon | Uncovers real origin IP leaks bypassing Cloudflare/WAF; generates UFW patches |
| `php <url>` | Runtime CVE Audit | CVE-2024-4577 / PHP Foundation | Detects PHP-CGI Argument Injection (CVSS 9.8), EOL PHP branches, exposed `phpinfo` |
| `vulns <url>` | CVE & Exposure | NVD / OWASP Config | Scans Apache/Nginx/OpenSSL CVEs and exposed `.git`, `.env`, Actuator, `security.txt` |
| `ssl <url>` | Cryptography | SSL Labs | TLS 1.3/1.2 validation, SAN inspection, weak cipher/hash detection, expiry days |
| `tech <url>` | Reconnaissance | Wappalyzer / BuiltWith | Identifies React, Next.js, Vue, Angular, WordPress, Django, Nginx, Cloudflare |
| `methods <url>` | Protocol Audit | OWASP Testing Guide | Enumerates verbs; detects TRACE (XST vector), unauthenticated PUT/DELETE |
| `redirects <url>` | Web Vulnerability | OWASP CWE-601 | Probes 20+ redirect parameters against malicious external destinations |
| `waf <url>` | Edge Defense | WAFW00F Engine | Identifies 22+ WAF vendors (Cloudflare, AWS, Fastly, Fortinet, Imperva, Akamai) |
| `ports <host>` | Network SAST | Nmap / Shodan Model | Scans 37 critical ports (Databases, Remote Access, K8s, Legacy protocols) |
| `scan-dir [path]` | Code SAST | TruffleHog / Gitleaks Model | 45+ regex patterns for API keys, private keys, database strings, `.env` files |
| `jwt <token>` | Auth Audit | jwt_tool Model | Validates signature presence, `alg: none` bypass, expiration & claim decoding |
| `subdomains <dom>` | OSINT Recon | Subfinder / crt.sh | Passive subdomain enumeration via public Certificate Transparency logs |
| `dns <dom>` | Anti-Phishing | RFC 7208 / 7489 | Audits SPF hardfail mechanisms, DMARC reject policies, and DNSSEC |
| `entropy <pass>` | Cryptanalysis | Shannon Entropy / Hashcat | Bits of entropy, character set diversity & GPU brute-force crack time |
| `init-config` | Configuration | ChimeraGuard Core | Generates `chimeraguard.config.json` with authorized scope and AI budget limits |

---

## 🏛️ Architecture & Core Defenses

### 1. 🛡️ Authorized Scope Guard
Prevents accidental audits against forbidden domains (e.g. government, military, unowned infrastructure) with allowlist/blocklist glob patterns:
```json
{
  "scope": {
    "strictMode": false,
    "allowlist": ["localhost", "127.0.0.1", "*.yourcompany.com"],
    "blocklist": ["*.gov.br", "*.mil.br", "*.jus.br"]
  }
}
```

### 2. 🧠 Token Budget Guard & Zero-Token Default
- **100% Free & Local by Default**: Operates without requiring external AI APIs or cloud tokens.
- **SHA-256 Deduplication Cache**: Caches audit findings locally for 72 hours (`0 tokens, 0 network cost` on repeated runs).
- **Circuit Breaker**: Enforces a strict maximum requests-per-hour limit when LLM features are enabled.

### 3. 🕸️ BloodHound MITRE ATT&CK Mapping
Translates missing headers into an **actionable exploitation graph**, demonstrating how an attacker chains missing CSP or CORS into session hijacking (`T1539`) and account takeover (`T1078`).

---

## 🤖 CI/CD Quality Gate Example (GitHub Actions)

Fail pull requests automatically if security standards or perimeter requirements are violated:

```yaml
name: ChimeraGuard CI/CD Quality Gate

on: [push, pull_request]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Secret Hunter (SAST)
        run: npx chimeraguard scan-dir ./

      - name: Edge Security Audit (Quality Gate Grade >= A)
        run: npx chimeraguard audit https://staging.yourdomain.com --min-grade=A
```

---

## 🧪 Automated Testing

ChimeraGuard is thoroughly tested with **39 Vitest suites and 181 automated tests (100% GREEN)**:

```bash
# Run complete test suite
npm test

# Build production bundle
npm run build
```

---

## 📜 License & Compliance

MIT License © 2026 Matheus Oliveira & ChimeraGuard Contributors.  
Designed in compliance with **OWASP Top 10**, **NIST SP 800-207 (Zero Trust)**, and **CWE Standards**.
