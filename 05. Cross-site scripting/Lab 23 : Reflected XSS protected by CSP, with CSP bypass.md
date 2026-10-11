

# Lab Walkthrough: Reflected XSS protected by CSP, with CSP bypass

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS) / HTTP Header Injection (CSP Bypass)
* **Target Context:** Content Security Policy (`Report-URI` Directive Injection)
* **Skill Level:** Expert (Advanced)
* **Estimated Completion Time:** 15–20 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The methodologies, payloads, and technical documentation contained in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%231-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%232-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%233-step-by-step-exploitation-flow)
4. [Execution Insight: CSP Level 3 Overrides](https://www.google.com/search?q=%234-execution-insight-csp-level-3-overrides)
5. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%235-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%236-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%237-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

Content Security Policy (CSP) is a defense-in-depth mechanism transmitted via HTTP headers to mitigate XSS by restricting where scripts can be loaded from and preventing inline script execution.

* **The Core Flaw:** The application reflects a user-controlled parameter (`token`) directly into the `Content-Security-Policy` HTTP response header, specifically within the `report-uri` directive.
* **The Mechanism:** Because HTTP headers use semicolons (`;`) as delimiters to separate different directives, an attacker can inject a semicolon into the `token` parameter to break out of the `report-uri` directive and append entirely new, attacker-controlled CSP directives to the policy.
* **Real-World Analogy:** A building manager issues a strict security policy memo: "No visitors allowed; Report violations to: [Manager_Name]". If a malicious employee changes their name in the HR system to "Bob; Allow all visitors", the printed memo now reads: "No visitors allowed; Report violations to: Bob; Allow all visitors". The subsequent rule contradicts and overrides the first.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   CSP HEADER INJECTION & OVERRIDE FLOW                 │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Input] 
  search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'

  [2. Server Backend (Flawed Header Construction)]
  The server concatenates the `token` parameter directly into the header.
  
  [3. HTTP Response (Poisoned Headers)]
  Content-Security-Policy: default-src 'self'; report-uri /csp-report?token=;script-src-elem 'unsafe-inline'
  
  [4. Browser Parsing (CSP Level 3 Logic)]
  - Browser reads `default-src 'self'`. (Blocks inline scripts).
  - Browser reads `report-uri /csp-report?token=`.
  - Browser hits the `;`, terminating the report-uri directive.
  - Browser reads `script-src-elem 'unsafe-inline'`. 
  - Because `script-src-elem` is more specific than `default-src` (or `script-src`), 
    the browser applies it, enabling inline script execution and bypassing the earlier restriction.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `search` parameter (XSS vector) and the `token` parameter (CSP Injection vector).
* **Primary Objective:** Break out of the CSP `report-uri` directive, inject a less restrictive directive (`script-src-elem`) to allow inline scripting, and execute `alert(1)`.
* **Validation Signal:** The lab is marked solved when the browser receives the modified CSP header and executes the injected `<script>alert(1)</script>` payload.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Context Mapping & Defense Probing

* Inject a standard XSS payload: `/?search=<img src=1 onerror=alert(1)>`.
* *Observation:* The payload is reflected perfectly in the DOM, but the browser console throws a CSP violation error. The payload fails to execute because the policy forbids `unsafe-inline` scripts.
* Review the HTTP Response Headers in Burp Proxy.
* *Observation:* The `Content-Security-Policy` header contains a `report-uri` directive that includes a token: `report-uri /csp-report?token=12345`.
* Change the token in the URL: `&token=CyberTest`.
* *Observation:* The response header updates to `report-uri /csp-report?token=CyberTest`. This confirms HTTP header injection.

### Phase 2: Payload Construction

To execute our script, we must overwrite the policy blocking it.

* **The XSS Payload:** `<script>alert(1)</script>` (Injected into `search`).
* **The CSP Injection:** `;script-src-elem 'unsafe-inline'` (Injected into `token`).
* `;`: Terminates the previous directive.
* `script-src-elem`: A highly specific CSP Level 3 directive that dictates policy specifically for `<script>` tags, overriding broader `script-src` or `default-src` directives.
* `'unsafe-inline'`: Instructs the browser to execute inline scripts.



### Phase 3: Execution

* Combine and URL-encode the payload:
`/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27`
* *Result:* The browser receives the poisoned header, evaluates the more specific `script-src-elem` directive, downgrades the security posture of the page, and executes the alert.

---

## 4. Execution Insight: CSP Level 3 Overrides

Content Security Policy evaluation is hierarchical.

In older CSP versions (Level 1 and 2), `script-src` served as the primary fallback for all script execution. If multiple identical directives were defined (e.g., two `script-src` directives), the browser typically enforced the *strictest* intersection of the two, meaning an attacker couldn't simply append a weaker rule to bypass a stronger one.

CSP Level 3 introduced granular directives like `script-src-elem` (for `<script>` blocks) and `script-src-attr` (for inline event handlers like `onclick`).

The bypass works because **specificity overrides inheritance**. When the browser evaluates the policy, it sees a strict `default-src` (or `script-src`). However, when evaluating the `<script>` tag, it looks for the most specific applicable rule. Because the attacker injected `script-src-elem`, the browser uses that rule exclusively for the script tag, completely ignoring the stricter, broader directives defined earlier in the header.

---

## 5. Defense, Hardening & Secure Coding

CSP is a powerful mitigation tool, but it is rendered useless if the policy itself can be modified by user input.

* **Never Reflect Input in HTTP Headers (Primary Defense):** HTTP response headers must be strictly hardcoded or structurally validated on the backend. User-supplied parameters (like tracking tokens or session IDs) should never be concatenated into security headers.
* **Strict CSP Architecture (Nonces):** Transition away from whitelist-based CSPs and adopt a strict, nonce-based architecture.
* `Content-Security-Policy: script-src 'nonce-rAnd0m123' 'strict-dynamic';`
* With a nonce-based policy, even if an attacker successfully injects `'unsafe-inline'`, modern browsers supporting CSP Level 3 will ignore it in the presence of a nonce, ensuring the payload still fails to execute.


* **Context-Aware Output Encoding:** The underlying XSS vulnerability remains. The `search` parameter must be HTML-encoded (`&lt;script&gt;`) before reflection, neutralizing the threat regardless of CSP status.

---

## 6. SIEM Detection & Telemetry Analysis

Detecting CSP injection requires monitoring URL parameters for characters that represent structural HTTP header delimiters or CSP keywords.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i);\s*(script-src|default-src|script-src-elem|script-src-attr|object-src).*?('unsafe-inline'|'unsafe-eval'|'\*')"
| stats count by src_ip, uri_path, decoded_query
| where count > 0

```

*Indicator of Attack (IoA):* The presence of a semicolon (`;`) followed immediately by standard CSP directives (`script-src`) and relaxation keywords (`'unsafe-inline'`) within a GET request parameter is a definitive signature for an HTTP Header Injection attempt targeting security policies.

---

> **Key Insight:** Defense-in-depth fails when the secondary defense mechanism shares the same attack surface as the primary vulnerability. A WAF or a CSP is only effective if its configuration is entirely immutable from the perspective of the untrusted client.
