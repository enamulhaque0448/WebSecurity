# Lab Walkthrough: Reflected XSS with AngularJS Sandbox Escape and CSP

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS) / CSP Evasion / Framework Execution
* **Target Context:** Content Security Policy (CSP) Bypass via AngularJS DOM Execution
* **Skill Level:** Expert (Advanced)
* **Estimated Completion Time:** 20–30 minutes
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
4. [Execution Insight: DOM Event Paths & Angular Filters](https://www.google.com/search?q=%234-execution-insight-dom-event-paths--angular-filters)
5. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%235-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%236-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%237-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

This lab demonstrates a highly advanced exploit chain where an attacker bypasses a strict Content Security Policy (CSP) by "living off the land" using the application's own trusted JavaScript framework (AngularJS).

* **The Core Flaw:** The application deploys a CSP that successfully blocks standard inline scripts (e.g., `<script>alert(1)</script>` will fail). However, the CSP permits the loading and execution of the AngularJS library.
* **The Mechanism:** AngularJS scans the DOM for its own custom attributes (like `ng-focus`) and executes the expressions contained within them. Because AngularJS is already trusted by the CSP, the browser allows it to evaluate these expressions. To achieve arbitrary code execution, the attacker uses Angular's event objects and filters to dynamically locate the global `window` object in memory and execute functions against it, completely sidestepping both the CSP's inline-script ban and Angular's internal sandbox.
* **Real-World Analogy:** A secure facility (CSP) forbids anyone from bringing in outside weapons (inline scripts). However, they allow authorized construction workers (AngularJS) to bring in power tools. An attacker sneaks in, grabs an authorized nail gun (the `orderBy` filter), and uses it maliciously. The security cameras (the browser) see an authorized tool being used and do not trigger an alarm.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   CSP BYPASS VIA FRAMEWORK EXECUTION                   │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Delivery]
  Redirects victim to target with payload:
  <input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x

  [2. Browser Enforcement (CSP)]
  - Standard <script> tags blocked.
  - URL fragment `#x` auto-focuses the injected `<input>` element.
  
  [3. Framework Execution (AngularJS)]
  - Focus triggers the `ng-focus` expression.
  - `$event.composedPath()` captures the DOM hierarchy up to `window`.
  - The `| orderBy` filter iterates over this hierarchy array.
  
  [4. The Sandbox Bypass]
  - As `orderBy` iterates, it executes `(z=alert)(document.cookie)` on each object.
  - When it reaches the `window` object, `alert` is a valid reference.
  - Execution succeeds. CSP is completely bypassed.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The search query parameter (`/?search=`).
* **Primary Objective:** Inject an AngularJS expression that bypasses the Content Security Policy, escapes the Angular sandbox, and executes `alert(document.cookie)` without user interaction.
* **Validation Signal:** The lab is marked solved when the simulated victim visits the exploit server, is redirected, and the XSS payload successfully executes in their browser context.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Context & CSP Mapping

* Inject a standard XSS payload: `<script>alert(1)</script>`.
* *Observation:* The browser console throws a CSP violation error. Inline scripts are blocked.
* *Observation:* The page source reveals that AngularJS is loaded and active (e.g., `ng-app` is present). This means Angular directives injected into the DOM will be parsed.

### Phase 2: Payload Construction (The Logic)

Because we cannot use `<script>`, we must inject an HTML element with an Angular event handler.

* **The Trigger:** `<input id=x ng-focus="...">` combined with the `#x` URL fragment guarantees zero-click execution when the page loads and the browser auto-focuses the input.
* **The Target (`window`):** Angular's sandbox prevents direct access to `window`. We use `$event.composedPath()` (or `$event.path` in older Chrome versions). When the focus event fires, this function returns an array of the DOM elements the event bubbled through: `[input#x, div, body, html, document, Window]`.
* **The Execution Sink:** `| orderBy:'(z=alert)(document.cookie)'`
* We pipe (`|`) the array of DOM elements into Angular's `orderBy` filter.
* The argument passed to `orderBy` is evaluated against every item in the array to determine how to sort them.
* We assign `alert` to a temporary variable `z` to bypass internal lexical checks, then immediately invoke it with `document.cookie`.



### Phase 3: Weaponization & Delivery

* **Exploit Server Script:**
```html
<script>
location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>

```


* *Result:* The victim is redirected, the input is focused, the array is generated, the filter iterates, and the alert fires upon hitting the `window` object, executing completely independent of CSP restrictions.

---

## 4. Execution Insight: DOM Event Paths & Angular Filters

The brilliance of this exploit lies in abusing the intended functionality of Angular's `$event` object and filtering pipeline.

Normally, CSP effectively mitigates Reflected XSS because an attacker cannot execute newly injected scripts. However, modern JavaScript frameworks parse the DOM *after* the browser does. AngularJS effectively acts as a secondary execution engine.

By injecting an `<input>` tag (which is perfectly valid HTML and permitted by CSP), the attacker provides data to this secondary engine. The `$event.composedPath()` trick is a pure "living off the land" technique—it uses standard browser APIs to map the environment, finds the highly restricted `window` object dynamically at runtime, and uses Angular's own array-sorting logic (`orderBy`) to force the execution of arbitrary functions against that global object.

---

## 5. Defense, Hardening & Secure Coding

Content Security Policy is not a silver bullet, especially when complex JavaScript frameworks are whitelisted.

* **Context-Aware Output Encoding (Primary Defense):** No matter how strong the CSP is, the backend application must strictly HTML-encode all user input before reflecting it into the DOM. Converting `<input>` to `&lt;input&gt;` renders the payload as plain text, preventing Angular from ever parsing the directives.
* **Framework Migration:** AngularJS (v1.x) is obsolete and structurally vulnerable to these types of expression injections. Migrate to modern Angular (v2+), which utilizes Ahead-of-Time (AOT) compilation and does not evaluate DOM attributes as executable expressions at runtime.
* **Strict CSP Architecture:** While CSP couldn't prevent this specific Angular bypass, a strong CSP (`strict-dynamic` with nonces) combined with disabling `unsafe-eval` significantly narrows the attacker's execution capabilities.

---

## 6. SIEM Detection & Telemetry Analysis

Detecting framework-based execution relies on identifying framework-specific syntax in inbound HTTP requests.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i)ng-(focus|click|mouseover|init)=.*?(\\\$event\.composedPath|\\\$event\.path|orderBy)"
| stats count by src_ip, uri_path, decoded_query
| where count > 0

```

*Indicator of Attack (IoA):* The presence of Angular-specific event handlers (`ng-focus`) combined with internal framework objects (`$event`) and array manipulation filters (`orderBy`) in URL parameters is a definitive signature for advanced Client-Side Template Injection (CSTI) and sandbox evasion attempts.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload renders but doesn't execute (No Auto-Focus)** | Missing Hash Fragment. | Ensure the `#x` is appended to the end of the URL. Without this, the browser will not automatically focus the injected input element, meaning `ng-focus` will not trigger without manual user interaction. |
| **Console Error: `$event.composedPath is not a function**` | Browser Compatibility / Angular Version. | Older exploits used `$event.path`, which was Chrome-specific. `$event.composedPath()` is the modern standard. Depending on the exact browser version simulating the victim, you may need to swap them. |
| **Console Error: CSP Violation for `eval**` | CSP strictness. | If the CSP explicitly blocks `unsafe-eval`, older versions of Angular's `$parse` service might fail structurally before the payload even reaches the `orderBy` filter. |

---

> **Key Insight:** A Content Security Policy only restricts the browser's native JavaScript engine. When you whitelist a JavaScript framework, you are effectively delegating trust to that framework's internal parser. If the framework's parser is flawed, your CSP provides zero protection against payloads crafted in the framework's proprietary language.
