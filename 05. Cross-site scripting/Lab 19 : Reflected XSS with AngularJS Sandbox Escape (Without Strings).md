

# Lab Walkthrough: Reflected XSS with AngularJS Sandbox Escape (Without Strings)

* **Vulnerability Type:** Client-Side Template Injection (CSTI) / AngularJS Sandbox Evasion
* **Target Context:** Client-Side JavaScript (AngularJS 1.x Scope and Lexer)
* **Skill Level:** Expert (Advanced)
* **Estimated Completion Time:** 30–45 minutes
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
4. [Execution Insight: Breaking the Lexer](https://www.google.com/search?q=%234-execution-insight-breaking-the-lexer)
5. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%235-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%236-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%237-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

This lab demonstrates one of the most complex client-side vulnerabilities: bypassing a JavaScript framework's internal security sandbox when severe syntax restrictions are in place.

* **The Core Flaw:** The application reflects user input into an AngularJS (v1.x) execution context. To prevent arbitrary code execution, AngularJS employs a "sandbox" that parses and restricts expressions (preventing access to `window`, `document`, `eval`, etc.).
* **The Constraints:** In this specific scenario, the `$eval` function is blocked, and the application strictly filters or encodes all string literals (single `'` and double `"` quotes).
* **The Mechanism:** To execute code, an attacker must accomplish two things without using strings:
1. **Blind the Sandbox:** Overwrite native JavaScript functions (like `String.prototype.charAt`) that the AngularJS internal parser (the Lexer) relies on to validate expressions.
2. **Generate the Payload dynamically:** Use mathematical or prototype-based string generation (like `fromCharCode`) to construct the malicious string `x=alert(1)` entirely from integers, bypassing the quote restriction, and pass it to a native Angular filter (like `orderBy`) that evaluates it.



---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The search query parameter (`/?search=`).
* **Primary Objective:** Break out of the AngularJS sandbox and execute the `alert()` function without using any quote characters (`'`, `"`) or the `$eval` function.
* **Validation Signal:** The lab is marked solved when the `alert(1)` pop-up executes in the browser.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Context Mapping & Constraint Identification

* Inject a standard AngularJS expression: `{{1+1}}`.
* *Observation:* The application evaluates it (yielding `2`), confirming CSTI.
* Inject a standard string payload: `{{'a'}}` or `{{$eval('alert(1)')}}`.
* *Observation:* The payload fails to execute or is blocked by backend filters (quotes are neutralized, `$eval` is undefined).

### Phase 2: Payload Construction (The Sandbox Breaker)

Since we cannot use strings, we must use prototype chaining to access native objects.

* **Step 1: Obtain the String Constructor.**
Normally, you'd use `"".constructor`. Without quotes, we use `toString().constructor`.
* **Step 2: Break the Lexer.**
AngularJS's sandbox uses `charAt()` to scan expressions character-by-character to identify restricted keywords. We can overwrite this globally:
`toString().constructor.prototype.charAt=[].join`
By replacing `charAt` with the Array `join` method, the sandbox's validation logic crashes or fails open, allowing restricted code to pass through.
* **Step 3: Generate the Payload String.**
We need the string `x=alert(1)`. We can generate this using ASCII character codes via `String.fromCharCode()`:
`toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)`
* **Step 4: Execute via a Filter.**
Since `$eval` is missing, we use a built-in Angular filter that executes expressions, such as `orderBy`:
`[1]|orderBy: [PAYLOAD_STRING]`

### Phase 3: Assembly & Execution

* Chain the components together using the URL parameter syntax (which Angular parses into the scope):
`?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1`
* *Result:* The URL is reflected. Angular evaluates the expression, overwrites `charAt`, generates `x=alert(1)`, and evaluates it via `orderBy`, triggering the alert.

---

## 4. Execution Insight: Breaking the Lexer

The most brilliant aspect of this exploit is the structural sabotage of the AngularJS parser itself.

AngularJS (in versions 1.2 to 1.5) operates by taking your expression and running it through a **Lexer** and a **Parser**. The Lexer's job is to read the string character by character (using `String.prototype.charAt`) to tokenize it and ensure you aren't trying to access forbidden properties like `__proto__` or the `window` object.

When the attacker executes `toString().constructor.prototype.charAt = [].join`, they are modifying the core JavaScript `String` object in the browser's memory. When the AngularJS Lexer subsequently calls `charAt()` to inspect the rest of the payload, it doesn't get a character back; it gets the result of an array `join` operation. This completely blinds the Lexer's security checks. The sandbox effectively disarms itself, allowing the dynamically generated `x=alert(1)` string to be evaluated as executable code by the `orderBy` filter.

---

## 5. Defense, Hardening & Secure Coding

Server-side sanitization is nearly impossible to implement correctly against this type of attack, as the payload contains no standard malicious characters (no `<script>`, no quotes, no explicit function calls).

* **Framework Upgrade (Primary Defense):** The AngularJS sandbox was historically so flawed that the Angular team officially removed it entirely in version 1.6, admitting it provided a false sense of security. The only true remediation is to **migrate away from AngularJS (v1.x)** to modern Angular (v2+), which uses Ahead-of-Time (AOT) compilation and strict contextual escaping to eliminate dynamic runtime template evaluation.
* **Use `ng-non-bindable`:** If legacy AngularJS must be used, any DOM node that reflects user-supplied input must be wrapped in the `ng-non-bindable` directive. This explicitly instructs AngularJS to ignore that section of the DOM, preventing it from parsing `{{ }}` or parameter-bound expressions.
* **Content Security Policy (CSP):** Implement a strict CSP without `'unsafe-eval'`. While Angular's `$parse` service doesn't strictly use the native `eval()`, modern CSP architectures can help mitigate the execution of dynamic payloads generated by prototype manipulation.

---

## 6. SIEM Detection & Telemetry Analysis

Detecting advanced CSTI sandbox escapes requires monitoring for JavaScript prototype manipulation keywords in HTTP requests.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i)(constructor\.prototype|fromCharCode|\[\]\.join|charAt\s*=)"
| stats count by src_ip, uri_path, decoded_query
| where count > 0

```

*Indicator of Attack (IoA):* The presence of JavaScript prototype chain manipulation (`constructor.prototype`), especially combined with ASCII generation functions (`fromCharCode`) or array manipulations (`[].join`) in a URL query string, is a definitive signature of an advanced framework sandbox escape attempt.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload renders as text but does not execute** | URL Encoding. | Ensure the `=` sign used in the prototype overwrite is properly URL-encoded as `%3d`. If passed as a literal `=`, the backend web server might parse it as a parameter delimiter before Angular ever sees it. |
| **Console Error: `charAt is not a function**` | Version Incompatibility. | Sandbox escapes are highly specific to the exact minor version of AngularJS running on the target (e.g., 1.4.0 vs 1.4.8). If this payload fails outside the lab, a different sandbox escape is required. |
| **`alert(1)` works, but `document.cookie` fails** | Character Code Array. | If attempting to exfiltrate data, you must translate your exact payload (e.g., `fetch(...)`) into ASCII character codes for the `fromCharCode()` function. A single incorrect integer will break the entire JavaScript syntax. |

---

> **Key Insight:** This vulnerability demonstrates the futility of client-side sandboxes built in JavaScript. Because JavaScript is a prototype-based, highly dynamic language, an attacker running code *inside* the sandbox often has the ability to redefine the very rules and native functions the sandbox relies on to enforce security.
