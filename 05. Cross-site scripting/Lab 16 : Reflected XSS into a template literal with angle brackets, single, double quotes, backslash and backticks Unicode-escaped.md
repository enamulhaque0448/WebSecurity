# Lab Walkthrough: Reflected XSS into a Template Literal

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS)
* **Target Context:** Client-Side JavaScript (Template Literal Interpolation)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 10–15 minutes
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
4. [Execution Insight: Template Interpolation vs. String Concatenation](https://www.google.com/search?q=%234-execution-insight-template-interpolation-vs-string-concatenation)
5. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%235-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%236-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%237-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

This lab demonstrates a context-specific XSS vulnerability where standard input sanitization completely fails because it targets the wrong threat model. The backend heavily sanitizes structural HTML and standard JavaScript string boundaries, but fails to account for modern ES6 syntax features.

* **The Core Flaw:** The application reflects user input inside a JavaScript **Template Literal** (strings enclosed by backticks ```). It successfully HTML-encodes angle brackets (`<`, `>`) and quotes (`"`, `'`), and it Unicode-escapes backslashes (`\`) and backticks. However, it fails to sanitize the JavaScript template interpolation sequence: `${}`.
* **The Mechanism:** Unlike standard strings, template literals evaluate JavaScript expressions embedded within `${}` *natively* before the final string is rendered. The attacker does not need to break out of the string boundary; they simply execute their payload from *inside* the string.
* **Real-World Analogy:** Imagine filling out an automated tax form. The backend secures the form so you can't alter the printed text. However, there is a designated "Formula Box" (`${}`) intended for automated math. If you write `[Erase Hard Drive]` inside that formula box, the machine blindly executes the instruction while attempting to calculate the final value to print on the form.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   TEMPLATE INTERPOLATION EXECUTION FLOW                │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Input] 
  ${alert(1)}
           │
           ▼
  [2. Server Backend (Sanitization Engine)]
  Rule: Encode < > " '. Escape ` \.
  Action: Input `${alert(1)}` contains none of the banned characters.
  Result: Input passes completely untouched.
           │
           ▼
  [3. Rendered DOM]
  <script>
      var message = `Search results for: ${alert(1)}`;
  </script>
           │
           ▼
  [4. JS Engine Evaluation]
  - Engine parses the backticks and recognizes a template literal.
  - Engine encounters the `${}` interpolation syntax.
  - Engine pauses string creation, evaluates the JavaScript inside `alert(1)`, 
    executes the pop-up, and returns 'undefined' to the string.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The search query functionality (`/?search=`).
* **Primary Objective:** Exploit the ES6 template literal interpolation feature to execute the `alert()` function without breaking the string boundary.
* **Validation Signal:** The lab is marked solved when the payload is processed and the browser triggers an `alert(1)` pop-up.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Context Mapping & Defense Probing

* Inject a distinct string into the search bar: `CyberTest`.
* Intercept the response in Burp Suite and inspect where the payload lands.
* *Observation:* The payload is reflected within backticks: `var searchMessage = `You searched for: CyberTest`;`
* **Probe Standard Breakouts:** Test `CyberTest`payload ` or `CyberTest\payload`.
* *Observation:* The server neutralizes string breakout attempts via Unicode escaping. For example, a backtick is escaped into its Unicode representation, keeping it structurally inert as a literal text character.

### Phase 2: Payload Construction (The Interpolation)

* Because the container is a template literal, breakout is unnecessary. The goal shifts to executing inline JavaScript.
* **The Injection:** `${alert(1)}`
1. `$`: The trigger character for ES6 string interpolation.
2. `{`: Opens the execution block.
3. `alert(1)`: The execution sink.
4. `}`: Closes the execution block.



### Phase 3: Execution

* Inject the payload into the search bar.
* *Result:* The backend renders `var searchMessage = `You searched for: ${alert(1)}`;`. The browser's JavaScript engine evaluates the expression, fires the alert, and assigns the final string as `"You searched for: undefined"`.

---

## 4. Execution Insight: Template Interpolation vs. String Concatenation

Prior to ES6 (ECMAScript 2015), developers concatenated dynamic variables into strings using quotes and plus signs (`'Search for: ' + userInput`). Securing this required escaping quotes so an attacker couldn't prematurely end the string.

Template literals (``Search for: ${userInput}``) fundamentally changed browser parsing. The `${}` construct instructs the JavaScript engine to temporarily suspend string parsing, switch context back to the primary JavaScript execution thread, evaluate the contained expression, and inject the result. Because of this architectural shift, sanitizing quotes or backticks is insufficient. The `{` and `}` characters, when preceded by `$`, become hard execution boundaries.

---

## 5. Defense, Hardening & Secure Coding

* **Avoid Direct Reflection into Template Literals:** Never reflect untrusted data directly into the raw source code of a template string.
* **Safe DOM APIs (Primary Defense):** The correct architecture is to pass data to the client-side via safe JSON serialization or standard HTML element properties, and let the frontend JavaScript retrieve it via the DOM.
* *Vulnerable:* `var msg = `Hello ${userInput}`;`
* *Secure:* `var msg = 'Hello ' + document.getElementById('userData').textContent;`


* **Interpolation Sanitization (If direct reflection is unavoidable):** The backend sanitization routine must be explicitly updated to handle template literal syntax. If input is going into backticks, the `$` and `{` characters must be escaped or stripped to break the interpolation sequence.

---

## 6. SIEM Detection & Telemetry Analysis

Security Operations can detect this exploit by monitoring HTTP requests for unencoded or URL-encoded ES6 interpolation syntax.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i)\\\$\\\{.*?(alert|eval|confirm|prompt|fetch|document|window)"
| stats count by src_ip, uri_path, decoded_query
| where count > 0

```

*Indicator of Attack (IoA):* The presence of `${` (or `%24%7B` in URL-encoded format) in a search parameter, specifically followed by known JavaScript execution sinks or global objects, is a definitive indicator of an attacker targeting template literal vulnerabilities.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload renders literally as `${alert(1)}` in the browser** | Wrong String Type. | Verify the reflection context. `${}` interpolation *only* works inside backticks (```). If the backend is using single (`'`) or double (`"`) quotes, this technique will not execute. |
| **Console Error: `Uncaught ReferenceError**` | Contextual limitation. | Ensure the payload is a valid JavaScript expression. Statements (like `if` or `for`) cannot be evaluated inside `${}` without being wrapped in an Immediately Invoked Function Expression (IIFE). |
| **WAF blocks the request** | `alert` signature matched. | Replace `alert(1)` with a less common execution function like `prompt(1)`, `console.log(1)`, or mathematical expressions `${1/0}` to bypass basic WAF signatures during testing. |

---

> **Key Insight:** Securing data requires understanding the exact capabilities of the container holding it. A backtick is not just a different type of quote; it is an active compilation boundary in modern JavaScript. When defenders focus exclusively on preventing string *breakout*, they leave the application vulnerable to execution from *within*.
