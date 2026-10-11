
# Lab Walkthrough: Reflected XSS in a JavaScript URL (Advanced WAF Evasion)

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS) / WAF Evasion
* **Target Context:** `javascript:` URL Execution Context (String Breakout & Syntax Obfuscation)
* **Skill Level:** Expert (Advanced)
* **Estimated Completion Time:** 30–45 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]  
> The methodologies, payloads, and technical documentation contained in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](#1-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](#2-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](#3-step-by-step-exploitation-flow)
4. [Execution Insight: Type Coercion & Exception Handling](#4-execution-insight-type-coercion--exception-handling)
5. [Defense, Hardening & Secure Coding](#5-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](#6-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](#7-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

This lab explores a highly restricted XSS scenario where the execution context is a `javascript:` pseudo-protocol URL (often found in `href` attributes of `<a>` tags), and the Web Application Firewall (WAF) aggressively strips spaces and specific function calls.

* **The Core Flaw:** The application reflects user input directly into a `javascript:` URI without proper contextual escaping. While the WAF blocks standard XSS vectors (like `alert(1)` or spaces), it fails to account for the esoteric syntax capabilities of modern JavaScript, specifically ES6 arrow functions, implicit type coercion, and global error handling.
* **The Mechanism:** The attacker must achieve arbitrary code execution without using spaces or standard function invocation syntax (which might be blocked). To do this, they weaponize the `throw` statement to intentionally crash the script, but immediately catch that crash with a globally hijacked `onerror` handler mapped to `alert`. 
* **Real-World Analogy:** You are trapped in a room (the restricted WAF environment) where you are forbidden from speaking the word "Fire" (the `alert` function) or using the phone. Instead, you wire the building's fire alarm (the `onerror` handler) to the PA system, and then deliberately light a match (`throw 1337`) to set off the sprinklers, forcing the system itself to announce the emergency.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   JS URL SYNTAX EVASION & COERCION FLOW                │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Input (URL Parameter)] 
  '},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'

  [2. Server Backend (Sanitization Engine)]
  Strips standard XSS vectors, but allows complex punctuation and block comments.
           
  [3. Rendered DOM Context]
  <a href="javascript:someFunction({id:'5&'},x=x=>{...},toString=x,window+'',{x:''})">
  Back to blog</a>
           
  [4. Victim Interaction & Execution]
  - Victim clicks "Back to blog".
  - The `javascript:` URL is evaluated.
  - The payload assigns the arrow function to the `toString` property.
  - The `window+''` concatenation forces JavaScript to implicitly call `toString()`.
  - The malicious arrow function executes: overriding `onerror` and throwing `1337`.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The blog post redirection functionality (the "Back to blog" link).
* **Primary Objective:** Craft a JavaScript payload that breaks out of the existing object context, bypasses space/syntax restrictions, and leverages exception handling to trigger `alert(1337)`.
* **Validation Signal:** The lab is marked solved when the victim clicks the weaponized link and the alert executes with the exact integer `1337`.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Context Mapping

* When viewing a blog post, inspect the "Back to blog" link.
* *Observation:* It uses a JavaScript URI that dynamically includes the URL parameters: `<a href="javascript:fetch('/analytics?postId=5&[YOUR_INPUT]')">`.
* Attempting a standard breakout like `');alert(1)//` is blocked or neutralized by the WAF. Space characters (`%20`) are also heavily restricted.

### Phase 2: Payload Deconstruction (The Bypass)

Because standard execution is blocked, the payload must be assembled using advanced JavaScript operators.

* **The Injection Breakdown:** `'},x=x=>{throw/**/onerror=alert,1337},toString=x,window%2b'',{x:'`
1. `'},`: Breaks out of the application's native JSON/Object structure inside the `javascript:` URL.
2. `x=x=>{...}`: Defines an ES6 arrow function and assigns it to the variable `x`. This creates an executable block of code without using the `function` keyword.
3. `throw/**/onerror=alert,1337`: The core logic.
* `/**/` acts as an inline comment to bypass the space restriction (as `throwonerror` is invalid).
* The comma operator evaluates from left to right. First, it assigns the native `alert` function to the global `onerror` handler.
* Second, it throws the integer `1337` as an unhandled exception.


4. `,toString=x`: Overwrites the `toString` method in the current execution scope with our malicious arrow function.
5. `,window+''`: Adding an empty string to an object (`window`) forces JavaScript into **implicit type coercion**. It attempts to convert the object to a string by calling its `toString()` method. Because we just hijacked `toString`, this forces our arrow function to execute.
6. `,{x:'`: Repairs the trailing syntax of the original script to prevent a fatal SyntaxError before execution begins.



### Phase 3: Execution

* Inject the URL-encoded payload into the URL parameter.
* Scroll to the bottom of the page and click "Back to blog".
* *Result:* The type coercion triggers the arrow function, which overwrites the error handler and throws `1337`. The browser catches the throw, passes `1337` to the `onerror` handler (`alert`), and the pop-up fires.

---

## 4. Execution Insight: Type Coercion & Exception Handling

This exploit relies on two distinct JavaScript quirks to bypass the WAF:

1. **Implicit Type Coercion (`window+''`):** In JavaScript, attempting to add a string to an object forces the engine to resolve the object to a primitive value. It does this by implicitly invoking the object's `valueOf()` or `toString()` methods. By overwriting `toString` in the local scope, the attacker creates a trigger mechanism that does not require parentheses `()` for function invocation, completely bypassing WAF rules looking for `alert()`, `eval()`, or `x()`.
2. **The `throw` Statement as an Execution Sink:** Because `throw` is a statement (like `return` or `if`), it forces the JavaScript engine to halt current execution and bubble the thrown value up to the nearest error handler. By mapping the global `onerror` property to `alert`, the attacker turns the browser's native crash-reporting mechanism into a weaponized execution sink.

---

## 5. Defense, Hardening & Secure Coding

The primary vulnerability is not the WAF bypass; it is the architectural decision to use `javascript:` URIs.

* **Eliminate `javascript:` URIs (Primary Defense):** Modern web development should completely prohibit the use of `javascript:` pseudo-protocols in `href` attributes. They are inherently dangerous execution sinks.
* *Vulnerable:* `<a href="javascript:doSomething('USER_INPUT')">`
* *Secure:* Use standard HTTP links (`<a href="/blog">`), or use safe DOM event listeners (`<a id="backBtn">`) with logic handled in external scripts.


* **URL Encoding is insufficient for JS contexts:** If data must be placed inside a `javascript:` URL, standard URL encoding or HTML entity encoding will not protect it. The data must be strictly Unicode hex-escaped (`\u0027`) to prevent context breakout.
* **Content Security Policy (CSP):** A strong CSP without `unsafe-inline` will block the execution of `javascript:` URIs entirely, rendering this entire class of vulnerability inert regardless of how clever the WAF bypass is.

---

## 6. SIEM Detection & Telemetry Analysis

Detecting this attack requires monitoring for JavaScript syntax obfuscation techniques, specifically inline comments acting as space replacements and exception hijacking.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i)throw/\*\*/onerror|toString\s*=\s*\w+|window\s*\+\s*['\"]"
| stats count by src_ip, uri_path, decoded_query
| where count > 0

```

*Indicator of Attack (IoA):* The presence of `/**/` immediately following a JS statement keyword (`throw`, `return`, `var`), combined with DOM coercion patterns like `window+''` or overriding native methods like `toString=`, is a definitive signature for an expert-level WAF evasion attempt.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload reflected but clicking does nothing** | Syntax repair failure. | If the `,{x:'` at the end of the payload doesn't perfectly match the application's trailing syntax, a `SyntaxError` will fire before the script executes. Check the browser console and adjust the trailing braces/quotes to cleanly close the application's object literal. |
| **Console Error: `Uncaught 1337**` | Missing onerror mapping. | If `alert` doesn't fire, the WAF may have blocked the word `onerror` or the assignment failed. Ensure the comma operator was used correctly (`throw/**/onerror=alert,1337`). |
| **WAF blocks the plus sign (`+`)** | URL Decoding. | Ensure the `+` sign in `window+''` is properly URL encoded as `%2b`. A raw `+` in a URL parameter is interpreted as a space by backend web servers, breaking the coercion syntax into `window ''`. |

---

> **Key Insight:** WAFs that rely on blocking specific characters or function names are fundamentally outmatched by the extreme flexibility of JavaScript syntax. If an attacker can inject code, they don't need to call functions directly; they can manipulate the JavaScript engine's internal mechanics—like type coercion and error bubbling—to execute code on their behalf.

```

```
