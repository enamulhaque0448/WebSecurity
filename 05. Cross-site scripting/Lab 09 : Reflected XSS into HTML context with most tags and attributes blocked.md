
# Lab Walkthrough: Reflected XSS via WAF Fuzzing

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS) / WAF Evasion
* **Target Context:** HTML Body (Blocklist Evasion)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 20–30 minutes
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
4. [Execution Strategy: Iframe-Driven Zero-Click](#4-execution-strategy-iframe-driven-zero-click)
5. [Defense, Hardening & Secure Coding](#5-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](#6-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](#7-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability exposes the architectural fragility of relying on Web Application Firewalls (WAFs) that use negative security models (blocklists) to sanitize input, rather than implementing secure output encoding at the application layer.

* **The Core Flaw:** The WAF intercepts inbound HTTP requests and compares parameters against a list of known malicious HTML tags (e.g., `<script>`, `<svg>`, `<img>`) and event handlers (e.g., `onerror`, `onload`). If the input is not on the list, it is allowed through and reflected by the backend.
* **The Bypass Mechanism:** Blocklists are infinite games of whack-a-mole. By systematically fuzzing the WAF with a dictionary of every valid HTML tag and event handler, an attacker identifies the "blind spots" the vendor failed to block. In this scenario, the WAF permits the `<body>` tag and the `onresize` event attribute.
* **Real-World Analogy:** A bouncer has a list of 50 known troublemakers to ban from a club. If troublemaker #51 walks up, the bouncer lets them in because they aren't explicitly on the list. A secure system uses an allowlist (a VIP list), ensuring only explicitly trusted entities are permitted entry.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The search query parameter (`/?search=`).
* **Primary Objective:** Systematically fuzz the WAF to discover unblocked tags/attributes, construct an XSS payload, and deliver it via an exploit server to execute a zero-click `print()` function in the victim's browser.
* **Validation Signal:** The lab is solved when the victim simulates a visit to the exploit server and the `print()` function executes automatically.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: WAF Mapping & Tag Discovery
* **Baseline Rejection:** Inject a standard payload like `<img src=1 onerror=print()>`. The WAF returns an `HTTP 400 Bad Request`.
* **Automated Tag Fuzzing:**
  1. Capture the search request and send it to **Burp Intruder**.
  2. Modify the search parameter to `<§§>`.
  3. Load an XSS cheat sheet containing all valid HTML tags into the payload configuration.
  4. Launch the attack.
* *Analysis:* Sort the results by HTTP status code. The `body` payload returns `HTTP 200 OK`. The WAF blindly allows `<body ...>`.

### Phase 2: Attribute Discovery
* **Automated Attribute Fuzzing:**
  1. Update the Intruder payload position to target attributes: `<body %20§§=1>`.
  2. Load a comprehensive list of JavaScript event handlers into the payload configuration.
  3. Launch the attack.
* *Analysis:* Sort the results. The `onresize` payload returns `HTTP 200 OK`.
* *Payload Discovered:* `<body onresize=print()>`

### Phase 3: Weaponization & Delivery
Because the WAF only permitted `onresize`, the payload lies dormant unless the user manually resizes their browser window. To convert this into a critical, zero-click exploit, you must force the window to resize programmatically.
* **Exploit Construction (The Iframe Wrapper):**
  ```html
  <iframe src="[https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E](https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E)" onload=this.style.width='100px'></iframe>

```

* **Delivery:** Store this HTML on the Exploit Server and deploy it. When the victim visits the page, the iframe loads, instantly resizes itself to 100 pixels, and triggers the `onresize` handler automatically.

---

## 4. Execution Strategy: Iframe-Driven Zero-Click

Converting a context-dependent XSS vector into a zero-click exploit is a hallmark of advanced payload development.

When a WAF severely restricts event handlers, attackers must build an external environment that mathematically guarantees the restricted event will occur. An `<iframe>` serves as this controlled environment. By hosting the vulnerable target application inside a frame you control, you can manipulate its dimensions (`onload=this.style.width='100px'`), its focus state (`autofocus`), or its hash fragment (`#id`), forcing the target application to evaluate your injected payload without the victim ever touching their mouse or keyboard.

---

## 5. Defense, Hardening & Secure Coding

* **Context-Aware Output Encoding:** The definitive fix. The backend application must encode the input before reflecting it into the HTML document. Characters like `<`, `>`, `"`, and `'` must be converted to their respective HTML entities (`&lt;`, `&gt;`, `&quot;`, `&#x27;`). This structurally neutralizes XSS, rendering WAF bypasses irrelevant.
* **Positive Security Model (Allowlisting):** If WAF filtering or input validation is required, enforce strict allowlists (e.g., matching the search input against `^[a-zA-Z0-9\s]+$`). Reject anything that does not match.
* **Content Security Policy (CSP):** Implement a strict CSP (`Content-Security-Policy: default-src 'self'; script-src 'self';`). Even if an attacker injects `<body onresize=print()>`, the browser will refuse to execute the inline event handler.

---

## 6. SIEM Detection & Telemetry Analysis

Security teams can detect WAF mapping and evasion attempts by tracking anomalous HTTP response distributions.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined uri_path="/"
| eval is_blocked=if(status==400 OR status==403, 1, 0)
| bin _time span=2m
| stats count as total_requests, sum(is_blocked) as blocked_requests by src_ip, _time
| eval block_ratio = round((blocked_requests / total_requests) * 100, 2)
| where total_requests > 40 AND block_ratio > 80

```

*Indicator of Attack (IoA):* An attacker systematically fuzzing a WAF will generate a rapid sequence of requests from a single IP, the vast majority of which will be blocked (`HTTP 400/403`). A high request volume coupled with a high block ratio strongly indicates automated boundary testing (like Burp Intruder).

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Intruder returns 400 for all tags** | Payload position formatting. | Ensure you are only fuzzing the word inside the brackets (`<§§>`), not injecting entire tags (`<tag>`). The WAF might also be blocking the brackets themselves if not properly URL encoded (`%3C§§%3E`). |
| **Iframe loads, but payload doesn't fire** | Race Condition. | The iframe's `onload` event might fire slightly before the inner page finishes loading its DOM. If `print()` fails to execute, try adding a slight delay using `setTimeout` in the parent frame to ensure the target DOM is fully loaded before resizing. |
| **Victim simulator does not solve the lab** | Exploit Server URL issue. | Ensure you replaced `YOUR-LAB-ID` with your current active lab session ID in the `src` attribute of the iframe before clicking "Deliver exploit to victim". |

---

> **Key Insight:** WAF blocklists operate under the false assumption that malice is finite and predictable. By systematically fuzzing the filtering mechanism, an attacker treats the WAF not as an impenetrable shield, but as a rigid logic puzzle, isolating exactly which inputs are permitted and weaponizing the remainder.

```

```
