
# Lab Walkthrough: Reflected XSS into HTML Context (Custom Tags & Auto-Focus)

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS) / WAF Evasion
* **Target Context:** HTML Body (Strict Tag Blocklist Evasion)
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
4. [Execution Strategy: DOM Targeting & Auto-Focus](#4-execution-strategy-dom-targeting--auto-focus)
5. [Defense, Hardening & Secure Coding](#5-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](#6-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](#7-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability exposes a critical gap between how a Web Application Firewall (WAF) filters input and how a modern web browser parses HTML. 

* **The Core Flaw:** The WAF employs a strict blocklist, successfully dropping every standard HTML tag (`<script>`, `<img>`, `<body>`, `<svg>`, etc.). However, it fails to account for HTML5's forward-compatibility feature: **Custom Elements**. If you inject `<anything>`, the WAF permits it because it is not on the known-bad list, and the browser parses it as a valid `HTMLUnknownElement`.
* **The Mechanism:** While the browser doesn't know what an `<xss>` tag is supposed to *do*, it still applies global HTML attributes (like `id`, `class`, `tabindex`, and event handlers like `onfocus`) to it. Attackers leverage these standard global attributes on custom tags to execute JavaScript.
* **Real-World Analogy:** Imagine a border crossing that explicitly bans cars, trucks, and motorcycles. You build a bizarre, homemade vehicle they have never seen before (a custom tag). Because it's not on the banned list, the guards let it through. Once inside, you can still attach standard accessories—like a remote-detonated alarm (event handler)—because the fundamental laws of physics (the DOM) still apply to it.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The search query parameter (`/?search=`).
* **Primary Objective:** Evade the WAF by injecting a custom HTML tag, and orchestrate a zero-click payload that automatically alerts `document.cookie` when a victim visits the crafted URL.
* **Validation Signal:** The lab is solved when the victim simulates a visit to the exploit server and the `alert(document.cookie)` function executes automatically.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: WAF Evasion (Custom Tag Injection)
* Intercept the search request. If you attempt standard fuzzing, you will observe that *every* valid HTML5 tag returns an `HTTP 400 Bad Request`.
* Inject a completely fabricated tag: `<customxss>`. 
* *Result:* `HTTP 200 OK`. The WAF ignores tags it doesn't recognize. 

### Phase 2: Payload Construction
To execute JavaScript on a static, non-resource-loading tag (unlike `<img>`), you must rely on user interaction events (like clicking or focusing).
* **The Injection:** `<xss id=x onfocus=alert(document.cookie) tabindex=1>`
  * `<xss>`: The custom tag bypassing the filter.
  * `id=x`: Assigns a unique identifier to the element, making it a targetable anchor in the DOM.
  * `tabindex=1`: **Crucial.** By default, random HTML elements cannot receive browser focus. Adding `tabindex` makes the element focusable, enabling focus-related event handlers.
  * `onfocus=...`: The execution sink.

### Phase 3: Zero-Click Weaponization (The Hash Fragment)
* Waiting for a user to click a random invisible element is not a viable exploit. You must force the browser to focus the element automatically.
* **The Technique:** Appending `#x` to the end of the URL instructs the browser to automatically scroll to and focus on the element with `id="x"` the millisecond the DOM finishes rendering.

### Phase 4: Delivery
* **Exploit Server Script:**
  ```html
  <script>
  location = '[https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x](https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x)';
  </script>

```

* *Result:* The victim visits the exploit server, which instantly redirects them to the vulnerable search page. The browser parses the custom tag, reads the `#x` hash, forces focus onto the `<xss>` element, and triggers the alert seamlessly.

---

## 4. Execution Strategy: DOM Targeting & Auto-Focus

Modern browsers are designed for accessibility and deep-linking. Attackers weaponize these features to transform context-dependent payloads into zero-click exploits.

The URL fragment (the data following the `#` symbol) is never sent to the server; it is processed entirely client-side. When a browser sees `https://target.com/#login`, it scans the DOM for an element with `id="login"` and attempts to bring it into the user's viewport and focus it. By injecting an element with a specific `id` and simultaneously providing that `id` in the URL fragment, you manipulate the browser's native navigation mechanics into pulling the trigger on your payload.

---

## 5. Defense, Hardening & Secure Coding

* **Context-Aware Output Encoding:** This remains the ultimate defense. If the backend correctly HTML-encodes the input (`&lt;xss id=x...`), the browser renders it as plain text. The browser will not parse it as an element, meaning it cannot receive focus, rendering the hash fragment targeting useless.
* **Strict Allowlisting (WAF/Filter Level):** If application-layer filtering is absolutely required, it must utilize a strict allowlist of both tags *and* attributes. For example, explicitly permitting only `<b>`, `<i>`, and `<a>`, and dropping everything else, completely blocks custom tag injection.
* **Content Security Policy (CSP):** A strong CSP (`script-src 'self'`) prevents the execution of inline event handlers (like `onfocus`), neutralizing the payload even if the HTML is successfully injected.

---

## 6. SIEM Detection & Telemetry Analysis

Security Operations can detect this technique by correlating abnormal search inputs with client-side URL fragment usage (if captured by endpoint agents or advanced client-side telemetry).

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined uri_path="/"
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i)<[a-z0-9_-]+\s+.*?onfocus\s*=.*?tabindex"
| stats count by src_ip, decoded_query, status
| where count > 0

```

*Indicator of Attack (IoA):* The presence of non-standard HTML tags combined with global event handlers (`onfocus`, `onclick`, `onanimationstart`) and accessibility attributes (`tabindex`) is a highly specific signature for WAF evasion techniques.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Element injects, but alert doesn't fire** | Missing `tabindex`. | Custom elements (like `div` or `span`) cannot receive focus natively. You must explicitly define `tabindex=1` (or any integer) to make the browser recognize it as a focusable node. |
| **WAF blocks the custom tag** | Aggressive regex. | If a WAF blocks `<anyword>`, try injecting spaces or slashes to break the parser: `<xss/id=x...>` or `<xss%09id=x...>` (Tab character). |
| **Exploit server redirection fails** | Payload encoding. | Ensure the payload injected into the `location` assignment is properly URL-encoded. Bare quotes or spaces will break the JavaScript syntax on your exploit server before the redirect even happens. |

---

> **Key Insight:** The browser's HTML parser is designed to be endlessly forgiving and forward-compatible, which makes negative security models (blocklists) fundamentally inadequate. By injecting undefined elements, attackers step outside the WAF's known universe while remaining fully within the browser's executable execution context.

```

```
