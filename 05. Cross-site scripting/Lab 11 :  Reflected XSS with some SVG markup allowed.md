
# Lab Walkthrough: Reflected XSS with some SVG markup allowed

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS) / WAF Evasion
* **Target Context:** HTML Body (SVG Sandbox Evasion)
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
4. [Execution Insight: The SVG DOM and Zero-Click Triggers](#4-execution-insight-the-svg-dom-and-zero-click-triggers)
5. [Defense, Hardening & Secure Coding](#5-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](#6-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](#7-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability exploits a common misconception in Web Application Firewall (WAF) rule design: treating SVG (Scalable Vector Graphics) purely as an image format rather than a fully-featured, scriptable XML document.

* **The Core Flaw:** The application deploys a blocklist that successfully strips standard HTML execution vectors (`<script>`, `<iframe>`, `<img>` with `onerror`). However, to support modern web design, the WAF permits `<svg>` tags. The developers failed to account for the fact that the SVG specification includes its own set of animation tags and event handlers capable of executing JavaScript.
* **The Mechanism:** By fuzzing the WAF, an attacker identifies that the `<animatetransform>` tag and the `onbegin` event handler are permitted. Because these are nested inside the valid `<svg>` context, the browser parses them according to the SVG namespace rules and executes the payload.
* **Real-World Analogy:** A security checkpoint explicitly bans firearms and knives (HTML XSS). However, they allow passengers to bring laptops (SVG images) because laptops are standard business tools. The security fails to realize that the laptop can be programmed to hack the terminal from the inside (SVG embedded JavaScript). The container is trusted, blinding the filter to the weapon inside.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The search query parameter (`/?search=`).
* **Primary Objective:** Systematically fuzz the WAF to isolate permitted SVG tags and event handlers, bypassing the blocklist to execute the `alert()` function.
* **Validation Signal:** The lab is solved when the application reflects the crafted payload and the `alert(1)` pop-up executes automatically in the browser.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: WAF Tag Reconnaissance
* **Baseline Rejection:** Inject a standard payload like `<img src=1 onerror=print()>`. The WAF returns an `HTTP 400 Bad Request`.
* **Automated Tag Fuzzing:**
  1. Capture the search request and send to **Burp Intruder**.
  2. Isolate the tag structure: `<§§>`.
  3. Load an XSS cheat sheet containing all HTML/SVG tags.
  4. Launch the attack.
* *Analysis:* Sort by HTTP status code. While HTML tags fail, `<svg>`, `<animatetransform>`, `<title>`, and `<image>` return `HTTP 200 OK`. The WAF permits SVG structures.

### Phase 2: Attribute & Event Handler Fuzzing
* **Automated Attribute Fuzzing:**
  1. Update the payload position to target the permitted animation tag: `<svg><animatetransform %20§§=1>`.
  2. Load a list of all JavaScript event handlers into Intruder.
  3. Launch the attack.
* *Analysis:* Sort by HTTP status code. The `onbegin` payload returns `HTTP 200 OK`.
* *Payload Discovered:* `<svg><animatetransform onbegin=alert(1)>`

### Phase 3: Weaponization & Delivery
* **Context Breakout:** To ensure the browser parses the payload correctly, you must break out of whatever HTML attribute the search term is currently reflected inside. Prepend `">` to close the existing attribute and tag.
* **Final Payload:** `"><svg><animatetransform onbegin=alert(1)>`
* **Execution:** Inject the URL-encoded payload into the search parameter.
  * `https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Csvg%3E%3Canimatetransform%20onbegin=alert(1)%3E`
* *Result:* The browser renders the SVG, initiates the animation timeline, triggers `onbegin`, and executes the alert.

---

## 4. Execution Insight: The SVG DOM and Zero-Click Triggers

SVG is not a flat image matrix (like a PNG or JPEG); it is a hierarchical Document Object Model (DOM) built on XML. Because it is a DOM, it supports dynamic interactivity and scripting.

The `<animatetransform>` element is used to animate a transformation attribute on a target element over time (e.g., rotating or scaling a shape). 

The critical bypass here relies on the `onbegin` event handler. 
* **Zero-Click Execution:** Unlike `onclick` (requires a user click) or `onmouseover` (requires mouse movement), `onbegin` fires the exact millisecond the SVG animation timeline starts. 
* Because animations typically start immediately when the SVG is rendered by the browser's rendering engine, `onbegin` acts effectively as an `onload` event strictly scoped to the SVG namespace, guaranteeing instantaneous, zero-click code execution without requiring complex `<iframe onload...>` wrappers.

---

## 5. Defense, Hardening & Secure Coding

* **Context-Aware Output Encoding (Primary Defense):** The application must encode the input (`<` to `&lt;`) before reflecting it into the HTML document. If the input is encoded, the browser treats `<svg>` as literal text, not as a DOM node, neutralizing the execution entirely.
* **SVG Sanitization (If Uploads/Inputs are Required):** If the application genuinely requires users to supply SVGs (e.g., uploading a profile avatar), you cannot rely on simple regex blocklists. The SVG must be parsed and sterilized using a robust, dedicated library (like `DOMPurify` for client-side or server-side equivalents) configured to strip *all* `<script>` tags, animation elements, and `on*` event attributes.
* **Content Security Policy (CSP):** A strict CSP (`script-src 'self'`) prevents the execution of inline event handlers (like `onbegin`), acting as a fail-safe even if the WAF is bypassed and the payload reaches the DOM.

---

## 6. SIEM Detection & Telemetry Analysis

Detecting SVG-based XSS requires monitoring for the intersection of graphic markup tags and JavaScript execution handlers.

### Splunk Search Query (SPL)
```spl
index=web_proxy sourcetype=access_combined uri_path="/"
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i)<svg.*?(<animate|<set|<animatetransform|<script).*?(onbegin|onload|onerror|onmouseover)="
| stats count by src_ip, decoded_query, status
| where count > 0

```

*Indicator of Attack (IoA):* Legitimate SVGs generated by design software rarely include inline JavaScript execution handlers (`onbegin=alert()`). The presence of execution sinks attached directly to SVG animation elements in HTTP query parameters is a high-confidence signature for WAF evasion.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload renders as plain text** | Incomplete context breakout. | Ensure you are injecting `">` at the start of the payload to break out of the `value=""` attribute of the search input field. Without it, the browser interprets the SVG as the literal string value of the input box. |
| **Intruder returns 400 for `onbegin**` | Spacing/Formatting issues. | WAFs often flag the space before an attribute. Try fuzzing with a slash instead of a space: `<svg><animatetransform/§§=1>`. |
| **Alert doesn't fire, but DOM shows the tag** | Browser compatibility or CSP. | Ensure you are testing in a modern browser. If testing against a hardened target outside this lab, check the browser console for CSP violation errors blocking inline script execution. |

---

> **Key Insight:** Web Application Firewalls frequently fail because they assess inputs based on the HTML context, ignoring the reality that browsers support multiple nested execution contexts (SVG, MathML, XML). By pivoting the payload into a secondary namespace like SVG, attackers bypass perimeter defenses by speaking a language the WAF doesn't fully understand, but the browser parses natively.
