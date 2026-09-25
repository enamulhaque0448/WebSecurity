# Lab Walkthrough: Blind SQL Injection with Time Delays

* **Vulnerability Type:** Blind SQL Injection (Time-Based / Inferential)
* **Target Context:** Data Exfiltration & Inference via Temporal Delays
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 10–15 minutes
* **Lab Status:**  Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The methodologies, payloads, and technical documentation contained in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%25231-vulnerability-architecture--mechanism&utm_source=gemini)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%25232-lab-objectives--verification-criteria&utm_source=gemini)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%25233-step-by-step-exploitation-flow&utm_source=gemini)
4. [Cross-Dialect Time Delay Comparison](https://www.google.com/search?q=%25234-cross-dialect-time-delay-comparison&utm_source=gemini)
5. [Defense & Prevention](https://www.google.com/search?q=%25235-defense--prevention&utm_source=gemini)
6. [Detection & SIEM Monitoring Rules](https://www.google.com/search?q=%25236-detection--siem-monitoring-rules&utm_source=gemini)
7. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25237-troubleshooting--diagnostic-runbook&utm_source=gemini)
8. [References & Standards](https://www.google.com/search?q=%25238-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

Time-Based Blind SQL Injection is the technique of last resort when an application is completely silent. The application does not reflect data (UNION), it does not change its UI based on True/False conditions (Boolean Blind), and it handles exceptions silently (Error-Based).

* **The Core Flaw:** The web server executes backend database queries *synchronously*. This means the HTTP response to the client is paused until the database finishes executing the SQL statement.
* **The Mechanism:** An attacker injects a database-specific command that explicitly instructs the SQL engine to sleep (pause) for a specified number of seconds. If the application takes exactly that long to respond, the attacker confirms the injection point is vulnerable.
* **Real-World Analogy:** Imagine knocking on a completely soundproof door where you cannot see or hear anyone inside. You slide a note under the door that says, *"If you are in there, wait exactly 10 seconds, then slide this note back."* If the note comes back 10 seconds later, you have established a covert communication channel based entirely on time.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   TIME-BASED INFERENCE EXECUTION FLOW                  │
└────────────────────────────────────────────────────────────────────────┘

  [Attacker Request] 
  Cookie: TrackingId=x'||pg_sleep(10)--

  [Database Evaluation]
  1. Engine parses the string concatenation (||).
  2. Encounters pg_sleep(10).
  3. Halts thread execution for exactly 10,000 milliseconds.
  
  [Web Server]
  Waits synchronously for the database query to return.

  [Attacker Client]
  Measures Time to First Byte (TTFB). 
  TTFB > 10s = Vulnerability Confirmed.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `TrackingId` HTTP Cookie.
* **Primary Objective:** Trigger a noticeable, conditional time delay within the application's response lifecycle to prove the existence of a SQL injection vulnerability.
* **Validation Signal:** The lab is marked solved when a payload successfully forces a 10-second delay in the HTTP response.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Payload Construction & Dialect Guessing

Because time-delay functions are highly specific to the underlying database engine, probing for time delays doubles as database fingerprinting.

* The application processes the `TrackingId` cookie. We must break out of the string encapsulation and append a sleep function.
* **PostgreSQL Payload:** `TrackingId=x'||pg_sleep(10)--`
* `x'` closes the legitimate string.
* `||` is the PostgreSQL string concatenation operator.
* `pg_sleep(10)` instructs the PostgreSQL engine to sleep.
* `--` comments out the remainder of the query to prevent syntax errors.



### Phase 2: Execution & Temporal Verification

* Intercept the HTTP request in Burp Suite containing the `TrackingId` cookie.
* Send the request to **Burp Repeater**.
* Replace the cookie value with the PostgreSQL payload.
* Click **Send** and monitor the response timer in the bottom-right corner of the Repeater interface.
* *Observation:* The application takes approximately ~10.05 seconds to respond.
* *Conclusion:* The backend is confirmed to be PostgreSQL, and it is vulnerable to Time-Based Blind SQLi.

---

## 4. Cross-Dialect Time Delay Comparison

Time-based functions are not standardized across SQL dialects. Penetration testers iterate through these specific payloads to fingerprint the backend engine when traditional errors are suppressed.

| Database Engine | Sleep Command | Example Injection Payload |
| --- | --- | --- |
| **PostgreSQL** | `pg_sleep(seconds)` | `'; SELECT pg_sleep(10)--` or `'||pg_sleep(10)--` |
| **MySQL / MariaDB** | `SLEEP(seconds)` | `' OR SLEEP(10)--` |
| **Microsoft SQL Server** | `WAITFOR DELAY 'time'` | `'; WAITFOR DELAY '0:0:10'--` |
| **Oracle** | `dbms_pipe.receive_message()` | `'||dbms_pipe.receive_message(('a'),10)--` |
| **SQLite** | `randomblob(N)` (Heavy compute) | `CASE WHEN (1=1) THEN randomblob(1000000000) ELSE 0 END` |

*Note: Oracle requires heavy PL/SQL execution privileges to use `DBMS_LOCK.SLEEP()`, making `dbms_pipe.receive_message` the preferred, unprivileged timing vector.*

---

## 5. Defense & Prevention

* **Parameterized Queries (Primary Defense):** As with all SQLi variants, using prepared statements ensures the database driver treats the payload (`pg_sleep(10)`) strictly as a literal string value to search for, rather than an executable function.
* **Asynchronous Analytics:** Tracking cookies and telemetry data should ideally be processed asynchronously (e.g., dropped into a message queue like Kafka or RabbitMQ) rather than blocking the main HTTP response thread. While this doesn't fix the SQLi, it eliminates the synchronous temporal side-channel.
* **Strict Timeouts:** Implement strict database query execution timeouts (e.g., `statement_timeout` in PostgreSQL). If a query takes longer than 2 seconds, the connection should be killed. This frustrates time-based extraction.

---

## 6. Detection & SIEM Monitoring Rules

Time-based attacks generate highly specific function calls in the web logs and cause measurable latency spikes in Application Performance Monitoring (APM) tools.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_cookie=urldecode(cookie)
| search decoded_cookie="*pg_sleep*" OR decoded_cookie="*WAITFOR DELAY*" OR decoded_cookie="*SLEEP(*"
| stats max(response_time) as max_latency, count by src_ip, uri_path
| where max_latency > 5000 AND count > 0

```

*Indicator of Attack (IoA):* Correlating standard SQL timing commands in HTTP parameters with a sudden spike in backend response times (> 5,000ms) is a definitive indicator of a time-based blind SQLi probe.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload executes instantly (no delay)** | Incorrect DB Dialect or Syntax. | The backend is likely not PostgreSQL. Iterate through MySQL (`SLEEP()`), MSSQL (`WAITFOR DELAY`), and Oracle timing payloads. |
| **Response takes 30+ seconds instead of 10** | Iterative Sleep Execution. | If the vulnerable parameter is inside a `WHERE` clause that evaluates multiple rows, the sleep function executes *per row*. Use conditional logic (`CASE WHEN`) to ensure the sleep only triggers once. |
| **Intermittent latency during testing** | Network jitter. | Always test a baseline request first. If normal requests take 2 seconds, set your `pg_sleep()` to at least 10 seconds to ensure the delay is distinctly artificial and not normal network lag. |

---

## 8. References & Standards

* [PortSwigger: Blind SQL Injection](https://www.google.com/search?q=https://portswigger.net/web-security/sql-injection/blind&utm_source=gemini)
* [OWASP: Blind SQL Injection](https://www.google.com/search?q=https://owasp.org/www-community/attacks/Blind_SQL_Injection&utm_source=gemini)
* [MITRE ATT&CK: T1190 - Exploit Public-Facing Application](https://www.google.com/search?q=https://attack.mitre.org/techniques/T1190/&utm_source=gemini)

---

> **Key Insight:** Time-Based Blind SQLi forces the attacker to rely on network latency as their only data channel. While it is the slowest and most fragile form of SQL injection (highly susceptible to network jitter and row-evaluation multiplication), it is virtually impossible for an application to hide if it executes queries synchronously.
