

# Lab Walkthrough: Stored XSS into onclick event (HTML-Entity Evasion)

* **Vulnerability Type:** Stored Cross-Site Scripting (XSS)
* **Target Context:** Client-Side JavaScript inside an HTML Attribute (`onclick` Event Handler)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 15–20 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The methodologies, payloads, and technical documentation contained in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal.

---

## Table of Contents

1. [Vulnerability Architecture & Mechanism](https://www.google.com/search?q=%231-vulnerability-architecture--mechanism)
2. [Lab Objectives & Verification Criteria](https://www.google.com/search?q=%232-lab-objectives--verification-criteria)
3. [Step-by-Step Exploitation Flow](https://www.google.com/search?q=%233-step-by-step-exploitation-flow)
4. [Execution Insight: Parser Precedence (HTML vs. JS)](https://www.google.com/search?q=%234-execution-insight-parser-precedence-html-vs-js)
5. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%235-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%236-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%237-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability highlights a critical failure in sanitization logic caused by a misunderstanding of how browsers parse layered execution contexts (JavaScript embedded inside HTML).

* **The Core Flaw:** The backend server successfully encodes HTML tags (`<`, `>`) and escapes literal single quotes (`'`) and backslashes (`\`) when storing the "Website" URL. However, the developer failed to account for the fact that the browser's HTML parser decodes HTML entities *before* handing the code over to the JavaScript engine.
* **The Mechanism:** The attacker injects the HTML entity for a single quote (`&apos;`). The backend server sees an ampersand, some letters, and a semicolon—not a literal single quote—so it does not escape it with a backslash. When the browser renders the `onclick` attribute, it decodes `&apos;` back into a literal `'`, which instantly breaks the JavaScript string boundary.
* **Real-World Analogy:** Imagine writing a secret message in invisible ink (the `&apos;` entity) and handing it to a censor (the backend server). The censor looks for bad words (literal quotes), sees nothing, and passes it along. Once the recipient (the browser) receives it, they apply heat to the paper (HTML decoding), revealing the malicious instructions right before executing them.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   HTML ENTITY DECODING BYPASS FLOW                     │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Input (Website Field)] 
  http://foo?&apos;-alert(1)-&apos;

  [2. Server Backend (Flawed Sanitization)]
  Rule: Escape literal ''' with '\'. HTML-encode '<' and '>'.
  Result: Input is left untouched because '&apos;' contains no literal quotes.
  
  [3. Rendered DOM]
  <a id="author" onclick="var tracker='http://foo?&apos;-alert(1)-&apos;';">

  [4. Browser Execution Order]
  - HTML Parser reads the `onclick` attribute.
  - HTML Parser decodes `&apos;` into `'`.
  - The attribute value becomes: var tracker='http://foo?'-alert(1)-'';
  - JS Engine receives the string, evaluates the mathematical subtraction (-), 
    and executes alert(1).

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The "Website" input field in the blog comment section.
* **Primary Objective:** Exploit the browser's parsing precedence to break out of a JavaScript string inside an `onclick` handler, bypassing the server's single-quote sanitization to execute `alert()`.
* **Validation Signal:** The lab is marked solved when a user clicks the injected author name and the `alert()` pop-up executes.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Context Mapping & Sanitization Probing

* Post a benign comment providing a random alphanumeric string in the "Website" field (e.g., `CyberTest`).
* View the rendered blog post. Intercept the request or inspect the page source.
* *Observation:* The website string is reflected inside an `onclick` event handler on the author's name: `<a id="author" href="#" onclick="var tracker='CyberTest'; ...">`
* **Test Sanitization:** Submit a second comment with a literal single quote: `test'payload`.
* *Observation:* The server escapes it: `var tracker='test\'payload';`. The string boundary is secure against literal quotes.

### Phase 2: Payload Construction (Entity Injection)

* Because the context is an HTML attribute (`onclick`), the HTML parser will process it before the JavaScript engine. We can use HTML entities to smuggle the quote past the server's sanitization routine.
* **The Injection:** `http://foo?&apos;-alert(1)-&apos;`
1. `http://foo?`: Satisfies basic URL validation if the backend checks for a protocol.
2. `&apos;`: The HTML entity for a single quote. (Smuggled past the server, decoded by the browser).
3. `-`: JavaScript arithmetic operator to separate the closed string from the function call.
4. `alert(1)`: The execution sink.
5. `-`: Another operator.
6. `&apos;`: Closes the remaining server-generated quote.



### Phase 3: Execution & Account Takeover

* Submit the comment using the constructed payload in the "Website" field.
* Navigate to the blog post.
* Click the author's name above your comment.
* *Result:* The browser decodes the entities, the JS string breaks, the syntax evaluates as subtraction, and the `alert(1)` payload executes.

---

## 4. Execution Insight: Parser Precedence (HTML vs. JS)

The core principle here is **Parser Precedence**. Browsers process documents in a specific order:

1. **HTML Parser:** Constructs the DOM tree, identifies attributes, and *decodes HTML entities* (`&quot;`, `&apos;`, `&#39;`).
2. **URL Parser:** Decodes `%20`, `%22` in `href` and `src` attributes.
3. **JavaScript Engine:** Executes the contents of `<script>` tags and event handlers (`onclick`, `onload`).

When a developer places JavaScript *inside* an HTML attribute, they create an overlapping execution context. The backend server treated the input purely as a JavaScript string (escaping it with backslashes). However, because the browser treats it as HTML *first*, it translates the harmless `&apos;` back into a weaponized `'` just milliseconds before handing it to the JavaScript engine.

---

## 5. Defense, Hardening & Secure Coding

To secure data that traverses multiple parsing contexts, developers must apply context-aware encoding in the correct order, or eliminate the overlapping contexts entirely.

* **Avoid Inline Event Handlers (Primary Defense):** The most effective way to eliminate this entire class of vulnerability is to stop writing JavaScript inside HTML attributes.
* *Vulnerable:* `<a onclick="doSomething('USER_INPUT')">`
* *Secure:* Use `data-*` attributes and attach event listeners in an external `.js` file:
```html
<a id="authorLink" data-website="USER_INPUT">Author</a>
<script>
  document.getElementById('authorLink').addEventListener('click', function() {
      let tracker = this.getAttribute('data-website');
      // Proceed securely...
  });
</script>

```




* **Context-Aware Encoding (If inline JS is unavoidable):** The backend must understand that the data will be parsed by HTML before JS. Therefore, it must be JavaScript-escaped *first* (using strict Unicode hex escaping like `\u0027` instead of backslashes), and then HTML-encoded *second*.

---

## 6. SIEM Detection & Telemetry Analysis

Detecting this attack requires monitoring for HTML entities being injected into fields that are logically supposed to hold URIs or plaintext.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined method=POST uri_path="/post/comment"
| eval decoded_body=urldecode(_raw)
| regex decoded_body="(?i)(&apos;|&#39;|&quot;|&#34;).*?(-|\+|\*|/|;).*?(alert|eval|prompt|confirm)"
| stats count by src_ip, uri_path, decoded_body
| where count > 0

```

*Indicator of Attack (IoA):* The presence of HTML entities (`&apos;`, `&#39;`) immediately adjacent to mathematical operators (`-`, `+`) in input fields is a strong signature for an attacker attempting to exploit parser precedence to achieve script breakout.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload renders exactly as `&apos;` in the DOM** | Not inside an HTML Attribute. | If the payload is reflected inside a `<script>` block rather than an `onclick` attribute, HTML decoding does *not* occur. You must use standard JS breakout techniques instead. |
| **Syntax Error in Console (alert doesn't fire)** | Missing operators. | Ensure you included the minus signs (`-alert(1)-`). If the browser evaluates `'http://foo?'alert(1)''`, it will throw a syntax error because there is no operator linking the string to the function. |
| **Server rejects the input** | URL Validation. | Some backends strictly validate that the "Website" field starts with `http://` or `https://`. Ensure your payload begins with a valid protocol scheme. |

---

> **Key Insight:** A sanitization routine is only secure if it anticipates the final execution environment. By embedding JavaScript within HTML attributes, developers subject the data to the rules of two different parsers. Attackers exploit this by speaking to the first parser (HTML) to disarm the defenses intended for the second (JavaScript).
