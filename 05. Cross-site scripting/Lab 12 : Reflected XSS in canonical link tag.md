# Lab Walkthrough: Reflected XSS in Canonical Link Tag

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS)
* **Target Context:** HTML Tag Attribute Injection (Metadata / `<link>` tag)
* **Skill Level:** Practitioner (Intermediate)
* **Estimated Completion Time:** 15–20 minutes
* **Lab Status:** Solved

---

## Legal & Ethical Disclaimer

> [!WARNING]
> The methodologies, proof-of-concept (PoC) scripts, and techniques documented in this repository are strictly for educational purposes, CTF preparation, and authorized security assessments. Executing these tests against infrastructure without prior, explicit, written engagement contracts is illegal.

---

## 1. Vulnerability Architecture & Mechanism

Reflected XSS often occurs in unexpected areas of the DOM, such as metadata tags located within the `<head>` of an HTML document.

* **The Core Flaw:** The application dynamically generates a canonical link tag (used for SEO to specify the preferred URL of a page) by reflecting the current requested URL directly into the `href` attribute. While the backend sanitizes angle brackets (`<` and `>`), preventing the creation of new HTML tags, it fails to sanitize single quotes (`'`).
* **The Mechanism (Attribute Escape):** By injecting a single quote, an attacker breaks out of the `href` attribute boundary and appends entirely new attributes to the existing `<link>` tag.
* **The Execution Hurdle:** A `<link>` tag is invisible metadata; a user cannot physically click it or hover over it. To achieve execution, the attacker must bridge the gap between an invisible element and user interaction. This is achieved using the HTML `accesskey` attribute, which binds a global keyboard shortcut to a specific DOM element.
* **Real-World Analogy:** Imagine placing a rigged mousetrap in a room with no doors (the invisible `<link>` tag). Since no one can walk in to step on it, you wire the trap to the building's main light switch (the `accesskey`). When an unsuspecting user flips the switch from another room, the trap snaps.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   ATTRIBUTE INJECTION & ACCESSKEY ROUTING              │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Request] 
  /?'accesskey='x'onclick='alert(1)

  [2. Server Backend (Flawed Sanitization)]
  Reflects input. Fails to escape the single quotes.
  
  [3. DOM Rendering]
  <link rel="canonical" href="/?'accesskey='x'onclick='alert(1)'">
  
  [4. Browser Interpretation]
  The browser parses three distinct attributes:
  - href="/?"
  - accesskey="x"
  - onclick="alert(1)"
  
  [5. Zero-Visibility Execution]
  Victim presses ALT+SHIFT+X (Chrome Windows).
  Browser routes a synthetic "click" event to the mapped element.
  The hidden link tag executes the onclick handler.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The canonical URL reflection on the application's home page.
* **Primary Objective:** Bypass angle-bracket sanitization by injecting attributes into the `<link>` tag that execute JavaScript when a simulated user inputs a specific keyboard shortcut.
* **Validation Signal:** The lab is marked solved when the exploit is triggered in the browser via the simulated keyboard interaction, executing `alert()`.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Context Mapping & Sanitization Probing

* Navigate to the target home page and inject a test parameter: `/?test=CyberTest`.
* Inspect the page source.
* *Observation:* The input is reflected inside the canonical link tag: `<link rel="canonical" href="[https://YOUR-LAB-ID.web-security-academy.net/?test=CyberTest](https://YOUR-LAB-ID.web-security-academy.net/?test=CyberTest)">`
* Test dangerous characters: `/?test=<script>"'`
* *Observation:* `<` and `>` are encoded to `&lt;` and `&gt;`. The double quote (`"`) is unaffected because the attribute is encapsulated in single quotes (`href='...'`). The single quote (`'`) breaks the attribute boundary entirely.

### Phase 2: Attribute Injection

* Construct a payload to escape the `href` attribute and introduce a new event handler.
* *Draft Payload:* `/?'onload='alert(1)`
* *Rendered DOM:* `<link rel="canonical" href="/?'onload='alert(1)'">`
* *Failure Analysis:* While the injection succeeds structurally, standard event handlers like `onload` or `onerror` do not reliably fire on `<link rel="canonical">` tags in modern browsers, and standard interaction handlers (`onclick`, `onmouseover`) require physical visibility.

### Phase 3: The Accessibility Pivot

* Pivot to accessibility attributes to force interaction. The `accesskey` attribute allows an element to be activated (clicked/focused) via a keyboard shortcut.
* *Final Payload Construction:* `/?'accesskey='x'onclick='alert(1)`
* *Rendered DOM:* `<link rel="canonical" href="/?'accesskey='x'onclick='alert(1)'">`

### Phase 4: Execution

* Load the weaponized URL in the browser.
* Execute the OS-specific keyboard combination to trigger the `accesskey`:
* **Windows / Linux (Chrome):** `ALT + SHIFT + X`
* **macOS (Chrome):** `CTRL + ALT + X`


* *Result:* The browser translates the keyboard shortcut into a click event on the `<link>` tag, triggering the injected `onclick` handler and executing the XSS payload.

---

## 4. Defense, Hardening & Secure Coding

Mitigating attribute-based XSS requires context-aware output encoding.

* **Context-Aware Output Encoding (Primary Defense):** The application must recognize *where* the data is being reflected. Because the input is reflected inside an HTML attribute wrapped in single quotes, the backend must HTML-encode single quotes (`'` to `&#39;` or `&apos;`), double quotes, and angle brackets before rendering the DOM.
* **Avoid Dynamic Canonical URLs:** Canonical URLs should ideally be static and hardcoded for each page to serve their exact SEO purpose. Dynamically constructing them based on the user's current request parameters defeats the purpose of canonicalization and introduces unnecessary attack surfaces.

**Key Insight:** XSS is not strictly bound to visible elements or standard `<script>` execution. By leveraging browser accessibility features like `accesskey`, attackers can weaponize invisible metadata tags, transforming passive HTML structure into active exploit triggers.
