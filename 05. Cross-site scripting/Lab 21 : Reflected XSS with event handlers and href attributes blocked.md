# Lab Walkthrough: Reflected XSS with event handlers and href attributes blocked

* **Vulnerability Type:** Reflected Cross-Site Scripting (XSS) / WAF Evasion
* **Target Context:** SVG Namespace (Attribute Smuggling via SMIL Animation)
* **Skill Level:** Expert (Advanced)
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
4. [Execution Insight: Attribute Smuggling via SVG SMIL](https://www.google.com/search?q=%234-execution-insight-attribute-smuggling-via-svg-smil)
5. [Defense, Hardening & Secure Coding](https://www.google.com/search?q=%235-defense-hardening--secure-coding)
6. [SIEM Detection & Telemetry Analysis](https://www.google.com/search?q=%236-siem-detection--telemetry-analysis)
7. [Troubleshooting & Diagnostic Runbook](https://www.google.com/search?q=%237-troubleshooting--diagnostic-runbook)

---

## 1. Vulnerability Architecture & Mechanism

This vulnerability exposes a fundamental weakness in signature-based Web Application Firewalls (WAFs): they analyze static text, whereas modern browsers render dynamic, multi-namespace Document Object Models (DOMs).

* **The Core Flaw:** The application deploys a WAF that effectively neutralizes standard HTML-based XSS. It strips all event handlers (e.g., `onclick`, `onmouseover`) and strictly blocks the `href` attribute on `<a>` tags to prevent `javascript:` URI execution. However, it permits the `<svg>` tag and its associated child elements.
* **The Mechanism:** The attacker pivots from the HTML namespace into the SVG namespace. Within SVG, the SMIL (Synchronized Multimedia Integration Language) specification allows the `<animate>` tag to dynamically alter the attributes of its parent element. The attacker uses `<animate>` to programmatically inject the forbidden `href` attribute into the `<a>` tag *after* the WAF has already validated the payload.
* **Real-World Analogy:** A security inspector checks every vehicle for hidden contraband (the `href` attribute). They inspect a car (the `<a>` tag) and find nothing. They inspect a passenger's suitcase (the `<animate>` tag) and see harmless-looking components. Once past the checkpoint, the passenger opens the suitcase, assembles the components into contraband, and attaches it to the car.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   SVG ANIMATION ATTRIBUTE SMUGGLING                    │
└────────────────────────────────────────────────────────────────────────┘

  [1. Attacker Input] 
  <svg><a><animate attributeName=href values=javascript:alert(1) />...</a>

  [2. WAF Inspection (Static Text Analysis)]
  - Checks <a> tag for "href". None found.
  - Checks for "on*" event handlers. None found.
  - Payload marked as SAFE.

  [3. Browser Rendering (Dynamic DOM Construction)]
  - HTML Parser enters the SVG namespace.
  - Browser creates the SVG <a> element.
  - Browser processes the <animate> tag. It reads `attributeName=href` 
    and applies `values=javascript:alert(1)` directly to the parent <a> tag.
           
  [4. The Trap is Set]
  - The DOM now internally represents the element as:
    <a href="javascript:alert(1)">Click me</a>
  - Victim clicks the link. Payload executes.

```

---

## 2. Lab Objectives & Verification Criteria

* **Target Surface:** The search query parameter (`/?search=`).
* **Primary Objective:** Evade the WAF's `href` and event handler blocklist by dynamically constructing a malicious hyperlink using SVG animation tags, executing `alert()` when clicked.
* **Validation Signal:** The lab is marked solved when the simulated victim user clicks the injected "Click me" text and the payload executes successfully.

---

## 3. Step-by-Step Exploitation Flow

### Phase 1: Context & Filter Mapping

* Inject standard vectors to map the WAF rules:
* `<a href="javascript:alert(1)">X</a>` -> **Blocked** (href not allowed on a tags).
* `<img src=1 onerror=alert(1)>` -> **Blocked** (event handlers not allowed).
* `<svg><a>test</a></svg>` -> **Allowed** (SVG and anchor tags permitted).



### Phase 2: Payload Construction (The Bypass)

* Because direct `href` assignment is blocked, we must assign it indirectly. The SVG `<animate>` tag is designed precisely for this purpose.
* **The Injection:** `<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>`
1. `<svg>`: Switches the parser into the SVG namespace.
2. `<a>`: The SVG anchor element (which behaves similarly to an HTML anchor but allows SVG-specific child nodes).
3. `<animate>`: The SMIL animation element.
4. `attributeName=href`: Instructs the browser to target the `href` attribute of the immediate parent (`<a>`).
5. `values=javascript:alert(1)`: The value to animate to. In this context, it statically sets the `href` to our payload.
6. `<text ...>Click me</text>`: Renders the visible, clickable text. The lab explicitly requires the word "Click" to induce the simulated bot to interact with it.



### Phase 3: Delivery

* Inject the URL-encoded payload into the search parameter.
* *Result:* The backend reflects the payload exactly as written. The browser's SVG rendering engine processes the `<animate>` tag, mutating the `<a>` tag's properties in memory. When the simulated user clicks the text, the browser evaluates the `javascript:` URI and executes the alert.

---

## 4. Execution Insight: Attribute Smuggling via SVG SMIL

The `<animate>` tag is part of SMIL, a feature built into SVGs to allow declarative animations without requiring JavaScript.

From a security perspective, SMIL acts as a native DOM-mutation engine. When a WAF performs regular expression matching, it evaluates the HTTP stream sequentially. It looks at `<a>` and confirms it is safe. It looks at `<animate>` and, lacking a specific signature for it, deems it safe.

However, the browser understands the *relationship* between these tags. The `<animate>` tag is not a standalone element; its entire purpose is to mutate its parent. By leveraging this native browser behavior, attackers can "smuggle" forbidden attributes past static filters, forcing the browser itself to assemble the weaponized XSS vector dynamically at runtime.

---

## 5. Defense, Hardening & Secure Coding

Blacklisting attributes and tags is a failing security model. As browser specifications expand, new execution vectors (like SMIL animations) will continually bypass legacy static filters.

* **Context-Aware Output Encoding (Primary Defense):** The application must completely encode the input *before* reflection. Converting `<` to `&lt;` ensures the browser treats the entire payload as literal text, preventing the HTML parser from ever initializing the SVG namespace.
* **SVG Sanitization:** If the application requires user-submitted SVGs, it must use a robust, dedicated XML/SVG parser (like `DOMPurify`) to sterilize the input. The sanitization logic must explicitly strip `<animate>`, `<set>`, `<animatetransform>`, and `<script>` tags, as well as `on*` event attributes.
* **Content Security Policy (CSP):** While CSP cannot always prevent `javascript:` URIs on anchor tags (depending on the browser's exact handling of navigation), a strict CSP combined with `navigate-to` or `frame-src` directives can limit the impact of executing malicious URIs.

---

## 6. SIEM Detection & Telemetry Analysis

Detecting SVG SMIL smuggling requires monitoring for the intersection of animation tags and sensitive attribute names in HTTP queries.

### Splunk Search Query (SPL)

```spl
index=web_proxy sourcetype=access_combined 
| eval decoded_query=urldecode(uri_query)
| regex decoded_query="(?i)<animate\s+.*?attributeName\s*=\s*['\"]?(href|xlink:href|src|on\w+)['\"]?.*?values\s*=\s*['\"]?javascript:"
| stats count by src_ip, uri_path, decoded_query
| where count > 0

```

*Indicator of Attack (IoA):* The presence of the `<animate>` tag specifically targeting the `href` or `xlink:href` attributes, combined with a `javascript:` pseudo-protocol in the `values` attribute, is a definitive signature for an advanced WAF evasion attempt.

---

## 7. Troubleshooting & Diagnostic Runbook

| Symptom | Probable Cause | Corrective Action |
| --- | --- | --- |
| **Payload renders but is unclickable** | Missing `<text>` rendering properties. | Ensure the `<text>` element is properly nested inside the `<a>` tag and has coordinates (`x=20 y=20`) so it renders visibly within the SVG viewport. |
| **Simulated victim does not trigger the alert** | Missing trigger word. | The lab's bot relies on keyword matching to simulate human interaction. The visible text must contain the word "Click" (e.g., `<text>Click me</text>`). |
| **WAF blocks `attributeName=href**` | Namespace evasion. | In older SVGs, links used the XLink namespace. If `href` is blocked, try targeting `attributeName=xlink:href` instead. |
