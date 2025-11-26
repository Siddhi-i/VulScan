import urllib.parse as urlparse
import requests

from .crawler import crawl
from .payloads import XSS_PAYLOADS, SQLI_PAYLOADS
from .analyzer import detect_xss, detect_sqli, detect_csrf_risk
from . import db


def log_progress(message: str) -> None:
    """Simple helper to print scan progress in the terminal."""
    print(f"[SCAN PROGRESS] {message}")


def send_request(method: str, url: str, params=None, data=None):
    """Wrapper around requests.get/post with basic error handling."""
    try:
        if method.upper() == "GET":
            return requests.get(url, params=params, timeout=5)
        else:
            return requests.post(url, data=data, timeout=5)
    except Exception as e:
        log_progress(f"Request error for {url}: {e}")
        return None


def scan(target_url: str, scan_id: int) -> None:
    """Main scanning function: crawl, test forms & query params, store findings."""
    log_progress(f"Starting scan #{scan_id} for target: {target_url}")

    # Crawl the target
    pages, forms = crawl(target_url)
    log_progress(f"Crawling completed. Found {len(pages)} pages and {len(forms)} forms.")

    # 1. CSRF risks in forms
    log_progress("Checking forms for potential CSRF risks...")
    for form in forms:
        if detect_csrf_risk(form):
            db.add_finding(
                scan_id=scan_id,
                vuln_type="CSRF Risk",
                url=form.action,
                parameter="N/A",
                payload="N/A",
                severity="Medium",
                evidence="POST form with no anti-CSRF token parameter."
            )
            log_progress(f"CSRF risk logged for form action: {form.action}")

    # 2. Test forms for XSS / SQLi
    log_progress("Testing forms for XSS and SQL Injection...")
    for form in forms:
        for param in form.inputs:
            # ---- XSS tests ----
            for payload in XSS_PAYLOADS:
                data = {p: "test" for p in form.inputs}
                data[param] = payload

                log_progress(
                    f"[FORM XSS] {form.method} {form.action}  param={param}  payload={payload[:30]}..."
                )

                resp = send_request(
                    form.method,
                    form.action,
                    params=data if form.method.upper() == "GET" else None,
                    data=data if form.method.upper() == "POST" else None,
                )

                if resp and detect_xss(resp.text):
                    db.add_finding(
                        scan_id=scan_id,
                        vuln_type="Reflected XSS",
                        url=form.action,
                        parameter=param,
                        payload=payload,
                        severity="High",
                        evidence=f"Payload marker reflected in response for parameter '{param}'."
                    )
                    log_progress(f"Reflected XSS found at {form.action} (param: {param})")
                    break  # stop trying more XSS payloads for this param

            # ---- SQLi tests ----
            for payload in SQLI_PAYLOADS:
                data = {p: "test" for p in form.inputs}
                data[param] = payload

                log_progress(
                    f"[FORM SQLi] {form.method} {form.action}  param={param}  payload={payload[:30]}..."
                )

                resp = send_request(
                    form.method,
                    form.action,
                    params=data if form.method.upper() == "GET" else None,
                    data=data if form.method.upper() == "POST" else None,
                )

                if resp and detect_sqli(resp.text):
                    db.add_finding(
                        scan_id=scan_id,
                        vuln_type="SQL Injection",
                        url=form.action,
                        parameter=param,
                        payload=payload,
                        severity="Critical",
                        evidence="Database error pattern detected in response."
                    )
                    log_progress(f"SQL Injection found at {form.action} (param: {param})")
                    break  # stop trying more SQLi payloads for this param

    # 3. Test query parameters in URLs
    log_progress("Testing URL query parameters for XSS and SQL Injection...")
    for page in pages:
        parsed = urlparse.urlparse(page)
        qs = urlparse.parse_qs(parsed.query)
        if not qs:
            continue

        for param in qs:
            # ---- XSS on URL params ----
            for payload in XSS_PAYLOADS:
                new_qs = qs.copy()
                new_qs[param] = payload
                new_query = urlparse.urlencode(new_qs, doseq=True)
                new_url = urlparse.urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path,
                     parsed.params, new_query, parsed.fragment)
                )

                log_progress(
                    f"[URL XSS] GET {new_url}  param={param}  payload={payload[:30]}..."
                )

                resp = send_request("GET", new_url)
                if resp and detect_xss(resp.text):
                    db.add_finding(
                        scan_id=scan_id,
                        vuln_type="Reflected XSS",
                        url=new_url,
                        parameter=param,
                        payload=payload,
                        severity="High",
                        evidence="Payload marker reflected in URL parameter."
                    )
                    log_progress(f"Reflected XSS found at {new_url} (param: {param})")
                    break

            # ---- SQLi on URL params ----
            for payload in SQLI_PAYLOADS:
                new_qs = qs.copy()
                new_qs[param] = payload
                new_query = urlparse.urlencode(new_qs, doseq=True)
                new_url = urlparse.urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path,
                     parsed.params, new_query, parsed.fragment)
                )

                log_progress(
                    f"[URL SQLi] GET {new_url}  param={param}  payload={payload[:30]}..."
                )

                resp = send_request("GET", new_url)
                if resp and detect_sqli(resp.text):
                    db.add_finding(
                        scan_id=scan_id,
                        vuln_type="SQL Injection",
                        url=new_url,
                        parameter=param,
                        payload=payload,
                        severity="Critical",
                        evidence="Database error pattern detected in response."
                    )
                    log_progress(f"SQL Injection found at {new_url} (param: {param})")
                    break

    db.finish_scan(scan_id, status="completed")
    log_progress(f"Scan #{scan_id} for {target_url} completed.")
