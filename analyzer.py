import re

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"pg_query\(",
    r"sqlite error",
]

def detect_xss(response_text: str, marker: str = "xss123") -> bool:
    return marker in response_text

def detect_sqli(response_text: str) -> bool:
    lower = response_text.lower()
    return any(re.search(pat, lower) for pat in SQL_ERROR_PATTERNS)

def detect_csrf_risk(form_obj) -> bool:
    # simple heuristic: POST form on same site without any token-like field
    if form_obj.method != "POST":
        return False
    token_like = [name for name in form_obj.inputs if "csrf" in name.lower() or "token" in name.lower()]
    return len(token_like) == 0
