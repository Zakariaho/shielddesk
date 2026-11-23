#!/usr/bin/env python3
"""Task 4.3 - weak vs secure login evidence for ShieldDesk.

Runs the SAME three authentication tests against any ShieldDesk build, so the
output can be captured for v0-vulnerable and again for v1-secure.

    python3 task4/login_tests.py http://127.0.0.1:5000 v0-vulnerable
    python3 task4/login_tests.py http://127.0.0.1:5000 v1-secure

Local, synthetic accounts only (student01 / Student@123 from the README).
Standard library only. Note: test 3 writes 25 LOGIN_FAILED lines to
logs/auth.log (useful later as input for the Task 5 monitoring rule).
"""
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000").rstrip("/")
LABEL = sys.argv[2] if len(sys.argv) > 2 else "build"

if urllib.parse.urlparse(BASE).hostname not in ("127.0.0.1", "localhost"):
    sys.exit("Refusing to test a non-local target (lab rule: local only).")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def session():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(CookieJar()), NoRedirect())


def post_login(op, user, pwd):
    data = urllib.parse.urlencode({"username": user, "password": pwd}).encode()
    try:
        r = op.open(f"{BASE}/login", data, timeout=10)
        status, body = r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read().decode(errors="replace")
    m = re.search(r'class="error">(.*?)</p>', body, re.S)
    return status, (m.group(1).strip() if m else "")


def has_session(op):
    """True if this cookie jar can open /requests (i.e. is logged in)."""
    try:
        return op.open(f"{BASE}/requests", timeout=10).status == 200
    except urllib.error.HTTPError:
        return False


print(f"=== ShieldDesk login tests | build: {LABEL} | target: {BASE} ===\n")

# Test 1 - SQL injection on the login form
print("Test 1: SQL injection in the username field")
payloads = ["' OR '1'='1' --", "admin' --"]
t1_bypass = False
for p in payloads:
    op = session()
    status, err = post_login(op, p, "x")
    ok = status == 302 and has_session(op)
    t1_bypass |= ok
    print(f"  payload {p!r:22} -> HTTP {status}, error={err!r}, "
          f"session granted={ok}")
print(f"  RESULT: {'VULNERABLE - authentication bypassed' if t1_bypass else 'payloads rejected, no session'}\n")

# Test 2 - account enumeration through the error message
print("Test 2: error message for a real vs a non-existent account")
_, e_real = post_login(session(), "student01", "WrongPassword!1")
_, e_fake = post_login(session(), "doesnotexist", "WrongPassword!1")
print(f"  real user, wrong password : {e_real!r}")
print(f"  unknown user              : {e_fake!r}")
print(f"  RESULT: {'identical - no enumeration' if e_real == e_fake else 'DIFFERENT - usernames can be enumerated'}\n")

# Test 3 - brute force / lockout
print("Test 3: 25 consecutive wrong passwords for student01, then the correct one")
codes = [post_login(session(), "student01", f"wrong{i}")[0] for i in range(25)]
blocked = [c for c in codes if c in (403, 429)]
op = session()
status, _ = post_login(op, "student01", "Student@123")
still_ok = status == 302 and has_session(op)
print(f"  status codes seen: {sorted(set(codes))} (blocked responses: {len(blocked)}/25)")
print(f"  correct password afterwards accepted: {still_ok}")
print(f"  RESULT: {'throttling/lockout active' if blocked or not still_ok else 'NO lockout - unlimited guessing allowed'}")
