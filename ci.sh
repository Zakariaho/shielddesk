#!/usr/bin/env bash
# ci.sh - ShieldDesk DevSecOps pipeline (CYS 401 project, Task 5)
#
# Gates (all run, then the build is failed if any gate failed):
#   1. Secret scan  - hardcoded credentials in the source
#   2. SAST         - Bandit static analysis of the Python code
#   3. SCA          - pip-audit: known-vulnerable dependencies
#   4. DAST         - OWASP ZAP scan of the running application
#
# Gate policy: High / Critical findings BLOCK the build.
#              Medium / Low findings are written to reports/ but do not block.
#
# Usage:  ./ci.sh                 run every gate
#         SKIP_DAST=1 ./ci.sh     skip the ZAP gate (quick local check only)
# Exit code 0 = release allowed, 1 = build blocked.

set -u
cd "$(dirname "$0")" || exit 1

PORT=5000
TARGET="http://127.0.0.1:${PORT}"
REPORTS="reports"
mkdir -p "$REPORTS" logs
FAIL=0
G1="-" G2="-" G3="-" G4="-"

stage() { echo; echo "[CI] ===== $1 ====="; }
pass()  { echo "[CI]   -> PASS: $1"; }
fail()  { echo "[CI]   -> FAIL: $1"; FAIL=1; }

echo "[CI] ShieldDesk pipeline started $(date '+%Y-%m-%d %H:%M:%S')"
echo "[CI] Commit under test: $(git rev-parse --short HEAD 2>/dev/null || echo n/a)" \
     "($(git describe --tags --always 2>/dev/null || echo untagged))"

# ---------------------------------------------------------------- Gate 1
stage "Gate 1: secret scan"
# Matches  NAME = "value"  where NAME contains key/secret/password/token,
# including names such as SECRET_KEY or INTERNAL_API_KEY, and the value is 8+ chars.
# Values starting with $ (environment variables / command output) are not secrets.
SECRET_RE="(api[_-]?key|secret|passw(or)?d|token)[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*['\"][^'\"\$][^'\"]{7,}['\"]"
grep -rnIiE "$SECRET_RE" \
     --exclude-dir=.git --exclude-dir=.venv --exclude-dir=venv --exclude-dir="$REPORTS" \
     --exclude=ci.sh . > "$REPORTS/secrets.txt"
SECRETS=$(wc -l < "$REPORTS/secrets.txt" | tr -d ' ')
if [ "$SECRETS" -gt 0 ]; then
    cat "$REPORTS/secrets.txt"
    fail "$SECRETS hardcoded secret(s) found"; G1="FAIL ($SECRETS)"
else
    pass "no hardcoded secrets"; G1="pass"
fi

# ---------------------------------------------------------------- Gate 2
stage "Gate 2: SAST (Bandit, blocks on High)"
bandit -q -r . -x ./.venv,./venv,./"$REPORTS" -f json -o "$REPORTS/bandit.json" 2>/dev/null
read -r HIGH MED LOW LOC <<EOF
$(python3 - "$REPORTS/bandit.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
sev = [r["issue_severity"] for r in d["results"]]
print(sev.count("HIGH"), sev.count("MEDIUM"), sev.count("LOW"), d["metrics"]["_totals"]["loc"])
PY
)
EOF
TOTAL=$((HIGH + MED + LOW))
DENSITY=$(python3 -c "print(round($TOTAL / ($LOC / 1000), 2) if $LOC else 0)")
echo "[CI]   findings: High=$HIGH Medium=$MED Low=$LOW (total $TOTAL), LOC=$LOC, defect density=$DENSITY per KLOC"
python3 - "$REPORTS/bandit.json" <<'PY'
import json, sys
for r in json.load(open(sys.argv[1]))["results"]:
    print(f"[CI]     {r['issue_severity']:<6} {r['test_id']} {r['filename']}:{r['line_number']} {r['issue_text'][:70]}")
PY
if [ "$HIGH" -gt 0 ]; then
    fail "$HIGH high-severity SAST finding(s)"; G2="FAIL (H$HIGH/M$MED/L$LOW)"
else
    pass "no high-severity findings"; G2="pass (H0/M$MED/L$LOW)"
fi

# ---------------------------------------------------------------- Gate 3
stage "Gate 3: dependency scan (pip-audit)"
if pip-audit -r requirements.txt > "$REPORTS/pip-audit.txt" 2>/dev/null; then
    pass "no known-vulnerable dependencies"; G3="pass"
else
    cat "$REPORTS/pip-audit.txt"
    fail "vulnerable dependency in requirements.txt"; G3="FAIL"
fi

# ---------------------------------------------------------------- Gate 4
stage "Gate 4: DAST (OWASP ZAP, blocks on High)"
if [ "${SKIP_DAST:-0}" = "1" ]; then
    echo "[CI]   -> SKIPPED (SKIP_DAST=1) - not valid for a release build"; G4="skipped"
else
    ZAP=$(command -v zaproxy || command -v zap.sh || true)
    if [ -z "$ZAP" ]; then
        fail "OWASP ZAP not installed (sudo apt install zaproxy)"; G4="FAIL (no ZAP)"
    else
        # free the port so ZAP never scans an old copy of the app
        fuser -k "${PORT}/tcp" >/dev/null 2>&1; sleep 1
        python3 seed.py > /dev/null
        python3 app.py > "$REPORTS/app.log" 2>&1 &
        APP_PID=$!
        for _ in $(seq 1 30); do curl -s "$TARGET/health" >/dev/null && break; sleep 1; done
        echo "[CI]   app started (pid $APP_PID), scanning $TARGET ..."
        rm -f "$REPORTS/zap.json"
        "$ZAP" -cmd -quickurl "$TARGET/search?q=test" \
               -quickout "$PWD/$REPORTS/zap.json" -quickprogress > "$REPORTS/zap.log" 2>&1
        kill "$APP_PID" 2>/dev/null; fuser -k "${PORT}/tcp" >/dev/null 2>&1
        if [ ! -s "$REPORTS/zap.json" ]; then
            fail "ZAP produced no report (see $REPORTS/zap.log)"; G4="FAIL (no report)"
        else
            read -r ZH ZM ZL ZI <<EOF
$(python3 - "$REPORTS/zap.json" <<'PY'
import json, sys
alerts = [a for s in json.load(open(sys.argv[1]))["site"] for a in s["alerts"]]
codes = [a["riskcode"] for a in alerts]
print(codes.count("3"), codes.count("2"), codes.count("1"), codes.count("0"))
for a in sorted(alerts, key=lambda a: -int(a["riskcode"])):
    print(f"[CI]     {a['riskdesc']:<28} {a['alert']}", file=sys.stderr)
PY
)
EOF
            echo "[CI]   alerts: High=$ZH Medium=$ZM Low=$ZL Informational=$ZI"
            if [ "$ZH" -gt 0 ]; then
                fail "$ZH high-risk DAST alert(s)"; G4="FAIL (H$ZH/M$ZM/L$ZL)"
            else
                pass "no high-risk alerts"; G4="pass (H0/M$ZM/L$ZL)"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------- verdict
echo
echo "[CI] ===== Summary ====="
printf "[CI]   %-22s %s\n" "Gate 1 secret scan" "$G1" "Gate 2 SAST" "$G2" \
       "Gate 3 dependencies" "$G3" "Gate 4 DAST" "$G4" | tee "$REPORTS/summary.txt"
if [ "$FAIL" -ne 0 ]; then
    echo "[CI] BUILD BLOCKED - fix the findings above (exit 1)"
    exit 1
fi
echo "[CI] ALL GATES PASSED - release allowed (exit 0)"
exit 0
