#!/usr/bin/env bash
# task5/demo.sh - guided Task 5 demo with on-screen captions, for the screen recording.
# Run from anywhere:  bash task5/demo.sh
# Press Enter to move to the next scene.

cd "$(dirname "$0")/.." || exit 1
FILES="app.py config.py seed.py requirements.txt templates/"

say()  { printf "\n\033[1;33m### %s\033[0m\n" "$*"; }      # yellow caption
note() { printf "\033[0;36m    %s\033[0m\n" "$*"; }          # cyan explanation
run()  { printf "\033[1;32m$ %s\033[0m\n" "$*"; eval "$@"; } # show + run a command
next() { printf "\n\033[2m[press Enter for the next scene]\033[0m"; read -r _; clear; }

clear
# ---------------------------------------------------------------- 0
say "ShieldDesk - Task 5: DevSecOps pipeline demo"
note "ci.sh runs 4 security gates before every commit:"
note "  1 secret scan   2 SAST (Bandit)   3 dependency scan (pip-audit)   4 DAST (OWASP ZAP)"
note "Policy: any High/Critical finding blocks the release (exit 1). Medium/Low are reported only."
run "ls"
next

# ---------------------------------------------------------------- 1
say "SCENE 1/7 - Original insecure version (v0-vulnerable)"
note "Expected: every gate fails and the build is blocked."
run "git checkout -q v0-vulnerable -- $FILES"
run "./ci.sh"
say "RESULT: 4 hardcoded secrets, Bandit 2 High, vulnerable Flask 3.0.3,"
say "        ZAP 3 High (Reflected XSS, DOM XSS, SQL Injection)  ->  BUILD BLOCKED"
next

# ---------------------------------------------------------------- 2
say "SCENE 2/7 - Try to commit the insecure version"
note "ci.sh is installed as the Git pre-commit hook, so the commit runs the pipeline first."
note "(DAST is skipped here only to save time - the full ZAP run was shown in scene 1.)"
run "SKIP_DAST=1 git commit -qam 'release v0'"
run "git log --oneline -1"
say "RESULT: commit refused - the insecure code never entered the repository"
next

# ---------------------------------------------------------------- 3
say "SCENE 3/7 - Task 3 secure build (v1-secure)"
note "The code was fixed in Task 3. Does it pass the pipeline?"
run "git checkout -q v1-secure -- $FILES"
run "./ci.sh"
say "RESULT: secrets, SAST and ZAP pass - but the dependency gate FAILS"
say "        Task 3 fixed the code but kept Flask 3.0.3 (PYSEC-2026-2151). The pipeline caught it."
next

# ---------------------------------------------------------------- 4
say "SCENE 4/7 - Release build: Flask upgraded to 3.1.3"
run "git checkout -q secure -- $FILES"
run "grep -i flask requirements.txt"
run "./ci.sh"
run "git log --oneline -3"
say "RESULT: all 4 gates pass, exit 0 - released as tag v2-release"
next

# ---------------------------------------------------------------- 5
say "SCENE 5/7 - Deploy the release (Docker, local only)"
run "sudo rm -f logs/auth.log logs/alerts.log"
run "./deploy.sh"
run "sleep 3; docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'"
run "ss -ltn | grep 5000"
run "curl -s http://127.0.0.1:5000/health; echo"
say "RESULT: running in Docker, bound to 127.0.0.1 only, health check ok"
next

# ---------------------------------------------------------------- 6
say "SCENE 6/7 - Monitoring: live brute-force attack"
note "monitor.py watches logs/auth.log. Rules:"
note "  R1 BRUTE_FORCE (HIGH): 5+ failed logins from one IP in 60 s"
note "  R2 POSSIBLE_COMPROMISE (CRITICAL): successful login after 5+ failures in 5 min"
python3 monitor.py logs/auth.log --follow &
MON=$!
sleep 1
note "Attacker: 6 wrong passwords for student07, then the correct one..."
run "for i in \$(seq 1 6); do curl -s -o /dev/null -d \"username=student07&password=guess\$i\" http://127.0.0.1:5000/login; done"
run "curl -s -o /dev/null -d 'username=student07&password=Student@123' http://127.0.0.1:5000/login"
sleep 2
kill "$MON" 2>/dev/null
say "RESULT: HIGH brute-force alert, then CRITICAL compromise alert"
next

# ---------------------------------------------------------------- 7
say "SCENE 7/7 - Before / after"
note "Secret scan : 4 secrets                    ->  0"
note "SAST        : 9 findings (2 High)          ->  0 findings"
note "Dependencies: Flask 3.0.3 vulnerable       ->  Flask 3.1.3, clean"
note "DAST (ZAP)  : 3 High alerts                ->  0 High"
note "Commit gate : none                         ->  insecure commits refused"
note "Monitoring  : logs nobody watched          ->  brute-force + compromise alerts"
say "Residual risks and recommendations are listed in the report."
printf "\n\033[2m[press Enter to clean up]\033[0m"; read -r _

docker rm -f shielddesk >/dev/null 2>&1
git checkout -q secure -- .
clear
echo "Demo finished - container removed, working tree restored:"
git status --short; [ -z "$(git status --short)" ] && echo "(clean)"
