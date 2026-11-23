# Task 5: DevSecOps pipeline runbook (Kali VM)

Files added for Task 5 (branch `secure`, on top of `v1-secure`):

| File | Purpose |
|---|---|
| `ci.sh` | Pipeline. Gate 1 secret scan, Gate 2 Bandit SAST, Gate 3 pip-audit SCA, Gate 4 OWASP ZAP DAST. High/Critical blocks; Medium/Low reported. Reports go to `reports/`. |
| `install-hook.sh` | Installs `ci.sh` as the Git pre-commit hook. |
| `deploy.sh` | Deploys v1 in Docker bound to 127.0.0.1, with the secret key generated at deploy time and the logs volume mounted. |
| `monitor.py` | Monitoring rules on `logs/auth.log`: R1 BRUTE_FORCE (5 or more failures from one IP in 60 s), R2 POSSIBLE_COMPROMISE (success after 5 or more failures in 5 min). |
| `task5/synthetic_auth.log` | Synthetic log entries for the alert demo. |

Take a screenshot at every **[S#]** step. Each screenshot maps to a Task 5 deliverable.

## 0. One-time setup

```bash
sudo apt update && sudo apt install -y git zaproxy docker.io psmisc curl python3-pip
sudo usermod -aG docker $USER        # then log out and back in
pip install flask==3.0.3 bandit pip-audit --break-system-packages
zaproxy -cmd -version                # first run unpacks add-ons, so let it finish once
```

Gate 3 (pip-audit) needs internet access to download the vulnerability database. Everything else runs offline on 127.0.0.1.

## 1. Get the code and install the hook

```bash
git clone https://github.com/Zakariaho/shielddesk.git && cd shielddesk
git checkout secure                 # Task 5 files live on the secure branch (never commit to main)
./install-hook.sh
```

## 2. Insecure build is BLOCKED (v0)

```bash
git checkout v0-vulnerable -- app.py config.py seed.py requirements.txt templates/
./ci.sh ; echo "exit code: $?"
```

Expected: all four gates FAIL. **[S1]** Gate 1 lists 4 secrets in `config.py`, and Gate 2 shows High=2 (B324 MD5, B201 debug=True). **[S2]** Gate 4 lists the ZAP alerts with a High-risk Cross Site Scripting (Reflected) alert, then BUILD BLOCKED with exit 1.

```bash
git commit -am "release v0" ; echo "exit code: $?"
```

**[S3]** The pre-commit hook runs the pipeline and Git refuses the commit.

## 3. Task 3's secure build: still blocked by the SCA gate

```bash
git checkout secure -- app.py config.py seed.py requirements.txt templates/
./ci.sh ; echo "exit code: $?"
```

**[S4]** Gates 1, 2 and 4 pass. Gate 3 FAILS because Flask 3.0.3 has a known vulnerability (PYSEC-2026-2151, fixed in 3.1.3). Task 3's code fixes did not cover dependencies; the pipeline catches this.

## 4. Fix the dependency: the build PASSES

```bash
sed -i 's/Flask==3.0.3/Flask==3.1.3/' requirements.txt
pip install -r requirements.txt --break-system-packages
./ci.sh ; echo "exit code: $?"
```

**[S5]** All four gates pass, followed by ALL GATES PASSED and exit 0.

```bash
git commit -am "Task 5: upgrade Flask to 3.1.3 (SCA gate finding)" && git tag v2-release
```

**[S6]** The hook runs, everything passes, and the commit is accepted. Run `git log --oneline -3` to show it.

## 5. Deploy and prove it is local-only

```bash
./deploy.sh
docker ps ; ss -ltnp | grep 5000 ; curl -s http://127.0.0.1:5000/health
```

**[S7]** The container is running, port 5000 is bound to 127.0.0.1 only, and the health check returns `ok`.

## 6. Monitoring: security event leads to an alert

Terminal A:

```bash
python3 monitor.py logs/auth.log --follow
```

Terminal B (simulated attack against your own app):

```bash
for i in $(seq 1 6); do curl -s -o /dev/null -d "username=student07&password=guess$i" http://127.0.0.1:5000/login; done
curl -s -o /dev/null -d "username=student07&password=Student@123" http://127.0.0.1:5000/login
```

**[S8]** Terminal A shows `ALERT | HIGH | BRUTE_FORCE`, then `ALERT | CRITICAL | POSSIBLE_COMPROMISE`.

```bash
python3 monitor.py task5/synthetic_auth.log ; cat logs/alerts.log
```

**[S9]** The same two alerts come from the synthetic log entries (attacker ip 10.10.9.66 against student07). The normal single typos from student11 and student19 raise nothing.

## 7. Scorecard

Fill in the ZAP numbers in `task5/SCORECARD.md` from `reports/summary.txt` after step 2 and step 4.

## Troubleshooting

- **ZAP scanned the old app:** run `fuser -k 5000/tcp` before `./ci.sh`. The script does this itself, but an app you started by hand can still hold the port.
- **`ZAP produced no report`:** check `reports/zap.log`. On some installs the launcher is `zap.sh` instead of `zaproxy`; the script tries both.
- **The pre-commit hook takes a few minutes:** this is the ZAP scan. `SKIP_DAST=1 ./ci.sh` is fine for quick checks but is not valid evidence for a release.
