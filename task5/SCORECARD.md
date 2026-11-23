# ShieldDesk before/after security scorecard (Task 5)

Measured with `ci.sh` on the Kali VM, 23 Nov 2026 (Bandit 1.9.4, pip-audit 2.10.1, OWASP ZAP 2.17.0). Line counts include the Task 5 `monitor.py`.

| Control / gate | Before: v0-vulnerable | After: v1-secure + Flask 3.1.3 | Evidence | Status |
|---|---|---|---|---|
| Secret scan | 4 hardcoded secrets (`SECRET_KEY`, `ADMIN_PASSWORD`, `DB_BACKUP_PASSWORD`, `INTERNAL_API_KEY`) | 0; secret key read from the environment | S1, S5 | Fixed |
| SAST (Bandit) | 9 findings: High 2 / Medium 4 / Low 3; 364 LOC, 24.73 findings per KLOC | 0 findings; 410 LOC, 0 per KLOC | S1, S5 | Fixed |
| SCA (pip-audit) | Flask 3.0.3, PYSEC-2026-2151 | Flask 3.1.3, no known vulnerabilities | S4, S5 | Fixed (found by Task 5, missed by Task 3) |
| DAST (OWASP ZAP) | High 3 (Reflected XSS, DOM-based XSS, SQL Injection) / Medium 3 (no anti-CSRF tokens, CSP not set, no anti-clickjacking header) / Low 2 / Info 2 | High 0 / Medium 3 (no anti-CSRF tokens, CSP has no fallback directive, CSP `style-src 'unsafe-inline'`) / Low 1 (`Server` header leaks version) / Info 2 | S2, S4, S5 | High risks fixed; Mediums remain (see residual risks) |
| Pre-commit gate | No automated checks; anything could be committed | Insecure commit blocked, fixed commit accepted | S3, S6 | Implemented |
| Monitoring | Auth events logged, but nobody watches them | R1 brute-force (HIGH) and R2 possible-compromise (CRITICAL) alerts | S8, S9 | Implemented |
| Deployment | `0.0.0.0`, `debug=True` | Docker, 127.0.0.1 only, key generated at deploy time, debug off | S7 | Fixed |

## Residual risks

| Risk | Why it remains | Recommended next step |
|---|---|---|
| v0 secrets still in Git history | They are removed from the code, but commit `c6fa3dd` still contains them | Rotate every value; for a real project, rewrite history (e.g. `git filter-repo`) |
| Hook can be bypassed | `git commit --no-verify` skips a local hook | Run the same `ci.sh` server-side (e.g. GitHub Actions) as a required check |
| DAST coverage is unauthenticated | The ZAP quick scan does not log in, so `/admin` and `/requests` are not deeply tested | Use an authenticated ZAP context or a scripted login |
| ZAP Medium/Low alerts on v1 | By policy only High/Critical blocks: missing anti-CSRF tokens, two CSP weaknesses (no fallback, `unsafe-inline` styles), `Server` header leaks the version | Backlog: add CSRF protection (Flask-WTF), tighten the CSP, hide the `Server` header behind a reverse proxy |
| Detection without prevention | The monitor alerts on brute force, but the app has no account lockout or rate limit | Add lockout/rate limiting (a Task 4 gap); forward alerts to a SIEM |
| SCA needs internet | pip-audit fetches the advisory database online | Cache or mirror the database for an offline lab |

## Pipeline timeline (evidence)

| Run | Code under test | Secrets | SAST | SCA | DAST | Verdict |
|---|---|---|---|---|---|---|
| 1 | v0-vulnerable | FAIL (4) | FAIL (H2/M4/L3) | FAIL | FAIL (H3/M3/L2) | Blocked, commit refused by hook (S1-S3) |
| 2 | v1-secure (Task 3) | pass | pass (0) | FAIL (Flask 3.0.3) | pass (H0/M3/L1) | Blocked (S4) |
| 3 | v1-secure + Flask 3.1.3 | pass | pass (0) | pass | pass (H0/M3/L1) | Released: commit d49af73, tag v2-release (S5-S6) |

Monitoring (S8): 6 failed logins for student07 against the deployed container raised BRUTE_FORCE (HIGH), then the successful login raised POSSIBLE_COMPROMISE (CRITICAL). The source IP is 172.17.0.1, the Docker bridge gateway. Container timestamps are in UTC.
