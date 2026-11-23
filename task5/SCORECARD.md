# ShieldDesk before/after security scorecard (Task 5)

Measured with `ci.sh`. Fill in the cells marked TBD from the Kali run (`reports/summary.txt`, `reports/zap.json`).

| Control / gate | Before: v0-vulnerable | After: v1-secure + Flask 3.1.3 | Evidence | Status |
|---|---|---|---|---|
| Secret scan | 4 hardcoded secrets (`SECRET_KEY`, `ADMIN_PASSWORD`, `DB_BACKUP_PASSWORD`, `INTERNAL_API_KEY`) | 0; secret key read from the environment | S1, S5 | Fixed |
| SAST (Bandit) | 9 findings: High 2 / Medium 4 / Low 3; 277 LOC, 32.49 findings per KLOC | 0 findings; 410 LOC, 0 per KLOC | S1, S5 | Fixed |
| SCA (pip-audit) | Flask 3.0.3, PYSEC-2026-2151 | Flask 3.1.3, no known vulnerabilities | S4, S5 | Fixed (found by Task 5, missed by Task 3) |
| DAST (OWASP ZAP) | High TBD (expect Reflected XSS on `/search`) / Medium TBD / Low TBD | High 0 / Medium TBD / Low TBD | S2, S5 | TBD |
| Pre-commit gate | No automated checks; anything could be committed | Insecure commit blocked, fixed commit accepted | S3, S6 | Implemented |
| Monitoring | Auth events logged, but nobody watches them | R1 brute-force (HIGH) and R2 possible-compromise (CRITICAL) alerts | S8, S9 | Implemented |
| Deployment | `0.0.0.0`, `debug=True` | Docker, 127.0.0.1 only, key generated at deploy time, debug off | S7 | Fixed |

## Residual risks

| Risk | Why it remains | Recommended next step |
|---|---|---|
| v0 secrets still in Git history | They are removed from the code, but commit `c6fa3dd` still contains them | Rotate every value; for a real project, rewrite history (e.g. `git filter-repo`) |
| Hook can be bypassed | `git commit --no-verify` skips a local hook | Run the same `ci.sh` server-side (e.g. GitHub Actions) as a required check |
| DAST coverage is unauthenticated | The ZAP quick scan does not log in, so `/admin` and `/requests` are not deeply tested | Use an authenticated ZAP context or a scripted login |
| Medium/Low findings are not blocking | By policy only High/Critical blocks (e.g. missing anti-CSRF tokens on forms) | Track them in the vulnerability backlog; add CSRF protection (Flask-WTF) |
| Detection without prevention | The monitor alerts on brute force, but the app has no account lockout or rate limit | Add lockout/rate limiting (a Task 4 gap); forward alerts to a SIEM |
| SCA needs internet | pip-audit fetches the advisory database online | Cache or mirror the database for an offline lab |
