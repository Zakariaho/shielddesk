# ShieldDesk (v0): CYS 401 Lab Project

A small university service-desk web app used for the CYS 401 DevSecOps lab project.
Students submit requests, staff and admins manage them.

> **WARNING: this v0 build is intentionally insecure.** It is a lab target for assessing,
> fixing and verifying security controls. Run it only locally (Kali VM or Docker bound to
> 127.0.0.1). Never deploy it or expose it to a network. All data is synthetic.

## Quick start (local)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python seed.py          # creates shielddesk.db + data/students.csv
python app.py           # http://127.0.0.1:5000
```

## Quick start (Docker)

```bash
docker build -t shielddesk:v0 .
docker run --rm -p 127.0.0.1:5000:5000 shielddesk:v0
```

The `127.0.0.1:` prefix keeps the app reachable from this machine only (useful lab-isolation evidence).

## Test accounts (synthetic)

| Role | Username | Password |
|---|---|---|
| Student | `student01` ... `student50` | `Student@123` |
| Staff | `staff1` ... `staff5` | `Staff@123` |
| Admin | `admin` | `Admin@123` |

## Routes

| Route | Description |
|---|---|
| `/login`, `/logout` | Sign in / out |
| `/requests` | Student: own requests. Staff/admin: all requests |
| `/requests/new` | Submit a request |
| `/requests/<id>` | Request detail |
| `/search?q=` | Public help-center search (no login needed) |
| `/admin` | User list and request status management |
| `/admin/sla?expr=` | SLA hours calculator |
| `/health` | Health check, returns `ok` |

## Authentication log

Login events are written to `logs/auth.log` in this fixed format
(use it for the monitoring and alert rule):

```
2026-11-16 10:42:07 | LOGIN_FAILED | user=student01 | ip=127.0.0.1
2026-11-16 10:42:15 | LOGIN_SUCCESS | user=student01 | ip=127.0.0.1
2026-11-16 10:50:02 | LOGOUT | user=student01 | ip=127.0.0.1
```

## Data

`data/students.csv` holds the 50 synthetic students (name, student ID, e-mail, phone,
date of birth, programme). All values are randomly generated and fake.

## Repository workflow

- `main` holds the **v0-vulnerable** baseline, tagged `v0-vulnerable`. Do not change it:
  all "before" measurements (ASVS, Bandit, ZAP) are taken on this tag.
- Fixes go on the `secure` branch (small commits, one per control), tagged `v1-secure`.
- Pipeline and compliance work go on their own branches.

```bash
git checkout v0-vulnerable      # reproduce the baseline
git checkout secure             # secured version
```

## Layout

```
app.py            Flask application
config.py         configuration
seed.py           builds the synthetic database and CSV
templates/        HTML templates
data/             synthetic dataset export
logs/             authentication log (generated)
Dockerfile        container build
```
