#!/usr/bin/env bash
# deploy.sh - run ShieldDesk locally for the Task 5 deployment + monitoring demo.
# Binds to 127.0.0.1 only. The secret key is generated at deploy time, never stored in Git.
set -eu
cd "$(dirname "$0")"
mkdir -p logs
export SHIELDDESK_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

if command -v docker >/dev/null 2>&1; then
    docker build -t shielddesk:v1 .
    docker rm -f shielddesk >/dev/null 2>&1 || true
    docker run -d --name shielddesk \
        -p 127.0.0.1:5000:5000 \
        -e SHIELDDESK_SECRET_KEY \
        -v "$PWD/logs:/app/logs" \
        shielddesk:v1
    echo "[deploy] container 'shielddesk' running on http://127.0.0.1:5000 (logs -> ./logs/auth.log)"
else
    echo "[deploy] docker not found - running with python3 instead"
    fuser -k 5000/tcp >/dev/null 2>&1 || true
    python3 seed.py
    nohup python3 app.py > logs/app.out 2>&1 &
    echo "[deploy] app running on http://127.0.0.1:5000 (pid $!)"
fi
