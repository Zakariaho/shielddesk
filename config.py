"""ShieldDesk configuration (v1 - secure build). Secrets come from the environment."""
import os
import secrets

DB_PATH = "shielddesk.db"
LOG_PATH = "logs/auth.log"

# Secret key from the environment; a random per-process key is used if unset.
SECRET_KEY = os.environ.get("SHIELDDESK_SECRET_KEY") or secrets.token_hex(32)
HOST = os.environ.get("SHIELDDESK_HOST", "127.0.0.1")
USE_HTTPS = os.environ.get("SHIELDDESK_HTTPS") == "1"
