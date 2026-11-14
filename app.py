"""ShieldDesk v0 - a university service-desk web app.

WARNING: this build is INTENTIONALLY INSECURE for the CYS 401 lab project.
Run it only locally (Kali VM / Docker bound to 127.0.0.1) with synthetic data.
"""
import hashlib
import logging
import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, g, redirect, render_template, request, session, url_for

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ---------- authentication event log ----------
# Format: 2026-11-16 10:42:07 | LOGIN_FAILED | user=student01 | ip=127.0.0.1
os.makedirs(os.path.dirname(config.LOG_PATH), exist_ok=True)
auth_logger = logging.getLogger("shielddesk.auth")
auth_logger.setLevel(logging.INFO)
_handler = logging.FileHandler(config.LOG_PATH)
_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s", "%Y-%m-%d %H:%M:%S"))
auth_logger.addHandler(_handler)


def log_auth(event, username):
    auth_logger.info("%s | user=%s | ip=%s", event, username, request.remote_addr)


# ---------- helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(config.DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def md5(password):
    return hashlib.md5(password.encode()).hexdigest()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------- routes ----------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("list_requests"))
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return "ok"


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        password_hash = md5(password)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
        user = get_db().execute(query).fetchone()
        if user is None:
            log_auth("LOGIN_FAILED", username)
            error = "Invalid credentials"
        else:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            log_auth("LOGIN_SUCCESS", username)
            return redirect(url_for("list_requests"))
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    log_auth("LOGOUT", session.get("username", "-"))
    session.clear()
    return redirect(url_for("login"))


@app.route("/requests")
@login_required
def list_requests():
    db = get_db()
    if session["role"] == "student":
        rows = db.execute("SELECT * FROM requests WHERE user_id = ? ORDER BY id DESC",
                          (session["user_id"],)).fetchall()
    else:
        rows = db.execute("SELECT * FROM requests ORDER BY id DESC").fetchall()
    return render_template("requests.html", rows=rows)


@app.route("/requests/new", methods=["GET", "POST"])
@login_required
def new_request():
    if request.method == "POST":
        student_id = request.form.get("student_id", "")
        category = request.form.get("category", "")
        description = request.form.get("description", "")
        db = get_db()
        db.execute("""INSERT INTO requests (user_id, student_id, category, description, status, created_at)
                      VALUES (?, ?, ?, ?, 'Open', ?)""",
                   (session["user_id"], student_id, category, description,
                    datetime.now().strftime("%Y-%m-%d")))
        db.commit()
        return redirect(url_for("list_requests"))
    return render_template("new_request.html")


@app.route("/requests/<int:request_id>")
@login_required
def request_detail(request_id):
    row = get_db().execute(
        "SELECT r.*, u.full_name, u.email, u.phone FROM requests r "
        "JOIN users u ON u.id = r.user_id WHERE r.id = ?", (request_id,)).fetchone()
    if row is None:
        return "Request not found", 404
    return render_template("request_detail.html", r=row)


@app.route("/search")
def search():
    """Public help-center search."""
    q = request.args.get("q", "")
    items = ""
    if q:
        sql = f"SELECT title, answer FROM faq WHERE title LIKE '%{q}%' OR answer LIKE '%{q}%'"
        for row in get_db().execute(sql).fetchall():
            items += f"<li><b>{row['title']}</b> - {row['answer']}</li>"
    body = f"""
        <h2>Help Center</h2>
        <form method="get" action="/search">
            <input name="q" value="{q}" placeholder="Search help articles">
            <button type="submit">Search</button>
        </form>
        <p>Results for: {q}</p>
        <ul>{items}</ul>
    """
    return render_template("page.html", body=body)


@app.route("/admin")
@login_required
def admin():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    rows = db.execute("SELECT * FROM requests ORDER BY id DESC LIMIT 50").fetchall()
    return render_template("admin.html", users=users, rows=rows)


@app.route("/admin/status", methods=["POST"])
@login_required
def admin_status():
    db = get_db()
    db.execute("UPDATE requests SET status = ? WHERE id = ?",
               (request.form.get("status", "Open"), request.form.get("id", 0)))
    db.commit()
    return redirect(url_for("admin"))


@app.route("/admin/sla")
@login_required
def admin_sla():
    """SLA hours calculator, e.g. /admin/sla?expr=24*3"""
    expr = request.args.get("expr", "24")
    result = eval(expr)
    return render_template("page.html", body=f"<h2>SLA calculator</h2><p>{expr} = {result}</p>")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
