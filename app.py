"""ShieldDesk v1 (secure build) - a university service-desk web app.

Run it only locally (Kali VM / Docker bound to 127.0.0.1) with synthetic data.
"""
import ast
import logging
import operator
import re
import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=config.USE_HTTPS)

# ---------- input validation (allowlists) ----------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
STUDENT_ID_RE = re.compile(r"^[A-Za-z0-9]{6,12}$")
SEARCH_RE = re.compile(r"^[\w\s.,?'-]{1,50}$")
DESC_RE = re.compile(r"^[\w\s.,;:!?@#()'/-]{1,500}$")
EXPR_RE = re.compile(r"^[0-9+\-*/(). ]{1,30}$")
CATEGORIES = {"IT Support", "Transcript Request", "Course Registration",
              "Fee Query", "Library Access", "Room Booking"}
STATUSES = {"Open", "In Progress", "Closed"}
_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv}


def safe_eval(expr):
    """Evaluate +,-,*,/ on numbers only (replaces eval())."""
    def walk(n):
        if isinstance(n, ast.Expression):
            return walk(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
            return n.value
        if isinstance(n, ast.BinOp) and type(n.op) in _OPS:
            return _OPS[type(n.op)](walk(n.left), walk(n.right))
        raise ValueError("unsupported expression")
    return walk(ast.parse(expr, mode="eval"))


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp

# ---------- authentication event log ----------
# Format: 2026-11-16 10:42:07 | LOGIN_FAILED | user=student01 | ip=127.0.0.1
os.makedirs(os.path.dirname(config.LOG_PATH), exist_ok=True)
auth_logger = logging.getLogger("shielddesk.auth")
auth_logger.setLevel(logging.INFO)
_handler = logging.FileHandler(config.LOG_PATH)
_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s", "%Y-%m-%d %H:%M:%S"))
auth_logger.addHandler(_handler)


def log_auth(event, username):
    username = re.sub(r"[^\w.@-]", "_", str(username))[:32]  # no log injection
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


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
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
        user = None
        if USERNAME_RE.match(username):
            user = get_db().execute("SELECT * FROM users WHERE username = ?",
                                    (username,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            log_auth("LOGIN_FAILED", username)
            error = "Invalid username or password"
        else:
            session.clear()
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
        if not (STUDENT_ID_RE.match(student_id) and category in CATEGORIES
                and DESC_RE.match(description)):
            return render_template("new_request.html", error="Invalid input"), 400
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
        abort(404)
    if session["role"] == "student" and row["user_id"] != session["user_id"]:
        abort(404)
    return render_template("request_detail.html", r=row)


@app.route("/search")
def search():
    """Public help-center search."""
    q = request.args.get("q", "")
    items, error = [], None
    if q and not SEARCH_RE.match(q):
        error = "Invalid search term"
    elif q:
        like = f"%{q}%"
        items = get_db().execute(
            "SELECT title, answer FROM faq WHERE title LIKE ? OR answer LIKE ?",
            (like, like)).fetchall()
    return render_template("search.html", q=q, items=items, error=error)


@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    rows = db.execute("SELECT * FROM requests ORDER BY id DESC LIMIT 50").fetchall()
    return render_template("admin.html", users=users, rows=rows)


@app.route("/admin/status", methods=["POST"])
@admin_required
def admin_status():
    status, rid = request.form.get("status", ""), request.form.get("id", "")
    if status not in STATUSES or not rid.isdigit():
        abort(400)
    db = get_db()
    db.execute("UPDATE requests SET status = ? WHERE id = ?", (status, int(rid)))
    db.commit()
    return redirect(url_for("admin"))


@app.route("/admin/sla")
@admin_required
def admin_sla():
    """SLA hours calculator, e.g. /admin/sla?expr=24*3"""
    expr = request.args.get("expr", "24")
    if not EXPR_RE.match(expr):
        return render_template("sla.html", error="Invalid expression"), 400
    try:
        result = safe_eval(expr)
    except (ValueError, SyntaxError, ZeroDivisionError):
        return render_template("sla.html", error="Invalid expression"), 400
    return render_template("sla.html", expr=expr, result=result)


if __name__ == "__main__":
    app.run(host=config.HOST, port=5000, debug=False)
