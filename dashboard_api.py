"""Read-only dashboard API + static PWA.

Mounted beside the licence service via wsgi.py.
Does NOT issue/revoke licences. Does NOT use or expose AEGIS_VENDOR_KEY_HEX.
Auth: AEGIS_DASHBOARD_TOKEN (set only in host env / Render dashboard).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import parse_qs

DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"
START_TS = time.time()

# In-memory sessions: token -> expiry (epoch)
_SESSIONS: dict[str, float] = {}
SESSION_TTL = 12 * 3600


def _dashboard_token() -> str:
    return (os.environ.get("AEGIS_DASHBOARD_TOKEN") or "").strip()


def _db_path() -> str:
    return os.environ.get("AEGIS_LICENCE_DB_PATH", "licences.db")


def _conn():
    path = _db_path()
    c = sqlite3.connect(path, timeout=5, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def _json(start_response, code: int, obj, extra_headers=None):
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(data))),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    start_response(str(code) + " " + {200: "OK", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 503: "Service Unavailable"}.get(code, "Error"), headers)
    return [data]


def _read_body(environ, limit=4096):
    try:
        n = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        return b""
    if n < 0 or n > limit:
        return None
    return environ["wsgi.input"].read(n)


def _session_ok(environ) -> bool:
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if auth.lower().startswith("bearer "):
        tok = auth[7:].strip()
        exp = _SESSIONS.get(tok)
        if exp and exp > time.time():
            return True
    # also allow cookie
    cookie = environ.get("HTTP_COOKIE", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("aegis_dash="):
            tok = part.split("=", 1)[1].strip()
            exp = _SESSIONS.get(tok)
            if exp and exp > time.time():
                return True
    return False


def _require_auth(environ, start_response):
    if not _dashboard_token():
        return _json(start_response, 503, {"error": "dashboard auth not configured"})
    if not _session_ok(environ):
        return _json(start_response, 401, {"error": "login required"})
    return None


def _stats(c):
    rows = c.execute("SELECT status, expiry, COUNT(*) AS n FROM licences GROUP BY status, expiry").fetchall()
    total = c.execute("SELECT COUNT(*) AS n FROM licences").fetchone()["n"]
    by_status = {"OK": 0, "REVOKED": 0, "SUSPENDED": 0}
    expired = 0
    lifetime = 0
    today = time.strftime("%Y%m%d", time.gmtime())
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + r["n"]
        if r["expiry"] == "LIFETIME":
            lifetime += r["n"]
        elif r["status"] == "OK" and r["expiry"] < today:
            expired += r["n"]
    unbound = c.execute(
        "SELECT COUNT(*) AS n FROM licences l WHERE NOT EXISTS (SELECT 1 FROM bindings b WHERE b.serial=l.serial)"
    ).fetchone()["n"]
    return {
        "total": total,
        "active_ok": by_status.get("OK", 0),
        "revoked": by_status.get("REVOKED", 0),
        "suspended": by_status.get("SUSPENDED", 0),
        "expired_ok_rows": expired,
        "lifetime": lifetime,
        "unbound": unbound,
    }


def _list_licences(c, q: str, limit=200):
    q = (q or "").strip()
    sql = "SELECT serial, plan, status, expiry, max_accounts, max_devices, min_version, is_test, created_at, updated_at FROM licences"
    args = []
    if q:
        sql += " WHERE serial LIKE ? OR plan LIKE ?"
        args.extend(["%" + q + "%", "%" + q + "%"])
    sql += " ORDER BY updated_at DESC LIMIT ?"
    args.append(limit)
    out = []
    for r in c.execute(sql, args):
        out.append(dict(r))
    return out


def _detail(c, serial: str):
    row = c.execute("SELECT * FROM licences WHERE serial=?", (serial,)).fetchone()
    if not row:
        return None
    d = dict(row)
    binds = c.execute("SELECT kind, value, first_seen, last_seen FROM bindings WHERE serial=? ORDER BY kind, value", (serial,)).fetchall()
    d["bindings"] = [dict(b) for b in binds]
    # mask binding values partially
    for b in d["bindings"]:
        v = b["value"]
        if len(v) > 6:
            b["value_masked"] = v[:2] + "…" + v[-2:]
        else:
            b["value_masked"] = "…"
        del b["value"]
    audits = c.execute(
        "SELECT ts, event, status, reason FROM audit WHERE serial_ref LIKE ? ORDER BY id DESC LIMIT 50",
        (serial[:8] + "%",),
    ).fetchall()
    # audit stores serial_ref hashed/ref — may not match; still return recent global if empty
    d["audit_sample"] = [dict(a) for a in audits]
    return d


def application(environ, start_response):
    path = environ.get("PATH_INFO") or ""
    method = environ.get("REQUEST_METHOD", "GET")

    # Static dashboard assets
    if path == "/dashboard" or path == "/dashboard/":
        path = "/dashboard/index.html"
    if path.startswith("/dashboard/"):
        rel = path[len("/dashboard/") :]
        if ".." in rel or rel.startswith("/"):
            return _json(start_response, 404, {"error": "not found"})
        if rel == "":
            rel = "index.html"
        fp = DASHBOARD_DIR / rel
        if not fp.is_file():
            return _json(start_response, 404, {"error": "not found"})
        data = fp.read_bytes()
        ctype = "text/plain"
        if rel.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        elif rel.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        elif rel.endswith(".js"):
            ctype = "application/javascript; charset=utf-8"
        elif rel.endswith(".json"):
            ctype = "application/json; charset=utf-8"
        elif rel.endswith(".webmanifest") or rel.endswith("manifest.json"):
            ctype = "application/manifest+json; charset=utf-8"
        elif rel.endswith(".svg"):
            ctype = "image/svg+xml"
        elif rel.endswith(".png"):
            ctype = "image/png"
        start_response("200 OK", [("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-cache")])
        return [data]

    # API
    if path == "/api/dashboard/login":
        if method != "POST":
            return _json(start_response, 405, {"error": "method not allowed"})
        expected = _dashboard_token()
        if not expected:
            return _json(start_response, 503, {"error": "dashboard auth not configured — set AEGIS_DASHBOARD_TOKEN in host env"})
        raw = _read_body(environ)
        if raw is None:
            return _json(start_response, 403, {"error": "bad body"})
        try:
            form = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            password = (form.get("password") or form.get("token") or [""])[0]
        except Exception:
            return _json(start_response, 403, {"error": "bad form"})
        if not hmac.compare_digest(password, expected):
            time.sleep(0.3)
            return _json(start_response, 401, {"error": "invalid credentials"})
        session = secrets.token_urlsafe(32)
        _SESSIONS[session] = time.time() + SESSION_TTL
        cookie = f"aegis_dash={session}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"
        return _json(start_response, 200, {"ok": True, "token": session, "expires_in": SESSION_TTL}, [("Set-Cookie", cookie)])

    if path == "/api/dashboard/logout":
        # best-effort clear
        return _json(start_response, 200, {"ok": True}, [("Set-Cookie", "aegis_dash=; Path=/; Max-Age=0")])

    if path == "/api/dashboard/overview":
        denied = _require_auth(environ, start_response)
        if denied:
            return denied
        try:
            c = _conn()
            stats = _stats(c)
            c.close()
        except Exception as e:
            return _json(start_response, 503, {"error": "database unavailable", "detail": str(e.__class__.__name__)})
        return _json(start_response, 200, {"stats": stats, "server_time": int(time.time())})

    if path == "/api/dashboard/licences":
        denied = _require_auth(environ, start_response)
        if denied:
            return denied
        qs = parse_qs(environ.get("QUERY_STRING") or "")
        q = (qs.get("q") or [""])[0]
        try:
            c = _conn()
            rows = _list_licences(c, q)
            c.close()
        except Exception as e:
            return _json(start_response, 503, {"error": "database unavailable", "detail": str(e.__class__.__name__)})
        return _json(start_response, 200, {"licences": rows})

    if path.startswith("/api/dashboard/licences/"):
        denied = _require_auth(environ, start_response)
        if denied:
            return denied
        serial = path.split("/api/dashboard/licences/", 1)[1].strip()
        if not serial or "/" in serial:
            return _json(start_response, 404, {"error": "not found"})
        try:
            c = _conn()
            d = _detail(c, serial)
            c.close()
        except Exception as e:
            return _json(start_response, 503, {"error": "database unavailable", "detail": str(e.__class__.__name__)})
        if not d:
            return _json(start_response, 404, {"error": "not found"})
        return _json(start_response, 200, {"licence": d})

    if path == "/api/dashboard/health":
        denied = _require_auth(environ, start_response)
        if denied:
            return denied
        ok = True
        err = None
        try:
            c = _conn()
            c.execute("SELECT 1")
            c.close()
        except Exception as e:
            ok = False
            err = str(e.__class__.__name__)
        return _json(
            start_response,
            200,
            {
                "licence_health_url": "https://licence.leveragefx.co/healthz",
                "db_path": _db_path(),
                "db_ok": ok,
                "db_error": err,
                "uptime_sec": int(time.time() - START_TS),
                "server_time": int(time.time()),
            },
        )

    return _json(start_response, 404, {"error": "not found"})
