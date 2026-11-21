from datetime import datetime, timedelta, timezone
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile

from flask import Flask, abort, jsonify, redirect, render_template_string, request, send_from_directory, session, url_for
from flask_migrate import Migrate
from sqlalchemy import delete, event, func, select, text
from sqlalchemy.engine import Engine
from werkzeug.security import check_password_hash, generate_password_hash
from flask.sessions import SecureCookieSessionInterface

from db import RevisionConflict, get_state, replace_state
from extensions import db, migrate
import models  # noqa: F401 - registers ORM models with SQLAlchemy metadata

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)


def private_password(environment_name, filename):
    configured = os.environ.get(environment_name)
    if configured:
        return configured
    try:
        return (INSTANCE_DIR / filename).read_text(encoding="utf-8").strip() or None
    except FileNotFoundError:
        return None


def get_secret_key():
    configured = os.environ.get("JIREH_SECRET_KEY")
    if configured:
        return configured
    key_path = INSTANCE_DIR / "jireh_secret.key"
    try:
        return key_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        generated = secrets.token_hex(32)
        try:
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return key_path.read_text(encoding="utf-8").strip()
        with os.fdopen(descriptor, "w", encoding="utf-8") as key_file:
            key_file.write(generated)
        return generated


class RequestAwareSecureCookieSessionInterface(SecureCookieSessionInterface):
    def get_cookie_secure(self, app):
        # Use secure cookies automatically for HTTPS requests, including PythonAnywhere.
        return bool(app.config["SESSION_COOKIE_SECURE"] or request.is_secure)


app = Flask(__name__, static_folder=None)
app.session_interface = RequestAwareSecureCookieSessionInterface()
app.config.update(
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
    SECRET_KEY=get_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("JIREH_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"},
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
ADMIN_PASSWORD = private_password("JIREH_ADMIN_PASSWORD", "jireh_admin_password")
MASTER_PASSWORD = private_password("JIREH_MASTER_PASSWORD", "jireh_master_password")
AUTH_CONFIG_PATH = INSTANCE_DIR / "jireh_auth_config.json"

raw_database_url = os.environ.get("DATABASE_URL")
if raw_database_url:
    if raw_database_url.startswith("postgres://"):
        raw_database_url = "postgresql+psycopg://" + raw_database_url[len("postgres://"):]
    elif raw_database_url.startswith("postgresql://"):
        raw_database_url = "postgresql+psycopg://" + raw_database_url[len("postgresql://"):]
else:
    db_path = Path(os.environ.get("JIREH_DB_PATH", BASE_DIR / "instance" / "encomienda_jireh.sqlite3")).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    raw_database_url = f"sqlite:///{db_path.resolve()}"

app.config.update(
    SQLALCHEMY_DATABASE_URI=raw_database_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
)
db.init_app(app)
migrate.init_app(app, db, directory="alembic")


@event.listens_for(Engine, "connect")
def configure_sqlite_connection(dbapi_connection, _connection_record):
    if dbapi_connection.__class__.__module__.startswith("sqlite3"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


def ensure_meta():
    with app.app_context():
        from models import DatabaseMeta
        if db.session.get(DatabaseMeta, 1) is None:
            db.session.add(DatabaseMeta(singleton=1, revision=0))
            db.session.commit()


def load_auth_config():
    try:
        config = json.loads(AUTH_CONFIG_PATH.read_text(encoding="utf-8"))
        return config if isinstance(config, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def ensure_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def master_auth_tag():
    return hmac.new(app.config["SECRET_KEY"].encode("utf-8"), (MASTER_PASSWORD or "").encode("utf-8"), "sha256").hexdigest()


def save_auth_config(config):
    descriptor, temporary_path = tempfile.mkstemp(prefix="jireh-auth-", dir=INSTANCE_DIR)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as config_file:
            json.dump(config, config_file, ensure_ascii=False)
        os.replace(temporary_path, AUTH_CONFIG_PATH)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


LOGIN_PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Acceso · Encomienda Jireh</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}
body{position:relative;isolation:isolate;margin:0;min-height:100vh;min-height:100svh;padding:28px;display:grid;place-items:center;overflow-x:hidden;background:#080808;color:#fff;font:16px/1.5 Arial,sans-serif}
body:before{position:fixed;inset:0;z-index:-1;content:"";background:radial-gradient(ellipse at 50% 42%,rgba(113,0,9,.34),transparent 46%),linear-gradient(180deg,rgba(0,0,0,.22),#080808 92%),#111}
body:after{position:fixed;inset:0 0 auto;height:4px;content:"";background:linear-gradient(90deg,#8e0008,#e50914 48%,#8e0008);box-shadow:0 2px 24px #e5091450}
.card{width:min(92vw,440px);padding:42px 40px 36px;border:1px solid #ffffff16;border-radius:12px;background:rgba(18,18,18,.94);box-shadow:0 24px 80px #000a}
.brand{margin:0 0 8px;color:#e50914;font-size:30px;line-height:1.15;font-weight:800;letter-spacing:-.7px}.sub{margin:0 0 28px;color:#b3b3b3;font-size:15px}
label{display:block;margin:14px 0 8px;color:#f2f2f2;font-size:14px;font-weight:700}
input{width:100%;padding:14px 15px;border:1px solid #555;border-radius:6px;outline:none;background:#2b2b2b;color:#fff;font-size:16px;transition:border-color .18s,box-shadow .18s}
input:focus{border-color:#e50914;box-shadow:0 0 0 3px #e509142e}
button{width:100%;margin-top:22px;padding:14px;border:0;border-radius:6px;background:#e50914;color:white;font-size:16px;font-weight:700;cursor:pointer;transition:background .18s,transform .18s}
button:hover{background:#f6121d}button:active{transform:scale(.99)}button:focus-visible{outline:3px solid #fff;outline-offset:3px}
.error{margin:0 0 16px;padding:11px 13px;border:1px solid #8e3030;border-radius:6px;background:#391719;color:#ffb8b8}
.hint{margin:18px 0 0;text-align:center;color:#858585;font-size:13px}
@media(max-width:520px){body{padding:16px}.card{width:100%;padding:34px 26px 30px}.brand{font-size:27px}}
</style></head><body><main class="card"><h1 class="brand">Encomienda Jireh</h1><p class="sub">Ingresa la clave de administrador para continuar.</p>
{% if notice %}<p class="hint" role="status">{{ notice }}</p>{% endif %}
{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
<form method="post" action="{{ url_for('login') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token }}"><input type="hidden" name="next" value="{{ next_url }}">
<label for="password">Clave de administrador</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Iniciar sesión</button></form><p class="hint">Encomienda Jireh · acceso protegido</p></main></body></html>"""


@app.before_request
def require_admin_session():
    if request.endpoint in {"login", "logout"}:
        return None
    if session.get("jireh_admin") is True:
        auth_version = int(load_auth_config().get("auth_version", 0))
        master_is_current = (
            session.get("jireh_master") is not True
            or hmac.compare_digest(session.get("master_auth_tag", ""), master_auth_tag())
        )
        if session.get("auth_version") == auth_version and master_is_current:
            return None
        session.clear()
    if request.path.startswith("/api/"):
        return jsonify({"error": "Se requiere iniciar sesión.", "loginRequired": True}), 401
    return redirect(url_for("login", next=request.full_path if request.query_string else request.path))


@app.before_request
def protect_state_changes_from_csrf():
    if request.method in {"GET", "HEAD", "OPTIONS"} or request.endpoint is None:
        return None
    # Native clients such as older versions of Monitor Jireh may not send browser origin headers.
    if (
        request.endpoint == "login"
        and not request.headers.get("Origin")
        and not request.headers.get("Referer")
        and not request.form.get("csrf_token")
    ):
        return None
    expected = session.get("_csrf_token", "")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
        if request.path.startswith("/api/"):
            return jsonify({"error": "La solicitud de seguridad expiró. Recarga la página e inténtalo de nuevo."}), 400
        return "La solicitud de seguridad expiró. Recarga la página e inténtalo de nuevo.", 400
    return None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if app.config["SESSION_COOKIE_SECURE"] or request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if response.mimetype == "text/html":
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )
    if request.endpoint in {"index", "login"}:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.after_request
def record_web_activity(response):
    """Registra metadatos de uso sin guardar contraseñas ni contenido enviado."""
    if request.endpoint in {"monitor_activity", "static_files"} or (request.endpoint == "login" and response.status_code == 429):
        return response
    try:
        if request.endpoint == "login" and request.method == "POST":
            event_type = "login_success" if session.get("jireh_admin") is True else "login_failed"
        elif request.endpoint == "logout":
            event_type = "logout"
        elif request.method == "GET":
            event_type = "visit"
        else:
            event_type = "action"

        activity = models.WebActivity(
            event_type=event_type,
            endpoint=request.endpoint or "unknown",
            method=request.method,
            status=response.status_code,
            username="admin" if session.get("jireh_admin") is True else "anonimo",
            remote_addr=request.remote_addr or "desconocida",
        )
        db.session.add(activity)
        db.session.flush()
        if activity.id % 100 == 0:
            db.session.execute(
                delete(models.WebActivity).where(models.WebActivity.id <= activity.id - 5000)
            )
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("No se pudo registrar la actividad web")
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("jireh_admin") is True:
        return redirect(url_for("index"))
    next_url = request.values.get("next", "/")
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"
    error = None
    notice = "La clave se actualizó. Inicia sesión con la nueva clave." if request.args.get("changed") == "1" else None
    status = 200
    if request.method == "POST":
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(minutes=15)).isoformat(timespec="seconds")
        remote_addr = request.remote_addr or "desconocida"
        recent_failures = db.session.scalar(
            select(func.count()).select_from(models.WebActivity).where(
                models.WebActivity.event_type == "login_failed",
                models.WebActivity.remote_addr == remote_addr,
                models.WebActivity.created_at >= cutoff,
            )
        ) or 0
        if recent_failures >= 5:
            oldest_failure = db.session.scalar(
                select(func.min(models.WebActivity.created_at)).where(
                    models.WebActivity.event_type == "login_failed",
                    models.WebActivity.remote_addr == remote_addr,
                    models.WebActivity.created_at >= cutoff,
                )
            )
            retry_after = 900
            if oldest_failure:
                expires = datetime.fromisoformat(oldest_failure) + timedelta(minutes=15)
                retry_after = max(1, int((expires - now).total_seconds()))
            response = app.make_response(render_template_string(
                LOGIN_PAGE, error="Demasiados intentos. Espera unos minutos e inténtalo de nuevo.",
                notice=None, next_url="/", csrf_token=ensure_csrf_token()
            ))
            response.status_code = 429
            response.headers["Retry-After"] = str(retry_after)
            response.headers["Cache-Control"] = "no-store"
            return response
        submitted = request.form.get("password", "")
        auth_config = load_auth_config()
        stored_hash = auth_config.get("admin_password_hash")
        if stored_hash:
            admin_matches = check_password_hash(stored_hash, submitted)
        else:
            configured_password = os.environ.get("JIREH_ADMIN_PASSWORD", ADMIN_PASSWORD)
            admin_matches = bool(configured_password) and hmac.compare_digest(submitted.encode("utf-8"), configured_password.encode("utf-8"))
        master_matches = bool(MASTER_PASSWORD) and hmac.compare_digest(submitted.encode("utf-8"), MASTER_PASSWORD.encode("utf-8"))
        if admin_matches or master_matches:
            session.clear()
            session["jireh_admin"] = True
            session["jireh_master"] = master_matches
            if master_matches:
                session["master_auth_tag"] = master_auth_tag()
            session["auth_version"] = int(auth_config.get("auth_version", 0))
            session.permanent = True
            return redirect(next_url)
        error = "La clave no es correcta. Intenta de nuevo."
        status = 401
    return render_template_string(LOGIN_PAGE, error=error, notice=notice, next_url=next_url, csrf_token=ensure_csrf_token()), status


CHANGE_PASSWORD_PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cambiar clave · Encomienda Jireh</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f1f4f1;color:#26352e;font:16px Arial,sans-serif}
.card{width:min(92vw,480px);background:white;border-radius:24px;padding:38px;box-shadow:0 18px 55px #16352b20}.brand{color:#087f62;font-size:25px;margin:0 0 8px}
p{color:#708077;line-height:1.5}label{display:block;font-weight:700;margin:16px 0 8px}input{width:100%;padding:13px;border:1px solid #cbd7d1;border-radius:12px;font-size:16px}
button,.back{display:inline-block;margin-top:20px;padding:13px 18px;border:0;border-radius:12px;background:#087f62;color:white;text-decoration:none;font-size:16px;font-weight:700;cursor:pointer}.error{padding:11px 13px;border-radius:10px;background:#fff0ed;color:#a53727}
</style></head><body><main class="card"><h1 class="brand">Cambiar clave de acceso</h1><p>Esta clave la usarán quienes entren a la aplicación. La clave maestra permanece privada y no se cambia aquí.</p>
{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token }}"><label for="current_password">Confirma tu clave actual</label><input id="current_password" name="current_password" type="password" autocomplete="current-password" required>
<label for="new_password">Nueva clave de acceso</label><input id="new_password" name="new_password" type="password" minlength="8" autocomplete="new-password" required>
<label for="confirm_password">Confirma la nueva clave</label><input id="confirm_password" name="confirm_password" type="password" minlength="8" autocomplete="new-password" required>
<button type="submit">Guardar nueva clave</button></form><a class="back" href="/">Volver a Encomienda Jireh</a></main></body></html>"""


@app.route("/clave", methods=["GET", "POST"])
def change_admin_password():
    error = None
    status = 200
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        auth_config = load_auth_config()
        stored_hash = auth_config.get("admin_password_hash")
        if session.get("jireh_master") is True:
            current_matches = bool(MASTER_PASSWORD) and hmac.compare_digest(current_password.encode("utf-8"), MASTER_PASSWORD.encode("utf-8"))
        elif stored_hash:
            current_matches = check_password_hash(stored_hash, current_password)
        else:
            configured_password = os.environ.get("JIREH_ADMIN_PASSWORD", ADMIN_PASSWORD)
            current_matches = bool(configured_password) and hmac.compare_digest(current_password.encode("utf-8"), configured_password.encode("utf-8"))
        new_password = request.form.get("new_password", "")
        confirmation = request.form.get("confirm_password", "")
        if not current_matches:
            error, status = "La clave actual no es correcta.", 403
        elif len(new_password) < 8:
            error, status = "La nueva clave debe tener al menos 8 caracteres.", 400
        elif new_password != confirmation:
            error, status = "Las claves nuevas no coinciden.", 400
        elif MASTER_PASSWORD and hmac.compare_digest(new_password.encode("utf-8"), MASTER_PASSWORD.encode("utf-8")):
            error, status = "La clave de acceso debe ser distinta a la clave maestra.", 400
        else:
            auth_config["admin_password_hash"] = generate_password_hash(new_password, method="pbkdf2:sha256:600000")
            auth_config["auth_version"] = int(auth_config.get("auth_version", 0)) + 1
            save_auth_config(auth_config)
            session.clear()
            return redirect(url_for("login", changed="1"))
    response = app.make_response(render_template_string(CHANGE_PASSWORD_PAGE, error=error, csrf_token=ensure_csrf_token()))
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    page = (BASE_DIR / "index.html").read_text(encoding="utf-8")
    marker = '<small class="footer-caption">Encomienda Jireh · versión web</small>'
    link = '<a class="side-action" href="/clave" aria-label="Cambiar clave de acceso">🔐 Cambiar clave de acceso</a>'
    page = page.replace(marker, link + marker, 1)
    csrf_token = ensure_csrf_token()
    logout_form = '<form action="/logout" method="post" style="margin:0">'
    secured_logout_form = logout_form + '<input type="hidden" name="csrf_token" value="' + csrf_token + '">'
    page = page.replace(logout_form, secured_logout_form, 1)
    csrf_script = (
        '<meta name="csrf-token" content="' + csrf_token + '">'
        '<script>(function(){var f=window.fetch.bind(window);window.fetch=function(input,init){init=init||{};var m=(init.method||(input instanceof Request?input.method:"GET")).toUpperCase();if(!["GET","HEAD","OPTIONS"].includes(m)){var u=new URL(input instanceof Request?input.url:input,location.href);if(u.origin===location.origin){var h=new Headers(init.headers||(input instanceof Request?input.headers:undefined));h.set("X-CSRF-Token",document.querySelector("meta[name=csrf-token]").content);init=Object.assign({},init,{headers:h})}}return f(input,init)}})();</script>'
    )
    page = page.replace("<head>", "<head>" + csrf_script, 1)
    response = app.response_class(page, mimetype="text/html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/health")
def health():
    dialect = db.engine.dialect.name
    db.session.execute(text("SELECT 1"))
    integrity = "ok"
    if dialect == "sqlite":
        integrity = db.session.execute(text("PRAGMA quick_check")).scalar_one()
    state = get_state()
    return jsonify({"status": "ok" if integrity == "ok" else "error", "database": dialect, "revision": state["revision"], "integrity": integrity})


@app.get("/api/state")
def read_state():
    return jsonify(get_state())


@app.put("/api/state")
def write_state():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("revision"), int) or body["revision"] < 0:
        return jsonify({"error": "Se requiere una revisión válida de la base de datos."}), 400
    try:
        state = replace_state(body, body["revision"])
    except RevisionConflict as error:
        return jsonify({"error": "Los datos cambiaron desde otra sesión. Recarga la app para evitar sobrescribir cambios.", "revision": error.current}), 409
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("No se pudo guardar la transacción SQL")
        return jsonify({"error": "No se pudo guardar la transacción. La base de datos conservó el estado anterior."}), 500
    return jsonify(state)


@app.get("/api/backup")
def backup():
    state = get_state()
    return jsonify({"app": "encomienda-jireh", "formatVersion": 2, "exportedAt": datetime.now(timezone.utc).isoformat(), **state})


@app.get("/api/monitor/activity")
def monitor_activity():
    limit = request.args.get("limit", 200, type=int) or 200
    limit = max(1, min(limit, 500))
    rows = db.session.scalars(
        select(models.WebActivity).order_by(models.WebActivity.id.desc()).limit(limit)
    ).all()
    return jsonify({
        "events": [
            {
                "id": row.id,
                "created_at": row.created_at,
                "event_type": row.event_type,
                "endpoint": row.endpoint,
                "method": row.method,
                "status": row.status,
                "username": row.username,
                "remote_addr": row.remote_addr,
            }
            for row in rows
        ]
    })


PUBLIC_FILES = {"logo-jireh.svg", "manifest.webmanifest", "sw.js"}


@app.get("/<path:filename>")
def static_files(filename: str):
    if filename not in PUBLIC_FILES:
        abort(404)
    path = (BASE_DIR / filename).resolve()
    if path.parent != BASE_DIR or not path.is_file():
        abort(404)
    return send_from_directory(BASE_DIR, filename)


if __name__ == "__main__":
    ensure_meta()
    app.run(host="127.0.0.1", port=5000, debug=False)
