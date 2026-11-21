from datetime import datetime, timedelta, timezone
import hmac
import json
import os
import re
from pathlib import Path
import secrets
import tempfile

from flask import Flask, abort, jsonify, redirect, render_template, render_template_string, request, send_from_directory, session, url_for
from flask_migrate import Migrate
from sqlalchemy import delete, event, select, text
from sqlalchemy.engine import Engine
from werkzeug.security import check_password_hash, generate_password_hash
from flask.sessions import SecureCookieSessionInterface

from db import RecordConflict, RecordNotFound, RevisionConflict, delete_record, get_state, replace_state, save_record
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


def configured_admin_username(auth_config=None):
    config = auth_config if isinstance(auth_config, dict) else load_auth_config()
    username = str(config.get("admin_username", "admin")).strip().lower()
    return username if re.fullmatch(r"[a-z0-9._-]{3,40}", username) else "admin"


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
</style></head><body><main class="card"><h1 class="brand">Encomienda Jireh</h1><p class="sub">Ingresa tu usuario y contraseña para continuar.</p>
{% if notice %}<p class="hint" role="status">{{ notice }}</p>{% endif %}
{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
<form method="post" action="{{ url_for('login') }}"><input type="hidden" name="next" value="{{ next_url }}">
<label for="username">Usuario</label><input id="username" name="username" autocomplete="username" value="{{ request.form.get('username', '') }}" required autofocus><label for="password">Contraseña</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Iniciar sesión</button></form><p class="hint">Encomienda Jireh · acceso protegido</p></main></body></html>"""


@app.before_request
def require_admin_session():
    if request.endpoint in {"login", "logout"}:
        return None
    if session.get("jireh_admin") is True:
        if session.get("jireh_role") == "staff":
            user = db.session.get(models.TeamUser, session.get("jireh_user_id"))
            if user and user.active and user.credential_version == session.get("user_credential_version"):
                db.session.commit()
                return None
            session.clear()
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
    # Login credentials are sent without a CSRF token; all state-changing authenticated routes remain protected.
    if request.endpoint == "login":
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
    if request.endpoint in {"monitor_activity", "static_files"}:
        return response
    try:
        if request.endpoint == "login" and response.status_code == 429:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(timespec="seconds")
            already_reported = db.session.scalar(
                select(models.WebActivity.id).where(
                    models.WebActivity.event_type == "login_blocked",
                    models.WebActivity.remote_addr == (request.remote_addr or "desconocida"),
                    models.WebActivity.created_at >= cutoff,
                ).limit(1)
            )
            if already_reported:
                return response
            event_type = "login_blocked"
        elif request.endpoint == "login" and request.method == "POST":
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
            username=session.get("jireh_username", "anonimo"),
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
    notice = "Los datos de administración se actualizaron. Inicia sesión con tu usuario y clave nuevos." if request.args.get("changed") == "1" else None
    status = 200
    if request.method == "POST":
        now = datetime.now(timezone.utc)
        username = request.form.get("username", "").strip().lower()[:80]
        lock = db.session.get(models.LoginLock, username) if username else None
        if lock and lock.locked_until:
            try:
                expires = datetime.fromisoformat(lock.locked_until)
            except ValueError:
                expires = now
            if expires > now:
                retry_after = max(1, int((expires - now).total_seconds()))
                response = app.make_response(render_template_string(
                    LOGIN_PAGE, error="Usuario bloqueado por demasiados intentos. Intenta de nuevo en unos minutos.",
                    notice=None, next_url="/"
                ))
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
                response.headers["Cache-Control"] = "no-store"
                return response
            lock.failed_attempts = 0
            lock.locked_until = ""
            db.session.commit()
        submitted = request.form.get("password", "")
        auth_config = load_auth_config()
        admin_username = configured_admin_username(auth_config)
        stored_hash = auth_config.get("admin_password_hash")
        if stored_hash:
            admin_matches = check_password_hash(stored_hash, submitted)
        else:
            configured_password = os.environ.get("JIREH_ADMIN_PASSWORD", ADMIN_PASSWORD)
            admin_matches = bool(configured_password) and hmac.compare_digest(submitted.encode("utf-8"), configured_password.encode("utf-8"))
        master_matches = bool(MASTER_PASSWORD) and hmac.compare_digest(submitted.encode("utf-8"), MASTER_PASSWORD.encode("utf-8"))
        team_user = db.session.scalar(select(models.TeamUser).where(models.TeamUser.username == username, models.TeamUser.active.is_(True))) if username != admin_username else None
        staff_matches = bool(team_user) and check_password_hash(team_user.password_hash, submitted)
        if (username == admin_username and (admin_matches or master_matches)) or staff_matches:
            if lock:
                db.session.delete(lock)
                db.session.commit()
            session.clear()
            session["jireh_admin"] = True
            session["jireh_role"] = "admin" if username == admin_username else "staff"
            session["jireh_username"] = admin_username if username == admin_username else team_user.username
            if staff_matches:
                session["jireh_user_id"] = team_user.id
                session["user_credential_version"] = team_user.credential_version
            session["jireh_master"] = master_matches
            if master_matches:
                session["master_auth_tag"] = master_auth_tag()
            session["auth_version"] = int(auth_config.get("auth_version", 0))
            session.permanent = True
            return redirect(next_url)
        if username:
            if lock is None:
                lock = models.LoginLock(username=username, failed_attempts=0, locked_until="")
                db.session.add(lock)
            lock.failed_attempts += 1
            if lock.failed_attempts >= 5:
                lock.locked_until = (now + timedelta(minutes=15)).isoformat(timespec="seconds")
                db.session.commit()
                error = "Usuario bloqueado por demasiados intentos. Intenta de nuevo en unos minutos."
                status = 429
            else:
                db.session.commit()
                error = "El usuario o la clave no son correctos. Intenta de nuevo."
                status = 401
        else:
            error = "Ingresa tu usuario y contraseña."
            status = 400
    return render_template_string(LOGIN_PAGE, error=error, notice=notice, next_url=next_url), status


CHANGE_PASSWORD_PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Acceso administrador · Encomienda Jireh</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f1f4f1;color:#26352e;font:16px Arial,sans-serif}
.card{width:min(92vw,480px);background:white;border-radius:24px;padding:38px;box-shadow:0 18px 55px #16352b20}.brand{color:#087f62;font-size:25px;margin:0 0 8px}
p{color:#708077;line-height:1.5}label{display:block;font-weight:700;margin:16px 0 8px}input{width:100%;padding:13px;border:1px solid #cbd7d1;border-radius:12px;font-size:16px}
button,.back{display:inline-block;margin-top:20px;padding:13px 18px;border:0;border-radius:12px;background:#087f62;color:white;text-decoration:none;font-size:16px;font-weight:700;cursor:pointer}.error{padding:11px 13px;border-radius:10px;background:#fff0ed;color:#a53727}
</style></head><body><main class="card"><h1 class="brand">Acceso administrador</h1><p>Personaliza el usuario administrador y, si quieres, cambia también la clave. La clave maestra permanece privada y no se modifica aquí.</p>
{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token }}"><label for="admin_username">Usuario administrador</label><input id="admin_username" name="admin_username" value="{{ admin_username }}" minlength="3" maxlength="40" pattern="[a-zA-Z0-9._-]{3,40}" autocomplete="username" required>
<label for="current_password">Confirma tu clave actual</label><input id="current_password" name="current_password" type="password" autocomplete="current-password" required>
<label for="new_password">Nueva clave (opcional)</label><input id="new_password" name="new_password" type="password" minlength="12" autocomplete="new-password">
<label for="confirm_password">Confirma la nueva clave</label><input id="confirm_password" name="confirm_password" type="password" minlength="12" autocomplete="new-password">
<button type="submit">Guardar acceso</button></form><a class="back" href="/">Volver a Encomienda Jireh</a></main></body></html>"""


@app.route("/clave", methods=["GET", "POST"])
def change_admin_password():
    if session.get("jireh_role", "admin") != "admin":
        abort(403)
    error = None
    status = 200
    auth_config = load_auth_config()
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        stored_hash = auth_config.get("admin_password_hash")
        if session.get("jireh_master") is True:
            current_matches = bool(MASTER_PASSWORD) and hmac.compare_digest(current_password.encode("utf-8"), MASTER_PASSWORD.encode("utf-8"))
        elif stored_hash:
            current_matches = check_password_hash(stored_hash, current_password)
        else:
            configured_password = os.environ.get("JIREH_ADMIN_PASSWORD", ADMIN_PASSWORD)
            current_matches = bool(configured_password) and hmac.compare_digest(current_password.encode("utf-8"), configured_password.encode("utf-8"))
        new_username = request.form.get("admin_username", "").strip().lower()
        current_username = configured_admin_username(auth_config)
        new_password = request.form.get("new_password", "")
        confirmation = request.form.get("confirm_password", "")
        changing_password = bool(new_password or confirmation)
        if not current_matches:
            error, status = "La clave actual no es correcta.", 403
        elif not re.fullmatch(r"[a-z0-9._-]{3,40}", new_username):
            error, status = "El usuario debe tener entre 3 y 40 caracteres: letras, números, punto, guion o guion bajo.", 400
        elif new_username != current_username and db.session.scalar(select(models.TeamUser.id).where(models.TeamUser.username == new_username)):
            error, status = "Ese usuario ya está asignado a una cuenta del equipo.", 409
        elif not changing_password and new_username == current_username:
            error, status = "Cambia el usuario o escribe una clave nueva.", 400
        elif changing_password and len(new_password) < 12:
            error, status = "La nueva clave debe tener al menos 12 caracteres.", 400
        elif changing_password and new_password != confirmation:
            error, status = "Las claves nuevas no coinciden.", 400
        elif changing_password and MASTER_PASSWORD and hmac.compare_digest(new_password.encode("utf-8"), MASTER_PASSWORD.encode("utf-8")):
            error, status = "La clave de acceso debe ser distinta a la clave maestra.", 400
        else:
            auth_config["admin_username"] = new_username
            if changing_password:
                auth_config["admin_password_hash"] = generate_password_hash(new_password, method="pbkdf2:sha256:600000")
            auth_config["auth_version"] = int(auth_config.get("auth_version", 0)) + 1
            save_auth_config(auth_config)
            session.clear()
            return redirect(url_for("login", changed="1"))
    response = app.make_response(render_template_string(CHANGE_PASSWORD_PAGE, error=error, csrf_token=ensure_csrf_token(), admin_username=configured_admin_username(auth_config)))
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/mi-clave", methods=["GET", "POST"])
def change_own_password():
    if session.get("jireh_role") != "staff":
        return redirect(url_for("change_admin_password"))
    user = db.session.get(models.TeamUser, session.get("jireh_user_id"))
    if not user or not user.active:
        session.clear()
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not check_password_hash(user.password_hash, current): error = "La contraseña actual no es correcta."
        elif len(new) < 12: error = "La contraseña nueva debe tener al menos 12 caracteres."
        elif new != confirm: error = "Las contraseñas nuevas no coinciden."
        else:
            user.password_hash = generate_password_hash(new, method="pbkdf2:sha256:600000")
            user.credential_version += 1
            db.session.commit()
            session.clear()
            return redirect(url_for("login", changed="1"))
    page = """<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="csrf-token" content="{{ csrf_token }}"><title>Cambiar contraseña</title><style>body{font:16px Arial;background:#f1f4f1;display:grid;place-items:center;min-height:100vh;color:#26352e}.box{background:white;padding:32px;border-radius:18px;width:min(90vw,480px)}input,button{display:block;width:100%;box-sizing:border-box;padding:13px;margin:12px 0;border:1px solid #ccd7d1;border-radius:9px;font:inherit}button{background:#087f62;color:white}</style><main class="box"><h1>Cambiar mi contraseña</h1>{% if error %}<p role="alert">{{ error }}</p>{% endif %}<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token }}"><input name="current_password" type="password" placeholder="Contraseña actual" required><input name="new_password" type="password" placeholder="Nueva (12 caracteres mínimo)" minlength="12" required><input name="confirm_password" type="password" placeholder="Confirmar nueva contraseña" minlength="12" required><button>Guardar</button></form><a href="/">Volver a la app</a></main></html>"""
    return render_template_string(page, error=error, csrf_token=ensure_csrf_token())


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    page = (BASE_DIR / "index.html").read_text(encoding="utf-8")
    marker = '<small class="footer-caption">Encomienda Jireh · versión web</small>'
    if session.get("jireh_role") == "admin":
        links = '<a class="side-action" href="/clave" aria-label="Cambiar usuario y clave administrador">🔐 Usuario y clave admin</a><a class="side-action" href="/usuarios" aria-label="Administrar usuarios">👥 Usuarios del equipo</a>'
    else:
        links = '<a class="side-action" href="/mi-clave" aria-label="Cambiar mi contraseña">🔐 Cambiar mi contraseña</a>'
    page = page.replace(marker, links + marker, 1)
    csrf_token = ensure_csrf_token()
    logout_form = '<form action="/logout" method="post" style="margin:0">'
    secured_logout_form = logout_form + '<input type="hidden" name="csrf_token" value="' + csrf_token + '">'
    page = page.replace(logout_form, secured_logout_form, 1)
    csrf_script = (
        '<meta name="csrf-token" content="' + csrf_token + '">'
        '<script>window.JIREH_ROLE="' + session.get("jireh_role", "admin") + '";</script>'
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
    if session.get("jireh_role", "admin") != "admin":
        return jsonify({"error": "Solo administración puede restaurar la base completa."}), 403
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("revision"), int) or body["revision"] < 0:
        return jsonify({"error": "Se requiere una revisión válida de la base de datos."}), 400
    try:
        state = replace_state(body, body["revision"], actor=session.get("jireh_username", "admin"))
    except RevisionConflict as error:
        return jsonify({"error": "Los datos cambiaron desde otra sesión. Recarga la app para evitar sobrescribir cambios.", "revision": error.current}), 409
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("No se pudo guardar la transacción SQL")
        return jsonify({"error": "No se pudo guardar la transacción. La base de datos conservó el estado anterior."}), 500
    return jsonify(state)


@app.post("/api/shipments")
def create_shipment():
    return _save_record_response("shipment", request.get_json(silent=True), None)

@app.put("/api/shipments/<int:record_id>")
def update_shipment(record_id):
    body = request.get_json(silent=True) or {}
    version = body.pop("version", None)
    return _save_record_response("shipment", body, record_id, version)

@app.delete("/api/shipments/<int:record_id>")
def remove_shipment(record_id):
    return _delete_record_response("shipment", record_id)

@app.post("/api/costs")
def create_cost():
    return _save_record_response("cost", request.get_json(silent=True), None)

@app.put("/api/costs/<int:record_id>")
def update_cost(record_id):
    body = request.get_json(silent=True) or {}
    version = body.pop("version", None)
    return _save_record_response("cost", body, record_id, version)

@app.delete("/api/costs/<int:record_id>")
def remove_cost(record_id):
    return _delete_record_response("cost", record_id)

def _save_record_response(kind, body, record_id, version=None):
    if record_id is not None and (not isinstance(version, int) or version < 1):
        return jsonify({"error": "Falta la versión actual del registro."}), 400
    try:
        saved = save_record(kind, body, session.get("jireh_username", "admin"), version, record_id)
        return jsonify(saved), 201 if record_id is None else 200
    except RecordConflict as error:
        return jsonify({"error": "Otra sesión modificó este registro. Recarga los datos y revisa el cambio antes de volver a guardarlo.", "version": error.current}), 409
    except RecordNotFound as error:
        return jsonify({"error": str(error)}), 404
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        db.session.rollback()
        app.logger.exception("No se pudo guardar el registro")
        return jsonify({"error": "No se pudo guardar. El registro conserva sus datos anteriores."}), 500

def _delete_record_response(kind, record_id):
    body = request.get_json(silent=True) or {}
    version = body.get("version")
    if not isinstance(version, int) or version < 1:
        return jsonify({"error": "Falta la versión actual del registro."}), 400
    try:
        delete_record(kind, record_id, version, session.get("jireh_username", "admin"))
        return jsonify({"ok": True})
    except RecordConflict as error:
        return jsonify({"error": "Otra sesión modificó este registro. No se eliminó.", "version": error.current}), 409
    except Exception:
        db.session.rollback()
        app.logger.exception("No se pudo eliminar el registro")
        return jsonify({"error": "No se pudo eliminar el registro."}), 500

@app.get("/api/audit")
def read_audit():
    rows = db.session.scalars(select(models.DatabaseAudit).order_by(models.DatabaseAudit.revision.desc()).limit(100)).all()
    return jsonify({"events": [{"revision": x.revision, "changed_at": x.changed_at, "actor": x.actor, "action": x.action, "record_type": x.record_type, "record_id": x.record_id} for x in rows]})

@app.post("/api/users")
def create_team_user():
    if session.get("jireh_role") != "admin":
        return jsonify({"error": "Solo administración puede crear usuarios."}), 403
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip().lower()
    display = str(body.get("displayName", "")).strip()
    password = str(body.get("password", ""))
    if not re.fullmatch(r"[a-z0-9._-]{3,40}", username):
        return jsonify({"error": "Usuario: usa 3–40 caracteres (letras, números, punto, guion o guion bajo)."}), 400
    if username == configured_admin_username():
        return jsonify({"error": "Ese nombre está reservado para la cuenta administradora."}), 409
    if len(display) < 2 or len(display) > 100:
        return jsonify({"error": "El nombre debe tener entre 2 y 100 caracteres."}), 400
    if len(password) < 12:
        return jsonify({"error": "La contraseña debe tener al menos 12 caracteres."}), 400
    if db.session.scalar(select(models.TeamUser.id).where(models.TeamUser.username == username)):
        return jsonify({"error": "Ese usuario ya existe."}), 409
    user = models.TeamUser(username=username, display_name=display, password_hash=generate_password_hash(password, method="pbkdf2:sha256:600000"))
    db.session.add(user)
    db.session.commit()
    return jsonify({"id": user.id, "username": user.username, "displayName": user.display_name, "active": user.active}), 201

@app.get("/api/users")
def list_team_users():
    if session.get("jireh_role") != "admin":
        return jsonify({"error": "Solo administración puede ver usuarios."}), 403
    rows = db.session.scalars(select(models.TeamUser).order_by(models.TeamUser.username)).all()
    return jsonify({"users": [{"id": x.id, "username": x.username, "displayName": x.display_name, "active": x.active} for x in rows]})

@app.patch("/api/users/<int:user_id>")
def update_team_user(user_id):
    if session.get("jireh_role") != "admin":
        return jsonify({"error": "Solo administración puede administrar usuarios."}), 403
    user = db.session.get(models.TeamUser, user_id)
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404
    body = request.get_json(silent=True) or {}
    if "active" in body:
        user.active = bool(body["active"])
    if "password" in body:
        password = str(body["password"])
        if len(password) < 12:
            return jsonify({"error": "La contraseña debe tener al menos 12 caracteres."}), 400
        user.password_hash = generate_password_hash(password, method="pbkdf2:sha256:600000")
        user.credential_version += 1
    db.session.commit()
    return jsonify({"ok": True})

@app.get("/usuarios")
def manage_users():
    if session.get("jireh_role") != "admin":
        abort(403)
    return render_template("team_users.html", csrf_token=ensure_csrf_token())

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
