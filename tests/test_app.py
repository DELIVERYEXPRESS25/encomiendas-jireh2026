import re

import pytest
from sqlalchemy import delete, select

import app as app_module
from app import app
from extensions import db
from models import DatabaseAudit, DatabaseMeta, Payment, Shipment, ShipmentItem, TravelCost, WebActivity

TEST_ADMIN_PASSWORD = "test-admin-only"
MASTER_KEY = "test-master-only"


def csrf_token(client, page="/"):
    response = client.get(page)
    html = response.get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not match:
        match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    assert match, f"No CSRF token found in {page}"
    return match.group(1)


def post_with_csrf(client, path, data, token_page=None):
    token = csrf_token(client, token_page or path)
    return client.post(path, data={**data, "csrf_token": token})


def put_state_with_csrf(client, payload):
    token = csrf_token(client, "/")
    return client.put("/api/state", json=payload, headers={"X-CSRF-Token": token})


@pytest.fixture(autouse=True)
def test_credentials(monkeypatch):
    monkeypatch.setattr(app_module, "ADMIN_PASSWORD", TEST_ADMIN_PASSWORD)
    monkeypatch.setattr(app_module, "MASTER_PASSWORD", MASTER_KEY)
    monkeypatch.delenv("JIREH_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("JIREH_MASTER_PASSWORD", raising=False)


@pytest.fixture(scope="module", autouse=True)
def apply_migrations():
    result = app.test_cli_runner().invoke(args=["db", "upgrade", "--directory", "alembic"])
    assert result.exit_code == 0, result.output


@pytest.fixture(autouse=True)
def clean_database():
    with app.app_context():
        for model in (ShipmentItem, Payment, DatabaseAudit, Shipment, TravelCost, WebActivity):
            db.session.execute(delete(model))
        meta = db.session.get(DatabaseMeta, 1)
        if meta is None:
            db.session.add(DatabaseMeta(singleton=1, revision=0))
        else:
            meta.revision = 0
        db.session.commit()
    yield
    with app.app_context():
        db.session.rollback()


@pytest.fixture
def client():
    app.config.update(TESTING=True)
    test_client = app.test_client()
    response = post_with_csrf(test_client, "/login", {"password": TEST_ADMIN_PASSWORD, "next": "/"})
    assert response.status_code == 302
    return test_client


def valid_payload(revision=0):
    return {
        "revision": revision,
        "shipments": [{
            "id": 1,
            "code": "JIR-TEST-001",
            "date": "2026-10-28",
            "sender": "Remitente de prueba",
            "receiver": "Destinatario de prueba",
            "items": [{"description": "Caja", "type": "producto", "qty": 1, "lbs": 2, "value": 10, "amount": 10}],
            "weight": 2,
            "subtotal": 10,
            "postage": 2,
            "total": 12,
            "paid": 0,
            "status": "Pendiente",
            "payments": [],
        }],
        "costs": [],
    }


def test_login_protects_application_and_data_routes():
    unauthenticated = app.test_client()
    page = unauthenticated.get("/")
    assert page.status_code == 302
    assert page.headers["Location"].startswith("/login")
    assert unauthenticated.get("/api/state").status_code == 401

    rejected = post_with_csrf(unauthenticated, "/login", {"password": "incorrecta"})
    assert rejected.status_code == 401
    assert "no es correcta" in rejected.get_data(as_text=True)

    accepted = post_with_csrf(unauthenticated, "/login", {"password": TEST_ADMIN_PASSWORD})
    assert accepted.status_code == 302
    assert unauthenticated.get("/api/state").status_code == 200
    assert post_with_csrf(unauthenticated, "/logout", {}, token_page="/").status_code == 302
    assert unauthenticated.get("/api/state").status_code == 401


def test_admin_password_can_be_overridden_with_environment(monkeypatch):
    monkeypatch.setenv("JIREH_ADMIN_PASSWORD", "ClavePersonal-MuySegura")
    configured_client = app.test_client()
    assert post_with_csrf(configured_client, "/login", {"password": TEST_ADMIN_PASSWORD}).status_code == 401
    assert post_with_csrf(configured_client, "/login", {"password": "ClavePersonal-MuySegura"}).status_code == 302


def test_master_key_can_manage_shared_key_without_exposing_master(monkeypatch, tmp_path):
    auth_config_path = tmp_path / "auth-config.json"
    monkeypatch.setattr(app_module, "AUTH_CONFIG_PATH", auth_config_path)

    owner = app.test_client()
    other_owner_session = app.test_client()
    assert post_with_csrf(owner, "/login", {"password": MASTER_KEY}).status_code == 302
    assert post_with_csrf(other_owner_session, "/login", {"password": MASTER_KEY}).status_code == 302
    page = owner.get("/").get_data(as_text=True)
    assert "/clave" in page
    assert MASTER_KEY not in page
    assert MASTER_KEY.encode() not in owner.get("/clave").data

    regular_user = app.test_client()
    assert post_with_csrf(regular_user, "/login", {"password": TEST_ADMIN_PASSWORD}).status_code == 302
    assert regular_user.get("/clave").status_code == 200
    assert "clave actual" in regular_user.get("/clave").get_data(as_text=True).lower()

    changed = post_with_csrf(owner, "/clave", {
        "current_password": MASTER_KEY,
        "new_password": "ClaveNuevaSegura2026",
        "confirm_password": "ClaveNuevaSegura2026",
    })
    assert changed.status_code == 302
    stored = auth_config_path.read_text(encoding="utf-8")
    assert "ClaveNuevaSegura2026" not in stored
    assert MASTER_KEY not in stored
    assert other_owner_session.get("/api/state").status_code == 401

    old_key = app.test_client()
    assert post_with_csrf(old_key, "/login", {"password": TEST_ADMIN_PASSWORD}).status_code == 401
    new_key = app.test_client()
    assert post_with_csrf(new_key, "/login", {"password": "ClaveNuevaSegura2026"}).status_code == 302
    master_still_works = app.test_client()
    assert post_with_csrf(master_still_works, "/login", {"password": MASTER_KEY}).status_code == 302


def test_regular_user_can_change_shared_password(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "AUTH_CONFIG_PATH", tmp_path / "auth-config.json")
    regular_user = app.test_client()
    assert post_with_csrf(regular_user, "/login", {"password": TEST_ADMIN_PASSWORD}).status_code == 302
    assert regular_user.get("/").status_code == 200

    changed = post_with_csrf(regular_user, "/clave", {
        "current_password": TEST_ADMIN_PASSWORD,
        "new_password": "ClaveDeUsuarioNueva",
        "confirm_password": "ClaveDeUsuarioNueva",
    })
    assert changed.status_code == 302
    assert regular_user.get(changed.headers["Location"]).status_code == 200
    assert "se actualizó" in regular_user.get(changed.headers["Location"]).get_data(as_text=True)
    assert post_with_csrf(app.test_client(), "/login", {"password": TEST_ADMIN_PASSWORD}).status_code == 401
    assert post_with_csrf(app.test_client(), "/login", {"password": "ClaveDeUsuarioNueva"}).status_code == 302
    assert post_with_csrf(app.test_client(), "/login", {"password": MASTER_KEY}).status_code == 302


def test_changing_master_configuration_revokes_old_master_sessions(monkeypatch):
    owner = app.test_client()
    assert post_with_csrf(owner, "/login", {"password": MASTER_KEY}).status_code == 302
    assert owner.get("/api/state").status_code == 200

    monkeypatch.setattr(app_module, "MASTER_PASSWORD", "master-nueva-test")
    assert owner.get("/api/state").status_code == 401

    new_owner = app.test_client()
    assert post_with_csrf(new_owner, "/login", {"password": "master-nueva-test"}).status_code == 302
    assert new_owner.get("/clave").status_code == 200


def test_health_and_existing_html_are_served(client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.get_json()["status"] == "ok"
    assert health.get_json()["integrity"] == "ok"

    page = client.get("/")
    assert page.status_code == 200
    assert b"Encomienda Jireh" in page.data
    assert b"Descargar respaldo JSON" in page.data
    assert b"Restaurar desde JSON" in page.data
    assert "solo se descargan cuando tú lo solicitas".encode("utf-8") in page.data
    assert "respaldos JSON periódicos".encode("utf-8") not in page.data


def test_state_save_read_and_relational_rows(client):
    saved = put_state_with_csrf(client, valid_payload())
    assert saved.status_code == 200
    assert saved.get_json()["revision"] == 1

    state = client.get("/api/state").get_json()
    assert state["revision"] == 1
    assert state["shipments"][0]["code"] == "JIR-TEST-001"
    assert state["shipments"][0]["items"][0]["description"] == "Caja"

    with app.app_context():
        assert db.session.scalar(select(db.func.count()).select_from(Shipment)) == 1
        assert db.session.scalar(select(db.func.count()).select_from(ShipmentItem)) == 1
        assert db.session.scalar(select(db.func.count()).select_from(DatabaseAudit)) == 1


def test_validation_and_stale_revision_are_rejected(client):
    invalid = valid_payload()
    invalid["shipments"][0]["subtotal"] = 11
    rejected = put_state_with_csrf(client, invalid)
    assert rejected.status_code == 400

    assert put_state_with_csrf(client, valid_payload()).status_code == 200
    stale = put_state_with_csrf(client, valid_payload(revision=0))
    assert stale.status_code == 409
    assert stale.get_json()["revision"] == 1
