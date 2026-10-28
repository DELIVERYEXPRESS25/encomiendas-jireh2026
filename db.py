"""Relational persistence services backed by Flask-SQLAlchemy."""
from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import OperationalError

from extensions import db
from models import DatabaseAudit, DatabaseMeta, Payment, Shipment, ShipmentItem, TravelCost


def cents(value: Any, field: str) -> int:
    try:
        amount = Decimal(str(value if value is not None else 0))
        if not amount.is_finite() or amount < 0:
            raise ValueError
        return int((amount * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f"El campo {field} debe ser un monto no negativo válido.") from None


def money(value: int) -> float:
    return float(Decimal(value) / 100)


def number(value: Any, field: str, *, minimum: float = 0) -> float:
    try:
        result = float(value if value is not None else minimum)
        if not (result >= minimum and result < float("inf")):
            raise ValueError
        return result
    except (ValueError, TypeError, OverflowError):
        raise ValueError(f"El campo {field} tiene un valor inválido.") from None


def text(record: dict[str, Any], key: str, *, required: bool = False, default: str = "", max_length: int = 2000) -> str:
    value = record.get(key, default)
    if value is None:
        value = default
    if not isinstance(value, str):
        value = str(value)
    value = value.strip() if required else value
    if required and not value:
        raise ValueError(f"Falta el campo obligatorio {key}.")
    if len(value) > max_length:
        raise ValueError(f"El campo {key} supera el máximo de {max_length} caracteres.")
    return value


def valid_date(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 10:
        raise ValueError(f"El campo {field} debe tener formato AAAA-MM-DD.")
    try:
        from datetime import date
        date.fromisoformat(value)
    except ValueError:
        raise ValueError(f"El campo {field} no es una fecha válida.") from None
    return value


def json_object(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def parse_extra(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


SHIPMENT_FIELDS = {
    "id", "code", "date", "sender", "senderPhone", "receiver", "receiverPhone", "address",
    "destination", "items", "weight", "subtotal", "total", "paid", "remaining", "status",
    "payment", "payments", "postagePlace", "postage", "note",
}
ITEM_FIELDS = {"description", "type", "qty", "lbs", "weight", "value", "amount"}
PAYMENT_FIELDS = {"date", "amount", "type"}
COST_FIELDS = {"id", "date", "category", "amount", "concept", "note"}


def normalize_state(payload: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(payload, dict):
        raise ValueError("El cuerpo debe ser un objeto JSON.")
    shipments, costs = payload.get("shipments"), payload.get("costs")
    if not isinstance(shipments, list) or not isinstance(costs, list):
        raise ValueError("El cuerpo debe contener listas de encomiendas y costos.")
    if len(shipments) > 100_000 or len(costs) > 100_000:
        raise ValueError("El respaldo supera el límite de registros permitido.")
    clean_shipments: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    seen_codes: set[str] = set()
    for raw in shipments:
        if not isinstance(raw, dict):
            raise ValueError("Cada encomienda debe ser un objeto JSON.")
        try:
            shipment_id = int(raw.get("id"))
            if shipment_id <= 0 or shipment_id in seen_ids:
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            raise ValueError("Cada encomienda necesita un ID numérico único y positivo.") from None
        seen_ids.add(shipment_id)
        code = text(raw, "code", required=True, max_length=40)
        if code.casefold() in seen_codes:
            raise ValueError(f"El código {code} está repetido.")
        seen_codes.add(code.casefold())
        items_raw = raw.get("items", [])
        payments_raw = raw.get("payments", [])
        if not isinstance(items_raw, list) or not isinstance(payments_raw, list):
            raise ValueError(f"Artículos y pagos de {code} deben ser listas.")
        items: list[dict[str, Any]] = []
        for item in items_raw:
            if not isinstance(item, dict):
                raise ValueError(f"Hay un artículo inválido en {code}.")
            qty = number(item.get("qty", 1), "cantidad", minimum=0.000001)
            lbs = number(item.get("lbs", item.get("weight", 0)), "peso")
            value_cents = cents(item.get("value", 0), "valor unitario")
            if item.get("amount") is not None:
                amount_cents = cents(item["amount"], "importe del artículo")
            else:
                amount_cents = int((Decimal(str(qty)) * Decimal(value_cents)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            items.append({
                "description": text(item, "description", required=True, max_length=500),
                "type": text(item, "type", default="producto", max_length=60),
                "qty": qty, "lbs": lbs, "value_cents": value_cents, "amount_cents": amount_cents,
                "extra": {k: v for k, v in item.items() if k not in ITEM_FIELDS},
            })
        payments: list[dict[str, Any]] = []
        payment_sum = 0
        for payment in payments_raw:
            if not isinstance(payment, dict):
                raise ValueError(f"Hay un abono inválido en {code}.")
            amount_cents = cents(payment.get("amount"), "abono")
            if amount_cents <= 0:
                raise ValueError(f"El abono de {code} debe ser mayor que cero.")
            payment_sum += amount_cents
            payments.append({
                "date": valid_date(payment.get("date"), "fecha de abono"),
                "amount_cents": amount_cents,
                "method": text(payment, "type", max_length=80),
                "extra": {k: v for k, v in payment.items() if k not in PAYMENT_FIELDS},
            })
        declared_paid = cents(raw.get("paid", 0), "total abonado")
        if not payments and declared_paid:
            payments.append({
                "date": valid_date(raw.get("date"), "fecha de encomienda"),
                "amount_cents": declared_paid,
                "method": text(raw, "payment", max_length=80),
                "extra": {"migrated_legacy_payment": True},
            })
            payment_sum = declared_paid
        elif payments and payment_sum != declared_paid:
            raise ValueError(f"Los abonos de {code} no coinciden con el total abonado del registro.")
        date = valid_date(raw.get("date"), "fecha de encomienda")
        subtotal_cents = cents(raw.get("subtotal", 0), "subtotal")
        if sum(item["amount_cents"] for item in items) != subtotal_cents:
            raise ValueError(f"El subtotal de {code} no coincide con la suma de sus artículos.")
        postage_cents = cents(raw.get("postage", max(0, number(raw.get("total", 0), "total") - number(raw.get("subtotal", 0), "subtotal"))), "correo externo")
        total_cents = cents(raw.get("total", money(subtotal_cents + postage_cents)), "total")
        if total_cents != subtotal_cents + postage_cents:
            raise ValueError(f"El total de {code} debe coincidir con el subtotal más el correo externo.")
        if payment_sum > total_cents:
            raise ValueError(f"Los abonos de {code} superan el total.")
        status = text(raw, "status", default="Pendiente", max_length=30)
        if status not in {"Pendiente", "Abono", "Pagado", "Cancelado"}:
            raise ValueError(f"Estado de encomienda no reconocido en {code}.")
        clean_shipments.append({
            "id": shipment_id, "code": code, "date": date,
            "sender": text(raw, "sender", required=True), "senderPhone": text(raw, "senderPhone", max_length=80),
            "receiver": text(raw, "receiver", required=True), "receiverPhone": text(raw, "receiverPhone", max_length=80),
            "address": text(raw, "address", max_length=1000), "destination": text(raw, "destination", default="Sin asignar", max_length=200),
            "items": items,
            "weight": number(raw.get("weight", sum(x["lbs"] * x["qty"] for x in items)), "peso total"),
            "subtotal_cents": subtotal_cents, "postage_cents": postage_cents, "total_cents": total_cents,
            "paid_cents": payment_sum, "remaining_cents": total_cents - payment_sum,
            "status": "Pagado" if total_cents > 0 and total_cents == payment_sum else ("Abono" if payment_sum else status),
            "payment": text(raw, "payment", max_length=80), "postagePlace": text(raw, "postagePlace", max_length=200),
            "note": text(raw, "note", max_length=4000), "payments": payments,
            "extra": {k: v for k, v in raw.items() if k not in SHIPMENT_FIELDS},
        })
    clean_costs: list[dict[str, Any]] = []
    for raw in costs:
        if not isinstance(raw, dict):
            raise ValueError("Cada costo debe ser un objeto JSON.")
        clean_costs.append({
            "id": raw.get("id"), "date": valid_date(raw.get("date"), "fecha de costo"),
            "category": text(raw, "category", required=True, max_length=120),
            "amount_cents": cents(raw.get("amount"), "monto del costo"),
            "concept": text(raw, "concept", required=True, max_length=500),
            "note": text(raw, "note", max_length=4000),
            "extra": {k: v for k, v in raw.items() if k not in COST_FIELDS},
        })
        if clean_costs[-1]["amount_cents"] <= 0:
            raise ValueError("El monto de cada costo debe ser mayor que cero.")
    return clean_shipments, clean_costs


def get_state() -> dict[str, Any]:
    meta = db.session.get(DatabaseMeta, 1)
    if meta is None:
        meta = DatabaseMeta(singleton=1, revision=0)
        db.session.add(meta)
        db.session.flush()
    shipments: list[dict[str, Any]] = []
    rows = db.session.scalars(select(Shipment).order_by(Shipment.shipment_date.desc(), Shipment.id.desc())).all()
    for row in rows:
        items = []
        for item in row.items:
            obj = {"description": item.description, "type": item.item_type, "qty": item.quantity, "lbs": item.weight_lbs, "value": money(item.unit_value_cents), "amount": money(item.amount_cents)}
            obj.update(parse_extra(item.extra_json))
            items.append(obj)
        payments = []
        for payment in row.payments:
            obj = {"date": payment.paid_on, "amount": money(payment.amount_cents), "type": payment.payment_method}
            obj.update(parse_extra(payment.extra_json))
            payments.append(obj)
        paid_cents = sum(payment.amount_cents for payment in row.payments)
        obj = {"id": row.id, "code": row.code, "date": row.shipment_date, "sender": row.sender,
               "senderPhone": row.sender_phone, "receiver": row.receiver, "receiverPhone": row.receiver_phone,
               "address": row.address, "destination": row.destination, "items": items, "weight": row.weight_lbs,
               "subtotal": money(row.subtotal_cents), "postage": money(row.postage_cents), "total": money(row.total_cents),
               "paid": money(paid_cents), "remaining": money(row.total_cents-paid_cents), "status": row.status,
               "payment": row.payment_method, "payments": payments, "postagePlace": row.postage_place, "note": row.note}
        obj.update(parse_extra(row.extra_json))
        shipments.append(obj)
    cost_rows = db.session.scalars(select(TravelCost).order_by(TravelCost.cost_date.desc(), TravelCost.id.desc())).all()
    costs = []
    for row in cost_rows:
        obj = {"id": row.id, "date": row.cost_date, "category": row.category, "amount": money(row.amount_cents), "concept": row.concept, "note": row.note}
        obj.update(parse_extra(row.extra_json))
        costs.append(obj)
    return {"revision": meta.revision, "shipments": shipments, "costs": costs}


def replace_state(payload: Any, expected_revision: int) -> dict[str, Any]:
    shipments, costs = normalize_state(payload)
    canonical = json.dumps({"shipments": shipments, "costs": costs}, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    try:
        with db.session.begin():
            meta = db.session.execute(select(DatabaseMeta).where(DatabaseMeta.singleton == 1).with_for_update()).scalar_one_or_none()
            if meta is None:
                meta = DatabaseMeta(singleton=1, revision=0)
                db.session.add(meta)
                db.session.flush()
            current = meta.revision
            if current != expected_revision:
                raise RevisionConflict(current)
            db.session.execute(delete(ShipmentItem))
            db.session.execute(delete(Payment))
            db.session.execute(delete(Shipment))
            db.session.execute(delete(TravelCost))
            for shipment in shipments:
                row = Shipment(id=shipment["id"], code=shipment["code"], shipment_date=shipment["date"], sender=shipment["sender"], sender_phone=shipment["senderPhone"], receiver=shipment["receiver"], receiver_phone=shipment["receiverPhone"], address=shipment["address"], destination=shipment["destination"], weight_lbs=shipment["weight"], subtotal_cents=shipment["subtotal_cents"], postage_cents=shipment["postage_cents"], total_cents=shipment["total_cents"], status=shipment["status"], payment_method=shipment["payment"], postage_place=shipment["postagePlace"], note=shipment["note"], extra_json=json_object(shipment["extra"]))
                row.items = [ShipmentItem(position=pos, description=item["description"], item_type=item["type"], quantity=item["qty"], weight_lbs=item["lbs"], unit_value_cents=item["value_cents"], amount_cents=item["amount_cents"], extra_json=json_object(item["extra"])) for pos, item in enumerate(shipment["items"])]
                row.payments = [Payment(paid_on=payment["date"], amount_cents=payment["amount_cents"], payment_method=payment["method"], extra_json=json_object(payment["extra"])) for payment in shipment["payments"]]
                db.session.add(row)
            for cost in costs:
                db.session.add(TravelCost(cost_date=cost["date"], category=cost["category"], amount_cents=cost["amount_cents"], concept=cost["concept"], note=cost["note"], extra_json=json_object(cost["extra"])))
            revision = current + 1
            meta.revision = revision
            meta.updated_at = func.current_timestamp()
            db.session.add(DatabaseAudit(revision=revision, shipment_count=len(shipments), cost_count=len(costs), snapshot_sha256=digest))
        return get_state()
    except Exception:
        db.session.rollback()
        raise


class RevisionConflict(Exception):
    def __init__(self, current: int):
        self.current = current
