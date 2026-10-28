from sqlalchemy import CheckConstraint, Index, UniqueConstraint, text

from extensions import db


class Shipment(db.Model):
    __tablename__ = "shipments"
    __table_args__ = (
        CheckConstraint("length(trim(code)) BETWEEN 1 AND 40"),
        CheckConstraint("weight_lbs >= 0"), CheckConstraint("subtotal_cents >= 0"),
        CheckConstraint("postage_cents >= 0"), CheckConstraint("total_cents >= 0"),
        CheckConstraint("status IN ('Pendiente', 'Abono', 'Pagado', 'Cancelado')"),
        CheckConstraint("total_cents = subtotal_cents + postage_cents"),
        Index("idx_shipments_date", "shipment_date"),
        Index("idx_shipments_sender", "sender"), Index("idx_shipments_receiver", "receiver"),
    )
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(40), nullable=False, unique=True)
    shipment_date = db.Column(db.String(10), nullable=False)
    sender = db.Column(db.Text, nullable=False)
    sender_phone = db.Column(db.Text, nullable=False, server_default="")
    receiver = db.Column(db.Text, nullable=False)
    receiver_phone = db.Column(db.Text, nullable=False, server_default="")
    address = db.Column(db.Text, nullable=False, server_default="")
    destination = db.Column(db.Text, nullable=False, server_default="Sin asignar")
    weight_lbs = db.Column(db.Float, nullable=False, server_default="0")
    subtotal_cents = db.Column(db.Integer, nullable=False)
    postage_cents = db.Column(db.Integer, nullable=False, server_default="0")
    total_cents = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(30), nullable=False)
    payment_method = db.Column(db.Text, nullable=False, server_default="")
    postage_place = db.Column(db.Text, nullable=False, server_default="")
    note = db.Column(db.Text, nullable=False, server_default="")
    extra_json = db.Column(db.Text, nullable=False, server_default="{}")
    created_at = db.Column(db.String(32), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    items = db.relationship("ShipmentItem", cascade="all, delete-orphan", order_by="ShipmentItem.position", passive_deletes=True)
    payments = db.relationship("Payment", cascade="all, delete-orphan", order_by="Payment.id", passive_deletes=True)


class ShipmentItem(db.Model):
    __tablename__ = "shipment_items"
    __table_args__ = (UniqueConstraint("shipment_id", "position"), CheckConstraint("position >= 0"), CheckConstraint("quantity > 0"), CheckConstraint("weight_lbs >= 0"), CheckConstraint("unit_value_cents >= 0"), CheckConstraint("amount_cents >= 0"))
    id = db.Column(db.Integer, primary_key=True)
    shipment_id = db.Column(db.Integer, db.ForeignKey("shipments.id", ondelete="CASCADE"), nullable=False)
    position = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    item_type = db.Column(db.Text, nullable=False, server_default="producto")
    quantity = db.Column(db.Float, nullable=False, server_default="1")
    weight_lbs = db.Column(db.Float, nullable=False, server_default="0")
    unit_value_cents = db.Column(db.Integer, nullable=False, server_default="0")
    amount_cents = db.Column(db.Integer, nullable=False)
    extra_json = db.Column(db.Text, nullable=False, server_default="{}")


class Payment(db.Model):
    __tablename__ = "payments"
    __table_args__ = (CheckConstraint("amount_cents > 0"), Index("idx_payments_date", "paid_on"), Index("idx_payments_shipment", "shipment_id", "id"))
    id = db.Column(db.Integer, primary_key=True)
    shipment_id = db.Column(db.Integer, db.ForeignKey("shipments.id", ondelete="CASCADE"), nullable=False)
    paid_on = db.Column(db.String(10), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    payment_method = db.Column(db.Text, nullable=False, server_default="")
    extra_json = db.Column(db.Text, nullable=False, server_default="{}")


class TravelCost(db.Model):
    __tablename__ = "travel_costs"
    __table_args__ = (CheckConstraint("amount_cents > 0"), Index("idx_travel_costs_date", "cost_date"))
    id = db.Column(db.Integer, primary_key=True)
    cost_date = db.Column(db.String(10), nullable=False)
    category = db.Column(db.Text, nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    concept = db.Column(db.Text, nullable=False)
    note = db.Column(db.Text, nullable=False, server_default="")
    extra_json = db.Column(db.Text, nullable=False, server_default="{}")


class DatabaseMeta(db.Model):
    __tablename__ = "database_meta"
    singleton = db.Column(db.Integer, primary_key=True)
    revision = db.Column(db.Integer, nullable=False, server_default="0")
    updated_at = db.Column(db.String(32), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


class DatabaseAudit(db.Model):
    __tablename__ = "database_audit"
    revision = db.Column(db.Integer, primary_key=True)
    changed_at = db.Column(db.String(32), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    shipment_count = db.Column(db.Integer, nullable=False)
    cost_count = db.Column(db.Integer, nullable=False)
    snapshot_sha256 = db.Column(db.String(64), nullable=False)
