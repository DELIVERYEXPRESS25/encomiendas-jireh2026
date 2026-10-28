BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS shipments (
    id INTEGER PRIMARY KEY,
    code TEXT NOT NULL UNIQUE CHECK (length(trim(code)) BETWEEN 1 AND 40),
    shipment_date TEXT NOT NULL CHECK (date(shipment_date) IS NOT NULL),
    sender TEXT NOT NULL CHECK (length(trim(sender)) > 0),
    sender_phone TEXT NOT NULL DEFAULT '',
    receiver TEXT NOT NULL CHECK (length(trim(receiver)) > 0),
    receiver_phone TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    destination TEXT NOT NULL DEFAULT 'Sin asignar',
    weight_lbs REAL NOT NULL DEFAULT 0 CHECK (weight_lbs >= 0),
    subtotal_cents INTEGER NOT NULL CHECK (subtotal_cents >= 0),
    postage_cents INTEGER NOT NULL DEFAULT 0 CHECK (postage_cents >= 0),
    total_cents INTEGER NOT NULL CHECK (total_cents >= 0),
    status TEXT NOT NULL CHECK (status IN ('Pendiente', 'Abono', 'Pagado', 'Cancelado')),
    payment_method TEXT NOT NULL DEFAULT '',
    postage_place TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    extra_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK (total_cents = subtotal_cents + postage_cents)
);
CREATE INDEX IF NOT EXISTS idx_shipments_date ON shipments(shipment_date DESC);
CREATE INDEX IF NOT EXISTS idx_shipments_sender ON shipments(sender COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_shipments_receiver ON shipments(receiver COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS shipment_items (
    id INTEGER PRIMARY KEY,
    shipment_id INTEGER NOT NULL REFERENCES shipments(id) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position >= 0),
    description TEXT NOT NULL CHECK (length(trim(description)) > 0),
    item_type TEXT NOT NULL DEFAULT 'producto',
    quantity REAL NOT NULL DEFAULT 1 CHECK (quantity > 0),
    weight_lbs REAL NOT NULL DEFAULT 0 CHECK (weight_lbs >= 0),
    unit_value_cents INTEGER NOT NULL DEFAULT 0 CHECK (unit_value_cents >= 0),
    amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0),
    extra_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (shipment_id, position)
);
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY,
    shipment_id INTEGER NOT NULL REFERENCES shipments(id) ON DELETE CASCADE,
    paid_on TEXT NOT NULL CHECK (date(paid_on) IS NOT NULL),
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    payment_method TEXT NOT NULL DEFAULT '',
    extra_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_payments_date ON payments(paid_on DESC);
CREATE INDEX IF NOT EXISTS idx_payments_shipment ON payments(shipment_id, id);
CREATE TABLE IF NOT EXISTS travel_costs (
    id INTEGER PRIMARY KEY,
    cost_date TEXT NOT NULL CHECK (date(cost_date) IS NOT NULL),
    category TEXT NOT NULL CHECK (length(trim(category)) > 0),
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    concept TEXT NOT NULL CHECK (length(trim(concept)) > 0),
    note TEXT NOT NULL DEFAULT '',
    extra_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_travel_costs_date ON travel_costs(cost_date DESC);
CREATE TABLE IF NOT EXISTS database_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
INSERT OR IGNORE INTO database_meta(singleton, revision) VALUES (1, 0);
CREATE TABLE IF NOT EXISTS database_audit (
    revision INTEGER PRIMARY KEY CHECK (revision > 0),
    changed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    shipment_count INTEGER NOT NULL CHECK (shipment_count >= 0),
    cost_count INTEGER NOT NULL CHECK (cost_count >= 0),
    snapshot_sha256 TEXT NOT NULL CHECK (length(snapshot_sha256) = 64)
);
PRAGMA user_version = 1;
COMMIT;
