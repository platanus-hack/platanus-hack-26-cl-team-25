from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import auth, db

router = APIRouter()

COLUMNS = "id, user_id, status, total, note, shipping_address, created_at"


class Line(BaseModel):
    product_id: int = Field(ge=1)
    qty: int = Field(ge=1, le=99)


class NewOrder(BaseModel):
    note: Optional[str] = Field(None, max_length=200)
    items: List[Line] = Field(min_length=1)


def lines(order_id):
    return db.fetch(
        "SELECT oi.product_id, p.name, oi.qty, oi.unit_price FROM order_items oi "
        "JOIN products p ON p.id = oi.product_id WHERE oi.order_id = ? ORDER BY oi.id",
        (order_id,),
    )


def full(row):
    row["items"] = lines(row["id"])
    return row


@router.get("/api/orders")
def list_orders(authorization: str = Header(None)):
    ident = auth.current(authorization)
    rows = db.fetch("SELECT " + COLUMNS + " FROM orders WHERE user_id = ? ORDER BY id", (ident.uid,))
    return {"items": [full(r) for r in rows]}


@router.post("/api/orders", status_code=201)
def create_order(body: NewOrder, authorization: str = Header(None)):
    ident = auth.current(authorization)
    user = db.fetch_one("SELECT address FROM users WHERE id = ?", (ident.uid,))
    if not user:
        raise HTTPException(401, "unauthorized")
    conn = db.connect()
    try:
        priced = []
        total = 0
        for line in body.items:
            prod = conn.execute("SELECT id, price FROM products WHERE id = ?", (line.product_id,)).fetchone()
            if not prod:
                raise HTTPException(422, "unknown product")
            priced.append((prod["id"], line.qty, prod["price"]))
            total += prod["price"] * line.qty
        cur = conn.execute(
            "INSERT INTO orders (user_id, status, total, note, shipping_address, created_at) VALUES (?, 'new', ?, ?, ?, ?)",
            (ident.uid, total, body.note or "", user["address"], db.stamp()),
        )
        oid = cur.lastrowid
        for pid, qty, price in priced:
            conn.execute(
                "INSERT INTO order_items (order_id, product_id, qty, unit_price) VALUES (?, ?, ?, ?)",
                (oid, pid, qty, price),
            )
        conn.commit()
    finally:
        conn.close()
    return full(db.fetch_one("SELECT " + COLUMNS + " FROM orders WHERE id = ?", (oid,)))


@router.get("/api/orders/{order_id}")
def get_order(order_id: int, authorization: str = Header(None)):
    auth.current(authorization)
    row = db.fetch_one("SELECT " + COLUMNS + " FROM orders WHERE id = ?", (order_id,))
    if not row:
        raise HTTPException(404, "not found")
    return full(row)


@router.get("/api/orders/{order_id}/invoice")
def invoice(order_id: int, authorization: str = Header(None)):
    auth.current(authorization)
    row = db.fetch_one(
        "SELECT o.id, o.total, o.note, o.shipping_address, o.created_at, u.name, u.email "
        "FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?",
        (order_id,),
    )
    if not row:
        raise HTTPException(404, "not found")
    out = [
        "TIENDA - FACTURA #%d" % row["id"],
        "Fecha: %s" % row["created_at"],
        "Cliente: %s <%s>" % (row["name"], row["email"]),
        "Despacho: %s" % row["shipping_address"],
        "",
    ]
    for it in lines(order_id):
        out.append("%3d x %-32s %8d" % (it["qty"], it["name"], it["unit_price"] * it["qty"]))
    out.append("")
    out.append("TOTAL: %d" % row["total"])
    if row["note"]:
        out.append("Nota: %s" % row["note"])
    return PlainTextResponse("\n".join(out) + "\n")


@router.get("/api/admin/orders")
def admin_orders(authorization: str = Header(None)):
    ident = auth.current(authorization)
    if ident.role != "admin":
        raise HTTPException(403, "forbidden")
    rows = db.fetch("SELECT " + COLUMNS + " FROM orders ORDER BY id")
    return {"items": rows}
