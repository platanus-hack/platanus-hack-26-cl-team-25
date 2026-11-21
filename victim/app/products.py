from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query

from . import db

router = APIRouter()

PAGE_SIZE = 10
ORDERINGS = {"name": "name ASC, id ASC", "price": "price ASC, id ASC", "newest": "id DESC"}


@router.get("/api/products")
def list_products(
    q: Optional[str] = Query(None, max_length=80),
    category: Optional[Literal["audio", "cables", "storage", "accessories"]] = None,
    sort: Literal["name", "price", "newest"] = "name",
    page: int = Query(1, ge=1, le=1000),
):
    conds = []
    params = []
    if q:
        conds.append("(name LIKE '%" + q + "%' OR category LIKE '" + q + "')")
    if category:
        conds.append("category = ?")
        params.append(category)
    where = " AND ".join(conds) if conds else "1 = 1"
    total = db.fetch_one("SELECT COUNT(*) AS n FROM products WHERE " + where, params)["n"]
    items = db.fetch(
        "SELECT id, name, category, price, description FROM products WHERE " + where
        + " ORDER BY " + ORDERINGS[sort] + " LIMIT ? OFFSET ?",
        params + [PAGE_SIZE, (page - 1) * PAGE_SIZE],
    )
    return {"items": items, "page": page, "total": total}


@router.get("/api/products/{product_id}")
def get_product(product_id: int):
    row = db.fetch_one("SELECT id, name, category, price, description FROM products WHERE id = ?", (product_id,))
    if not row:
        raise HTTPException(404, "not found")
    return row
