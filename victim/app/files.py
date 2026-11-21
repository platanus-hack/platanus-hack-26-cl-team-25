import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from . import db

router = APIRouter()


def static_root():
    return os.environ.get("APP_STATIC") or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")


@router.get("/api/files/download")
def download(name: str):
    path = os.path.join(static_root(), "manuals", name)
    if not os.path.isfile(path):
        raise HTTPException(404, "not found")
    return FileResponse(path)


@router.get("/api/products/{product_id}/image")
def product_image(product_id: int, file: str):
    if not db.fetch_one("SELECT id FROM products WHERE id = ?", (product_id,)):
        raise HTTPException(404, "not found")
    path = os.path.join(static_root(), "images", file)
    if not os.path.isfile(path):
        raise HTTPException(404, "not found")
    return FileResponse(path)
