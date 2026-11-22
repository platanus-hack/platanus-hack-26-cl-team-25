import sqlite3

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import auth, files, orders, products, users

app = FastAPI(title="Tienda", version="t0")
app.include_router(auth.router)
app.include_router(products.router)
app.include_router(files.router)
app.include_router(orders.router)
app.include_router(users.router)


@app.exception_handler(sqlite3.Error)
def database_error(request: Request, exc: sqlite3.Error):
    return JSONResponse({"detail": "internal error"}, status_code=500)


@app.get("/health")
def health():
    return {"ok": True}
