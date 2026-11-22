// Presentation excerpt of dashboard/tests/fixtures/real_run.jsonl.
const recordedRequests = [
  {
    "id": "ac96a507",
    "method": "GET",
    "path": "/api/products",
    "classification": "clean",
    "route": "prod",
    "verdict": null,
    "status": 200,
    "ms": 7.1,
    "input": {
      "query": {
        "category": "cables",
        "sort": "price"
      },
      "example": true
    }
  },
  {
    "id": "9f8f49bf",
    "method": "GET",
    "path": "/api/products",
    "classification": "suspect",
    "route": "shadow_l1",
    "verdict": "oracle",
    "status": 200,
    "ms": 124.0,
    "incident": {
      "id": "inc-0001",
      "kind": "sqli",
      "oracle": "sql",
      "runs": 3,
      "reproducible": true,
      "scope": "param",
      "ttl": 3600,
      "file": "victim/app/products.py",
      "diff": [
        "@@ -20,7 +20,9 @@ def list_products(",
        "     conds = []",
        "     params = []",
        "     if q:",
        "-        conds.append(\"(name LIKE '%\" + q + \"%' OR category LIKE '\" + q + \"')\")",
        "+        conds.append(\"(name LIKE ? OR category LIKE ?)\")",
        "+        params.append(\"%\" + q + \"%\")",
        "+        params.append(q)",
        "     if category:",
        "         conds.append(\"category = ?\")",
        "         params.append(category)"
      ],
      "gates": {
        "policy": true,
        "properties": true,
        "poc": true,
        "tests": true,
        "legit": true
      },
      "sha": "10c3e7cc",
      "outcome": "patched",
      "verified": true
    },
    "input": {
      "query": {
        "q": "zzzzzz'…"
      },
      "note": "Fragmento de la captura. El valor de q tiene 17 caracteres."
    }
  },
  {
    "id": "926831a8",
    "method": "POST",
    "path": "/api/register",
    "classification": "clean",
    "route": "prod",
    "verdict": null,
    "status": 201,
    "ms": 16.6,
    "input": {
      "body": {
        "name": "Ana Demo",
        "email": "ana@example.com",
        "password": "••••••••"
      },
      "example": true
    }
  },
  {
    "id": "5123cde6",
    "method": "GET",
    "path": "/api/files/download",
    "classification": "suspect",
    "route": "shadow_l1",
    "verdict": "oracle",
    "status": 200,
    "ms": 121.3,
    "incident": {
      "id": "inc-0002",
      "kind": "traversal",
      "oracle": "file",
      "runs": 3,
      "reproducible": true,
      "scope": "param",
      "ttl": 3600,
      "file": "victim/app/files.py",
      "diff": [
        "@@ -14,8 +14,9 @@ def static_root():",
        " ",
        " @router.get(\"/api/files/download\")",
        " def download(name: str):",
        "-    path = os.path.join(static_root(), \"manuals\", name)",
        "-    if not os.path.isfile(path):",
        "+    base = os.path.realpath(os.path.join(static_root(), \"manuals\"))",
        "+    path = os.path.realpath(os.path.join(base, name))",
        "+    if os.path.commonpath([base, path]) != base or not os.path.isfile(path):",
        "         raise HTTPException(404, \"not found\")",
        "     return FileResponse(path)",
        " "
      ],
      "gates": {
        "policy": true,
        "properties": true,
        "poc": true,
        "tests": true,
        "legit": true
      },
      "sha": "69a00c0e",
      "outcome": "patched",
      "verified": true
    },
    "input": {
      "query": {
        "name": "…/hostname"
      },
      "note": "Fragmento de la captura. El valor de name tiene 36 caracteres."
    }
  },
  {
    "id": "4e6adf12",
    "method": "GET",
    "path": "/health",
    "classification": "clean",
    "route": "prod",
    "verdict": null,
    "status": 200,
    "ms": 8.1,
    "input": {
      "note": "La ruta /health no define parámetros."
    }
  },
  {
    "id": "424ac2c5",
    "method": "GET",
    "path": "/api/orders/5",
    "classification": "suspect",
    "route": "shadow_l1",
    "verdict": "oracle",
    "status": 200,
    "ms": 132.7,
    "incident": {
      "id": "inc-0003",
      "kind": "idor",
      "oracle": "owner",
      "runs": 3,
      "reproducible": true,
      "scope": "all",
      "ttl": 3600,
      "file": "victim/app/orders.py",
      "diff": [
        "@@ -75,9 +75,9 @@ def create_order(body: NewOrder, authorization: str = Header(None)):",
        " ",
        " @router.get(\"/api/orders/{order_id}\")",
        " def get_order(order_id: int, authorization: str = Header(None)):",
        "-    auth.current(authorization)",
        "+    ident = auth.current(authorization)",
        "     row = db.fetch_one(\"SELECT \" + COLUMNS + \" FROM orders WHERE id = ?\", (order_id,))",
        "-    if not row:",
        "+    if not row or (row[\"user_id\"] != ident.uid and ident.role != \"admin\"):",
        "         raise HTTPException(404, \"not found\")",
        "     return full(row)",
        " "
      ],
      "gates": {
        "policy": true,
        "properties": true,
        "poc": true,
        "tests": true,
        "legit": true
      },
      "sha": "4b143e17",
      "outcome": "patched",
      "verified": true
    },
    "input": {
      "pathParams": {
        "order_id": "5"
      }
    }
  },
  {
    "id": "7c32ce8f",
    "method": "GET",
    "path": "/api/products",
    "classification": "suspect",
    "route": "prod",
    "verdict": "clean",
    "status": 200,
    "ms": 21.7,
    "input": {
      "query": {
        "q": "Hub USB"
      },
      "example": true
    }
  },
  {
    "id": "f7507d1d",
    "method": "GET",
    "path": "/api/products",
    "classification": "clean",
    "route": "prod",
    "verdict": null,
    "status": 200,
    "ms": 5.6,
    "input": {
      "query": {
        "page": "2"
      },
      "example": true
    }
  },
  {
    "id": "b07d9417",
    "method": "GET",
    "path": "/api/files/download",
    "classification": "suspect",
    "route": "prod",
    "verdict": "inconclusive",
    "status": 404,
    "ms": 15.2,
    "input": {
      "query": {
        "name": "manual-v2.txt"
      },
      "example": true
    }
  }
];
