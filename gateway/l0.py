"""L0: stateless procedural decoys for a fixed list of scanner paths.

Content is deterministic per (path, session) so repeated probes look stable,
and contains no real secret (every value is derived from a hash).
"""
from __future__ import annotations

import hashlib
import json

SCANNER_PATHS = {
    "/.env", "/.env.local", "/.env.production", "/wp-login.php", "/wp-admin", "/xmlrpc.php",
    "/actuator", "/actuator/env", "/actuator/health", "/.git/config", "/.git/head", "/phpmyadmin",
    "/pma", "/server-status", "/config.php", "/.aws/credentials", "/.ds_store", "/backup.sql",
    "/admin.php", "/.htaccess", "/web.config", "/console",
}


def is_scanner_path(raw_path: str) -> bool:
    p = raw_path.lower()
    if len(p) > 1:
        p = p.rstrip("/")
    return p in SCANNER_PATHS or p.startswith("/wp-admin/") or p.startswith("/phpmyadmin/")


def _h(seed: str, n: int, alphabet: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> str:
    out, i = [], 0
    while len(out) < n:
        d = hashlib.sha256(f"{seed}:{i}".encode()).digest()
        out.extend(alphabet[b % len(alphabet)] for b in d)
        i += 1
    return "".join(out[:n])


def respond(raw_path: str, session: str) -> tuple[int, str, bytes]:
    """-> (status, content-type, body)"""
    p = raw_path.lower().rstrip("/") or "/"
    seed = f"{p}|{session}"
    up = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if p.startswith("/.env"):
        body = (f"APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:{_h(seed + 'k', 43)}=\n"
                f"DB_CONNECTION=mysql\nDB_HOST=10.0.{int(_h(seed, 2, '0123456789'))}.12\nDB_PORT=3306\n"
                f"DB_DATABASE=shop\nDB_USERNAME=shop_app\nDB_PASSWORD={_h(seed + 'p', 18)}\n"
                f"REDIS_HOST=cache.internal\nMAIL_PASSWORD={_h(seed + 'm', 16)}\n"
                f"AWS_ACCESS_KEY_ID=AKIA{_h(seed + 'a', 16, up)}\nAWS_SECRET_ACCESS_KEY={_h(seed + 's', 40)}\n")
        return 200, "text/plain", body.encode()
    if p == "/.aws/credentials":
        body = (f"[default]\naws_access_key_id = AKIA{_h(seed + 'a', 16, up)}\n"
                f"aws_secret_access_key = {_h(seed + 's', 40)}\nregion = us-east-1\n")
        return 200, "text/plain", body.encode()
    if p.startswith("/actuator"):
        if p.endswith("/health"):
            return 200, "application/json", b'{"status":"UP"}'
        doc = {"activeProfiles": ["prod"], "propertySources": [
            {"name": "systemEnvironment", "properties": {
                "SPRING_DATASOURCE_URL": {"value": "jdbc:postgresql://db.internal:5432/shop"},
                "SPRING_DATASOURCE_USERNAME": {"value": "shop"},
                "SPRING_DATASOURCE_PASSWORD": {"value": "******"},
                "JWT_SECRET": {"value": _h(seed + "j", 32)}}}]}
        return 200, "application/json", json.dumps(doc).encode()
    if p.startswith("/.git"):
        if p.endswith("head"):
            return 200, "text/plain", b"ref: refs/heads/main\n"
        body = ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
                f"[remote \"origin\"]\n\turl = https://git.internal/shop/{_h(seed, 6)}.git\n"
                "\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n")
        return 200, "text/plain", body.encode()
    if p.startswith("/wp-") or p == "/xmlrpc.php":
        body = ("<!DOCTYPE html><html><head><title>Log In &lsaquo; Shop &#8212; WordPress</title></head><body class=\"login\">"
                "<form name=\"loginform\" id=\"loginform\" action=\"/wp-login.php\" method=\"post\">"
                "<p><label for=\"user_login\">Username or Email Address</label><input type=\"text\" name=\"log\" id=\"user_login\"></p>"
                "<p><label for=\"user_pass\">Password</label><input type=\"password\" name=\"pwd\" id=\"user_pass\"></p>"
                f"<input type=\"hidden\" name=\"testcookie\" value=\"1\"><input type=\"hidden\" name=\"_wpnonce\" value=\"{_h(seed, 10)}\">"
                "<p class=\"submit\"><input type=\"submit\" name=\"wp-submit\" value=\"Log In\"></p></form></body></html>")
        return 200, "text/html; charset=UTF-8", body.encode()
    if p.startswith("/phpmyadmin") or p == "/pma":
        body = ("<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body><div id=\"login_form\">"
                "<form method=\"post\" action=\"index.php\"><fieldset><legend>Log in</legend>"
                "<input type=\"text\" name=\"pma_username\"><input type=\"password\" name=\"pma_password\">"
                f"<input type=\"hidden\" name=\"token\" value=\"{_h(seed, 32)}\"></fieldset>"
                "<input value=\"Go\" type=\"submit\"></form></div></body></html>")
        return 200, "text/html; charset=utf-8", body.encode()
    if p == "/server-status":
        body = ("<html><head><title>Apache Status</title></head><body><h1>Apache Server Status</h1>"
                f"<dl><dt>Server Version: Apache/2.4.57 (Unix)</dt><dt>Total accesses: {int(_h(seed, 6, '0123456789'))}</dt></dl></body></html>")
        return 200, "text/html", body.encode()
    if p == "/backup.sql":
        body = ("-- MySQL dump 10.13\n-- Host: localhost    Database: shop\n"
                "CREATE TABLE `users` (`id` int NOT NULL AUTO_INCREMENT, `email` varchar(120), PRIMARY KEY (`id`));\n"
                f"INSERT INTO `users` VALUES (1,'admin@{_h(seed, 6)}.local');\n")
        return 200, "application/sql", body.encode()
    return 403, "text/html", b"<html><body><h1>403 Forbidden</h1></body></html>"
