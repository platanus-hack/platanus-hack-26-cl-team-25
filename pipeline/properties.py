"""Gate 2 — positive properties per vulnerability class (docs/plan-construccion.md §4.2).

Everything is derived from the incident (route, method, parameter, captured request),
the release's shadow profile (allowed file roots) and the seed manifest. Nothing here
names a specific endpoint. Application code only runs inside the runner.

  sqli       the executed query structure is identical under N metacharacter inputs and a
             benign value, the status does not change, and O'Brien reaches the database intact
  traversal  no file outside the allowed roots is opened for any traversal input, and every
             legitimate name that worked before (dotted names included) returns identical bytes
  idor       identity x resource matrix in the shadow harness: the owner gets 2xx with their own
             data, another seed user and a new user get 403/404, anonymous status unchanged
"""
from __future__ import annotations

import os

import sqlparse
from sqlparse import tokens as T

from . import reqs

SQL_BENIGN = ["abc", "usb hub"]
SQL_META = ["'", "''", '"', "' OR '1'='1", "') OR ('1'='1", "x' --", "x'; DROP TABLE users; --", "%' AND 1=1 --",
            "\\", "/*", "*/ --", "a' UNION SELECT NULL --", "`", "1 OR 1=1"]
ROUNDTRIP = "O'Brien"

TRAVERSAL = ["../" * 10 + "etc/hostname", "../" * 10 + "etc/passwd", "....//" * 10 + "etc/hostname",
             "..//" * 10 + "etc/hostname", "./" + "../" * 10 + "etc/hostname", "..\\" * 10 + "etc\\hostname",
             "../app/main.py", "../../app/main.py", "../../../app/main.py", "....//....//app/main.py",
             "%2e%2e/" * 10 + "etc/hostname", "..%2f" * 10 + "etc%2fhostname", ".../" * 10 + "etc/hostname",
             "../" * 10 + "proc/self/environ"]


# ------------------------------------------------------------------ helpers
def norm_sql(sql: str) -> str:
    out = []
    try:
        for t in sqlparse.parse(sql)[0].flatten():
            if t.is_whitespace:
                continue
            if t.ttype in T.Comment:
                out.append("COMMENT")
            elif t.ttype in T.Literal:
                out.append("?")
            elif t.ttype in T.Keyword:
                out.append(t.value.upper())
            else:
                out.append(t.value)
    except Exception:
        return "UNPARSABLE:" + sql
    return " ".join(out)


def structure(result: dict) -> tuple:
    return tuple(norm_sql(s["sql"]) for s in result.get("sql") or [])


def _literal_values(sql: str) -> list:
    vals = []
    try:
        for t in sqlparse.parse(sql)[0].flatten():
            if t.ttype in T.Literal.String.Single and len(t.value) >= 2:
                vals.append(t.value[1:-1].replace("''", "'"))
    except Exception:
        pass
    return vals


def roundtrips(result: dict, value: str) -> bool:
    for s in result.get("sql") or []:
        if any(isinstance(p, str) and value in p for p in s.get("params") or []):
            return True
        if any(value in v for v in _literal_values(s["sql"])):
            return True
    return False


def _short(s, n=90):
    s = str(s)
    return s if len(s) <= n else s[:n] + "..."


def template_request(inc: dict, poc: dict) -> dict:
    rq = dict((poc.get("requests") or [inc["request"]])[-1])
    rq.setdefault("headers", {})
    return rq


# ------------------------------------------------------------------ sqli
def sqli(v, inc, poc, base_dir, patched_dir):
    param, tpl = inc.get("param"), inc.get("route")
    if not param:
        return False, "cannot check: the incident has no injectable parameter"
    base = template_request(inc, poc)
    named = []
    for kind, vals in (("benign", SQL_BENIGN), ("meta", SQL_META), ("roundtrip", [ROUNDTRIP])):
        for val in vals:
            rq = reqs.set_value(base, param, val, tpl)
            rq["name"] = "%s:%s" % (kind, val)
            named.append(rq)
    res = v.run(patched_dir, {"kind": "plain", "requests": named})
    by = {r["name"]: r for r in res["results"]}
    b1, b2 = by["benign:" + SQL_BENIGN[0]], by["benign:" + SQL_BENIGN[1]]
    s0 = structure(b1)
    where = "%s %s param %s" % (inc["method"], inc["route"], param["name"])
    if not s0:
        return False, ("%s: a benign value (%r) executes no SQL statement (status %d) — the endpoint no longer "
                       "serves the request; the fix must keep the feature working" % (where, SQL_BENIGN[0], b1["status"]))
    if structure(b2) != s0:
        return False, "%s: the query structure differs between two benign values (%r, %r)" % (where, *SQL_BENIGN)
    if not roundtrips(b1, SQL_BENIGN[0]):
        # every check below would compare statements that never saw the input (e.g. only the auth lookup ran)
        return False, ("%s: a benign value (%r) never reaches an executed statement (status %d, %d statement(s)); "
                       "the endpoint must still use the parameter in its query" % (where, SQL_BENIGN[0], b1["status"], len(s0)))
    fails = []
    for val in SQL_META:
        r = by["meta:" + val]
        if r["status"] >= 500:
            fails.append("input %r -> server error %d" % (val, r["status"]))
        elif r["status"] != b1["status"]:
            fails.append("input %r handled differently (status %d, benign %d): metacharacters must be treated as "
                         "data, not refused" % (val, r["status"], b1["status"]))
        elif structure(r) != s0:
            got = structure(r)
            diff = next((g for g, w in zip(got, s0) if g != w), got[0] if got else "(no statement)")
            fails.append("input %r changed the query structure: %s" % (val, _short(diff, 140)))
    rt = by["roundtrip:" + ROUNDTRIP]
    if rt["status"] != b1["status"] or structure(rt) != s0:
        fails.append("%r is not handled like a benign value (status %d, structure %s)" %
                     (ROUNDTRIP, rt["status"], "same" if structure(rt) == s0 else "changed"))
    elif not roundtrips(rt, ROUNDTRIP):
        fails.append("%r does not reach the database intact (it was altered or stripped)" % ROUNDTRIP)
    if fails:
        return False, "%s: %s" % (where, "; ".join(fails[:4]) + (" (+%d more)" % (len(fails) - 4) if len(fails) > 4 else ""))
    return True, ("%s: query structure identical for %d metacharacter inputs (%d statement(s) each); %r reaches "
                  "the database intact" % (where, len(SQL_META), len(s0), ROUNDTRIP))


# ------------------------------------------------------------------ traversal
def _under(path: str, roots: list) -> bool:
    return any(path == r or path.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


def traversal_baseline(v, inc, poc, base_dir) -> dict:
    key = ("trav", base_dir, inc["method"], inc["route"], str(inc.get("param")))
    if key in v.cache:
        return v.cache[key]
    base = template_request(inc, poc)
    res = v.run(base_dir, {"kind": "plain", "requests": [],
                           "expand": {"param": inc["param"], "template": inc["route"], "base": base}})
    legit = [r for r in res["results"] if r["status"] == 200 and r["sha"] == r.get("expect_sha")]
    out = {"legit": [{"value": r["name"][5:], "sha": r["sha"]} for r in legit], "roots": res["roots"]}
    v.cache[key] = out
    return out


def traversal(v, inc, poc, base_dir, patched_dir):
    param, tpl = inc.get("param"), inc.get("route")
    if not param:
        return False, "cannot check: the incident has no file parameter"
    where = "%s %s param %s" % (inc["method"], inc["route"], param["name"])
    bl = traversal_baseline(v, inc, poc, base_dir)
    if not bl["legit"]:
        return False, "%s: no legitimate value found on the unpatched release; cannot check the property" % where
    base = template_request(inc, poc)
    rqs = []
    for item in bl["legit"]:
        rq = reqs.set_value(base, param, item["value"], tpl)
        rq.update(name="legit:" + item["value"], expect_sha=item["sha"])
        rqs.append(rq)
    for p in TRAVERSAL:
        rq = reqs.set_value(base, param, p, tpl)
        rq["name"] = "attack:" + p
        rqs.append(rq)
    warm = [reqs.set_value(base, param, bl["legit"][0]["value"], tpl), reqs.set_value(base, param, "zz-missing-file", tpl)]
    res = v.run(patched_dir, {"kind": "plain", "requests": rqs, "warmup": warm})
    roots = res["roots"]
    allowed = set(res.get("warm_opens") or [])
    fails, broken = [], []
    for r in res["results"]:
        outside = [o for o in r["opens"] if not _under(o, roots) and o not in allowed]
        if outside:
            fails.append("input %r opened %s (outside %s)" % (_short(r["name"].split(":", 1)[1], 50), outside[0], ", ".join(roots)))
        if r["name"].startswith("legit:") and (r["status"] != 200 or r["sha"] != r.get("expect_sha")):
            broken.append("%s (status %d)" % (r["name"][6:], r["status"]))
    if broken:
        fails.append("legitimate name(s) no longer served identically: %s" % ", ".join(broken[:5]))
    if fails:
        return False, "%s: %s" % (where, "; ".join(fails[:4]))
    dotted = [x["value"] for x in bl["legit"] if x["value"].count(".") >= 2]
    return True, ("%s: %d traversal inputs opened nothing outside %s; %d legitimate names (%d with 2+ dots%s) "
                  "return identical bytes" % (where, len(TRAVERSAL), ", ".join(roots), len(bl["legit"]), len(dotted),
                                              (", e.g. " + dotted[0]) if dotted else ""))


# ------------------------------------------------------------------ idor
def _candidate_ids(inc, manifest, poc_value) -> list:
    name = (inc.get("param") or {}).get("name") or ""
    ids = []
    ids += list((manifest.get("canaries") or {}).get(name, []))
    legit = [u["id"] for u in manifest.get("legit_users") or []]
    for table, mapping in (manifest.get("ownership") or {}).items():
        singular = table[:-1] if table.endswith("s") else table
        if name in (singular + "_id", table + "_id", "id"):
            own = [int(k) for k, o in mapping.items() if o in legit][:6]
            ids += own
    if name.startswith("user") or not ids:
        ids += legit[:4]
    if poc_value and str(poc_value).isdigit():
        ids.append(int(poc_value))
    out = []
    for i in ids:
        if i not in out:
            out.append(i)
    return out[:12]


def _as(rq, uid, role="user"):
    r = dict(rq)
    r["headers"] = reqs.clean_headers(rq.get("headers") or {}, drop_auth=True)
    r["uid"], r["role"] = uid, role
    return r


def idor_baseline(v, inc, poc, base_dir) -> dict:
    key = ("idor", base_dir, inc["method"], inc["route"], str(inc.get("param")))
    if key in v.cache:
        return v.cache[key]
    m = v.manifest(base_dir)
    param, tpl = inc["param"], inc["route"]
    base = template_request(inc, poc)
    poc_value = reqs.get_value(base, param, tpl)
    stranger = int(m.get("seed_max_uid", 0)) + 1000
    seqs = []
    for rid in _candidate_ids(inc, m, poc_value):
        seqs.append({"name": "probe:%s" % rid, "requests": [_as(reqs.set_value(base, param, rid, tpl), stranger)]})
    anon = dict(reqs.set_value(base, param, poc_value, tpl))
    anon["headers"] = reqs.clean_headers(anon.get("headers") or {}, drop_auth=True)
    anon["uid"] = None
    seqs.append({"name": "anon", "requests": [anon]})
    res = v.run(base_dir, {"kind": "harness", "sequences": seqs})
    owners = {}
    anon_status = None
    for s in res["sequences"]:
        r = s["runs"][0][-1]
        if s["name"] == "anon":
            anon_status = r["status"]
            continue
        mo = r["marker_owners"]
        if r["status"] < 300 and len(mo) == 1:
            owners[s["name"].split(":", 1)[1]] = mo[0]
    out = {"owners": owners, "anon_status": anon_status, "stranger": stranger, "manifest": m}
    v.cache[key] = out
    return out


def _anon(base, param, value, tpl):
    a = dict(reqs.set_value(base, param, value, tpl))
    a["headers"] = reqs.clean_headers(a.get("headers") or {}, drop_auth=True)
    a["uid"] = None
    return a


def idor_group(v, inc, poc, base_dir, patched_dir, gtable, where):
    """A members-scoped route (group-shared access, manifest groups/group_routes): every member of the
    group reads it exactly as before (2xx, same bytes, no oracle), a seed user outside the group and a new
    user get 403/404 with no oracle event, the admin and the anonymous caller are unchanged."""
    m = v.manifest(base_dir)
    param, tpl = inc["param"], inc["route"]
    groups = (m.get("groups") or {}).get(gtable) or {}
    admin_id = (m.get("admin") or {}).get("id")
    legit = [u["id"] for u in m.get("legit_users") or []]
    seed_max = int(m.get("seed_max_uid") or 0)
    stranger = seed_max + 1000
    everyone = sorted({u for ms in groups.values() for u in ms if isinstance(u, int) and u <= seed_max} | set(legit))
    base = template_request(inc, poc)
    plan = []
    for gid in sorted(groups, key=lambda g: (len(g), g)):
        members = [u for u in groups[gid] if u != admin_id]
        member = next((u for u in legit if u in members), members[0] if members else None)
        outsider = next((u for u in legit + everyone if u not in groups[gid] and u != admin_id), None)
        if member is None or outsider is None:
            continue
        plan.append((gid, member, outsider, set(groups[gid])))
        if len(plan) >= 4:
            break
    if len(plan) < 2:
        return False, "%s: fewer than 2 groups with a member and a non-member in the manifest; cannot build the matrix" % where

    def seqs_for(roles):
        out = []
        for gid, member, outsider, _ms in plan:
            rq = reqs.set_value(base, param, gid, tpl)
            who = {"member": member, "outsider": outsider, "new": stranger, "admin": admin_id}
            for role in roles:
                if role == "anon":
                    out.append({"name": "anon:%s:-" % gid, "requests": [_anon(base, param, gid, tpl)]})
                elif who.get(role) is not None:
                    out.append({"name": "%s:%s:%s" % (role, gid, who[role]),
                                "requests": [_as(rq, who[role], "admin" if role == "admin" else "user")]})
        return out
    before = {s["name"]: s["runs"][0][-1] for s in
              v.run(base_dir, {"kind": "harness", "sequences": seqs_for(("member", "admin", "anon"))})["sequences"]}
    usable = [p for p in plan if 200 <= before["member:%s:%s" % (p[0], p[1])]["status"] < 300
              and before["member:%s:%s" % (p[0], p[1])]["verdict"] != "oracle"]
    if len(usable) < 2:
        return False, ("%s: on the unpatched release fewer than 2 groups answer their own member with 2xx and no "
                       "oracle (%s); cannot build the matrix" % (where, ", ".join(
                           "%s=%s -> %s %s" % (param["name"], p[0], before["member:%s:%s" % (p[0], p[1])]["status"],
                                               before["member:%s:%s" % (p[0], p[1])]["verdict"]) for p in plan[:3])))
    plan = usable
    after = v.run(patched_dir, {"kind": "harness", "sequences": seqs_for(("member", "outsider", "new", "admin", "anon"))})
    members_of = {str(p[0]): p[3] for p in plan}
    fails, n_member, n_deny = [], 0, 0
    for s in after["sequences"]:
        r = s["runs"][0][-1]
        role, gid, uid = s["name"].split(":")
        if role in ("admin", "anon"):
            b = before.get(s["name"])
            if b is not None and (r["status"], r["sha"]) != (b["status"], b["sha"]):
                fails.append("%s reading %s=%s changed (status %s -> %s%s)" % (
                    "admin" if role == "admin" else "anonymous request", param["name"], gid, b["status"], r["status"],
                    ", body differs" if r["status"] == b["status"] else ""))
            continue
        foreign = [o for o in r["marker_owners"] if str(o) != uid and (role != "member" or o not in members_of[gid])]
        if role == "member":
            b = before[s["name"]]
            if not 200 <= r["status"] < 300:
                fails.append("member %s of %s=%s gets %d instead of 2xx" % (uid, param["name"], gid, r["status"]))
            elif r["verdict"] == "oracle" or foreign:
                fails.append("member %s of %s=%s receives data of user(s) outside the group %s" % (uid, param["name"],
                                                                                                    gid, foreign))
            elif r["sha"] != b["sha"]:
                fails.append("member %s of %s=%s no longer gets the same response as before" % (uid, param["name"], gid))
            else:
                n_member += 1
        else:
            who = "seed user outside the group" if role == "outsider" else "new user"
            if r["status"] not in (403, 404):
                fails.append("%s %s reading %s=%s gets %d (want 403/404)" % (who, uid, param["name"], gid, r["status"]))
            elif foreign or r["verdict"] == "oracle":
                fails.append("%s %s reading %s=%s still receives the members' data" % (who, uid, param["name"], gid))
            else:
                n_deny += 1
    if fails:
        return False, "%s: %s" % (where, "; ".join(fails[:4]) + (" (+%d more)" % (len(fails) - 4) if len(fails) > 4 else ""))
    return True, ("%s: members-scoped matrix over %d groups: %d member reads unchanged (2xx, same bytes, no oracle), "
                  "%d non-member reads (seed and new users) get 403/404 with no oracle; admin and anonymous unchanged"
                  % (where, len(plan), n_member, n_deny))


def idor(v, inc, poc, base_dir, patched_dir):
    param, tpl = inc.get("param"), inc.get("route")
    if not param:
        return False, "cannot check: the incident has no resource parameter"
    where = "%s %s param %s" % (inc["method"], inc["route"], param["name"])
    gtable = (v.manifest(base_dir).get("group_routes") or {}).get(param.get("name"))
    if gtable and param.get("in") == "path" and ("{%s}" % param["name"]) in (tpl or ""):
        return idor_group(v, inc, poc, base_dir, patched_dir, gtable, where)
    bl = idor_baseline(v, inc, poc, base_dir)
    m = bl["manifest"]
    admin_id = (m.get("admin") or {}).get("id")
    trusted = [u["id"] for u in m.get("legit_users") or []]
    owners = {k: o for k, o in bl["owners"].items() if o != admin_id}
    if len(owners) < 2:
        return False, "%s: fewer than 2 resources with an identifiable owner on the unpatched release; cannot build the matrix" % where
    base = template_request(inc, poc)
    seqs = []
    for rid, owner in owners.items():
        rq = reqs.set_value(base, param, rid, tpl)
        other = next((t for t in trusted if t != owner), None)
        seqs.append({"name": "owner:%s:%s" % (rid, owner), "requests": [_as(rq, owner)]})
        if other is not None:
            seqs.append({"name": "other:%s:%s" % (rid, other), "requests": [_as(rq, other)]})
        seqs.append({"name": "new:%s:%s" % (rid, bl["stranger"]), "requests": [_as(rq, bl["stranger"])]})
    anon = dict(reqs.set_value(base, param, next(iter(owners)), tpl))
    anon["headers"] = reqs.clean_headers(anon.get("headers") or {}, drop_auth=True)
    anon["uid"] = None
    seqs.append({"name": "anon", "requests": [anon]})
    res = v.run(patched_dir, {"kind": "harness", "sequences": seqs})
    fails = []
    n_owner = n_deny = 0
    for s in res["sequences"]:
        r = s["runs"][0][-1]
        if s["name"] == "anon":
            if r["status"] != bl["anon_status"]:
                fails.append("anonymous request now gets %d (was %s)" % (r["status"], bl["anon_status"]))
            continue
        role, rid, uid = s["name"].split(":")
        foreign = [o for o in r["marker_owners"] if str(o) != uid]
        if role == "owner":
            if not 200 <= r["status"] < 300:
                fails.append("owner %s of %s=%s gets %d instead of 2xx" % (uid, param["name"], rid, r["status"]))
            elif foreign:
                fails.append("owner %s of %s=%s also receives data of user(s) %s" % (uid, param["name"], rid, foreign))
            else:
                n_owner += 1
        else:
            who = "seed user" if role == "other" else "new user"
            if r["status"] not in (403, 404):
                fails.append("%s %s reading %s=%s gets %d (want 403/404)" % (who, uid, param["name"], rid, r["status"]))
            elif foreign or r["verdict"] == "oracle":
                fails.append("%s %s reading %s=%s still receives another user's data" % (who, uid, param["name"], rid))
            else:
                n_deny += 1
    if fails:
        return False, "%s: %s" % (where, "; ".join(fails[:4]) + (" (+%d more)" % (len(fails) - 4) if len(fails) > 4 else ""))
    return True, ("%s: identity x resource matrix over %d resources: %d owner reads get 2xx with only their data, "
                  "%d non-owner reads (seed and new users) get 403/404; anonymous status %s unchanged"
                  % (where, len(owners), n_owner, n_deny, bl["anon_status"]))


CHECKS = {"sqli": sqli, "traversal": traversal, "idor": idor}


def check(v, inc, poc, base_dir, patched_dir):
    fn = CHECKS.get(inc.get("vuln_class"))
    if fn is None:
        return False, "no positive property is defined for class %r: cannot validate a patch" % inc.get("vuln_class")
    return fn(v, inc, poc, base_dir, patched_dir)
