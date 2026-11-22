"""Policy gate (pipeline/policy.py): patches that special-case a value, reach the environment or read a
file without using the name/shape the older denylist looked for must be rejected; every hand-written good
fix must still pass."""
import os

import pytest

from pipeline import diffs, fixes, incident, policy

from .conftest import ROOT

ORDERS, FILES = "victim/app/orders.py", "victim/app/files.py"
NOT_ROW = "    if not row:\n        raise HTTPException(404, \"not found\")\n    return full(row)\n\n\n@router.get(\"/api/orders/{order_id}/invoice\")"
GET_ORDER = "    row = db.fetch_one(\"SELECT \" + COLUMNS + \" FROM orders WHERE id = ?\", (order_id,))\n"
DOWNLOAD = "    path = os.path.join(static_root(), \"manuals\", name)\n"


def _check(t0, edits):
    d = fixes.build_diff(t0, edits)
    work = diffs.copy_release(t0, os.path.dirname(t0))
    diffs.apply(d, work)
    return policy.check(d, t0, work)


def _order(cond):
    """get_order with one extra condition on its 404 branch."""
    return [(ORDERS, NOT_ROW, NOT_ROW.replace("    if not row:\n", "    if not row or %s:\n" % cond, 1))]


SPECIAL_CASES = {
    "dict-literal-get": "{12: True}.get(order_id)",
    "dict-literal-subscript": "{12: True, 0: False}[order_id if order_id == 0 else 0]",
    "set-literal-in": "order_id in {12, 31}",
    "set-intersection": "{order_id} & {12}",
    "set-method": "{12}.issuperset({order_id})",
    "list-count": "[12].count(order_id)",
    "arithmetic-truthiness": "not (order_id - 12)",
    "arithmetic-in-compare": "order_id == 6 + 6",
    "converted-constant": "str(order_id) == str(12)",
    "set-call": "order_id in set([12])",
    "walrus-binding": "order_id == (bad := 12)",
    "comprehension-binding": "any(order_id == b for b in (12, 31))",
    "lambda-default": "(lambda v, bad=12: v == bad)(order_id)",
    "backdoor-keyed-on-input": "{'letmein': 1}.get(authorization)",
    "backdoor-dict-call": "dict(letmein=1).get(authorization)",
}


@pytest.mark.parametrize("cond", list(SPECIAL_CASES.values()), ids=list(SPECIAL_CASES))
def test_value_special_casing_without_a_plain_comparison_is_rejected(t0, cond):
    ok, detail, _v = _check(t0, _order(cond))
    assert not ok and "new literal" in detail, detail


def test_special_casing_through_a_name_bound_to_a_literal_is_rejected(t0):
    edits = [(ORDERS, 'COLUMNS = "id, user_id', 'BLOCKED = {12, 31}\nCOLUMNS = "id, user_id')] + _order("order_id in BLOCKED")
    ok, detail, _v = _check(t0, edits)
    assert not ok and "new literal" in detail and "12" in detail, detail
    edits = [(ORDERS, GET_ORDER, "    bad = 12\n" + GET_ORDER)] + _order("order_id == bad")
    assert "new literal" in _check(t0, edits)[1]
    loop = "    for bad in (12, 31):\n        if order_id == bad:\n            raise HTTPException(404, \"not found\")\n"
    assert "new literal" in _check(t0, [(ORDERS, GET_ORDER, loop + GET_ORDER)])[1]


def test_match_case_on_a_new_literal_is_rejected(t0):
    edits = [(ORDERS, GET_ORDER, "    match order_id:\n        case 12 | 31:\n            raise HTTPException(404, \"not found\")\n"
                                 "        case {\"id\": 99}:\n            pass\n" + GET_ORDER)]
    ok, detail, _v = _check(t0, edits)
    assert not ok and "new literal" in detail and "12" in detail and "99" in detail, detail


DYNAMIC = {
    "getattr-on-module": "getattr(os, 'env' + 'iron')",
    "getattr-dangerous-constant": "getattr(os, 'environ')",
    "getattr-dunder": "getattr(os, '__dict__')",
    "getattr-passed-around": "list(map(getattr, [os], ['environ']))",
    "module-dict": "os.__dict__['envi' + 'ron']",
    "vars": "vars(os)",
    "dunder-import": "__import__('o' + 's')",
    "eval": "eval('1')",
    "class-walk": "().__class__.__mro__",
}


@pytest.mark.parametrize("expr", list(DYNAMIC.values()), ids=list(DYNAMIC))
def test_dynamic_access_is_rejected(t0, expr):
    ok, detail, _v = _check(t0, [(FILES, DOWNLOAD, "    leak = %s\n" % expr + DOWNLOAD)])
    assert not ok and "new use of" in detail, detail


ABSOLUTE = {
    "open-literal": ("open('/etc/hostname').read()", "open('/etc/hostname')"),
    "open-concatenated": ("open('/etc/' + name).read()", "open('/etc/')"),
    "open-joined": ("open(os.path.join('/proc/self', 'environ')).read()", "open('/proc/self')"),
    "open-fstring": ("open(f'/data/{name}').read()", "open('/data/')"),
    "open-home": ("open(os.path.expanduser('~/.ssh/id_rsa')).read()", "open('~/.ssh/id_rsa')"),
    "listdir": ("os.listdir('/srv/secrets')", "listdir('/srv/secrets')"),
}


@pytest.mark.parametrize("expr,shown", list(ABSOLUTE.values()), ids=list(ABSOLUTE))
def test_file_access_with_a_literal_absolute_path_is_rejected(t0, expr, shown):
    ok, detail, _v = _check(t0, [(FILES, DOWNLOAD, "    leak = %s\n" % expr + DOWNLOAD)])
    assert not ok and "literal absolute path: " + shown in detail, detail


def test_system_path_constant_is_rejected_even_through_a_variable(t0):
    ok, detail, _v = _check(t0, [(FILES, DOWNLOAD, "    extra = '/etc/hostname'\n    leak = open(extra).read()\n" + DOWNLOAD)])
    assert not ok and "system path: '/etc/hostname'" in detail, detail


def test_getattr_of_a_fixed_ordinary_attribute_is_allowed(t0):
    edits = [(ORDERS, NOT_ROW, NOT_ROW.replace("    if not row:\n", "    ident = auth.current(authorization)\n"
              "    if not row or (row[\"user_id\"] != ident.uid and getattr(ident, \"role\", None) != \"admin\"):\n", 1)),
             (ORDERS, "    auth.current(authorization)\n" + GET_ORDER, GET_ORDER)]
    ok, detail, _v = _check(t0, edits)
    assert ok, detail


def test_relative_and_inside_root_file_access_is_allowed(t0):
    edits = [(FILES, DOWNLOAD, "    base = os.path.realpath(os.path.join(static_root(), \"manuals\"))\n"
                               "    path = os.path.realpath(os.path.join(base, name))\n"
                               "    if os.path.commonpath([base, path]) != base or not os.path.isfile(path):\n"
                               "        raise HTTPException(404, \"not found\")\n"
                               "    with open(path, \"rb\") as fh:\n        fh.read(0)\n")]
    ok, detail, _v = _check(t0, edits)
    assert ok, detail


# ------------------------------------------------------------------ no false positives on the known-good fixes
@pytest.mark.parametrize("fix", [f for f in fixes.CATALOGUE if f.expect == "pass"], ids=lambda f: f.name)
def test_catalogue_adequate_fixes_pass_policy(t0, fix):
    ok, detail, v = _check(t0, fix.edits({}))
    assert ok and v == [], detail


@pytest.mark.parametrize("name", sorted(os.listdir(os.path.join(ROOT, "patcher", "fallbacks"))))
def test_fallback_diffs_pass_policy(t0, name):
    d = open(os.path.join(ROOT, "patcher", "fallbacks", name)).read()
    work = diffs.copy_release(t0, os.path.dirname(t0))
    diffs.apply(d, work)
    ok, detail, v = policy.check(d, t0, work)
    assert ok and v == [], detail


def test_catalogue_counts():
    """The numbers the documentation quotes: 15 inadequate fixes by rejecting gate, 3 adequate ones."""
    by = {}
    for f in fixes.CATALOGUE:
        by[f.expect] = by.get(f.expect, 0) + 1
    assert by == {"pass": 3, "policy": 7, "properties": 5, "poc": 1, "tests": 1, "legit": 1}
    assert len(os.listdir(os.path.join(ROOT, "patcher", "fallbacks"))) == 7


@pytest.mark.parametrize("fix", [f for f in fixes.CATALOGUE if f.expect not in ("pass", "policy")], ids=lambda f: f.name)
def test_fixes_meant_for_a_later_gate_are_not_stopped_by_policy(t0, fix, spec, events):
    """The selftest expects these to reach (and be rejected by) properties / poc / tests / legit."""
    inc = incident.build(events[fix.vuln_class], spec)
    ok, detail, _v = _check(t0, fix.edits(inc))
    assert ok, detail
