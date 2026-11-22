import dataclasses

import pytest
from anticipate import core, report

SRC = '''/* a { brace in a comment */
static int helper(int x)
{
    const char *s = "}{";
    return x + 1;
}

AP_DECLARE(int) target(char *p, unsigned int f)
{
    if (f) { return helper(1); }
    return 0;
}
'''


def test_extract_function_skips_braces_in_comments_and_strings():
    fn = core.extract_function(SRC, "static int helper(int x)")
    assert fn.endswith("return x + 1;\n}") and '"}{"' in fn
    assert core.extract_function(SRC, "AP_DECLARE(int) target(char *p, unsigned int f)").count("{") == 2
    assert core.extract_function(SRC, "int missing(void)") is None


def test_parse_findings_takes_last_valid_block():
    text = 'x ```json\n{"findings": [{"file": "a"}]}\n``` y ```json\n{"findings": [{"file": "b"}]}\n```'
    assert core.parse_findings(text) == [{"file": "b"}]
    assert core.parse_findings("no json here") == []


def test_hunks_and_enclosing_functions():
    diff = "--- a/f.c\n+++ b/f.c\n@@ -9,3 +9,4 @@ AP_DECLARE(int) target(char *p, unsigned int f)\n x\n+y\n"
    hs = core.hunks(diff)
    assert hs[0]["file"] == "f.c" and hs[0]["start"] == 9 and hs[0]["function"] == "target"
    assert core.enclosing_functions(SRC, hs) == {("f.c", "target")}


def test_prompt_omits_advisory_id_and_fixed_version_but_names_product_and_file():
    """Guards exactly this: the strings `CVE`, `41773` and the fixed version are absent from the prompt. It does
    not make the review blind: the prompt names the product and version, the area, the class and the file."""
    t = core.load_target("apache-httpd-2.4.49")
    p = core.render_prompt(t)
    assert "CVE" not in p and t["fixed_ref"] not in p and "41773" not in p
    assert "server/util.c" in p and t["name"] in p and t["vulnerable_ref"] in p


def test_review_carries_the_patched_files_as_a_declared_field():
    assert "patched" in {f.name for f in dataclasses.fields(core.Review)}
    assert core.Review(ok=True).patched == {}


def _result():
    t = {k: v for k, v in core.load_target("apache-httpd-2.4.49").items() if not k.startswith("_")}
    row = {"kind": "legit", "in": "/a", "ret": 1, "out": "/a", "expect": "ret=1 /a", "ok": True}
    chk = {"compiled": True, "results": [row], "passed": 1, "total": 1}
    return {"target": t, "started": 0, "seconds": 1.0, "review": {"model": "m", "findings": []},
            "diffs": {"suggested": "", "official": ""}, "checks": {"vulnerable": chk, "suggested": chk, "official": chk},
            "equivalence": {"comparable": True, "same": 1, "total": 1, "differ": []}, "localisation": {}}


@pytest.mark.parametrize("render", [report.markdown, report.html_page])
def test_report_says_what_the_model_knew_and_what_the_score_means(render):
    text = render(_result())
    assert "Qué sabía el modelo" in text and "Qué significa 1 de 1" in text
    assert "el modelo nunca los ve" in text and "datos de entrenamiento" in text
    assert "No demuestra equivalencia de comportamiento de Apache HTTP Server" in text
    assert "sin conocer el aviso" not in text and "no el aviso" not in text and "**no** el aviso" not in text


@pytest.mark.docker
def test_check_separates_released_and_fixed_versions():
    t = core.load_target("apache-httpd-2.4.49")
    repo = core.fetch(t)
    vuln = core.run_check(t, core.show(repo, t["vulnerable_ref"], t["check"]["file"]), "v")
    fixed = core.run_check(t, core.show(repo, t["fixed_ref"], t["check"]["file"]), "f")
    assert vuln["compiled"] and fixed["compiled"]
    assert vuln["passed"] < vuln["total"] and fixed["passed"] == fixed["total"]
    assert all(r["ok"] for r in vuln["results"] if r["kind"] == "legit")
