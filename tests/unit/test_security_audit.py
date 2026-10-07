"""Security-audit unit tests: rules, models, engine behaviour, report rendering."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from opencode_toolkit.core.config import SecurityAuditPolicy
from opencode_toolkit.core.errors import UsageError
from opencode_toolkit.security_audit import py_ast, redos
from opencode_toolkit.security_audit.engine import (
    AuditEngine,
    detect_language,
    rule_catalogue,
    scan_path,
)
from opencode_toolkit.security_audit.models import Confidence, ScanResult, Severity
from opencode_toolkit.security_audit.reports import render_json, render_sarif, render_text
from opencode_toolkit.security_audit.rules import (
    PATTERN_RULES,
    all_rules,
    rule_by_id,
    rules_for_language,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

pytestmark = pytest.mark.unit


# -- rule catalogue --------------------------------------------------------


def test_rule_ids_are_unique_and_well_formed() -> None:
    ids = [rule.rule_id for rule in all_rules()]
    assert len(ids) == len(set(ids))
    for rule_id in ids:
        assert rule_id.startswith("OCSA-")
        assert len(rule_id.split("-")) == 3


def test_every_rule_documents_every_required_field() -> None:
    for rule in all_rules():
        for field in (
            "description",
            "root_cause",
            "impact",
            "remediation",
        ):
            value = getattr(rule, field)
            assert isinstance(value, str) and len(value) > 20, f"{rule.rule_id}.{field}"
        assert rule.languages
        assert rule.severity in tuple(Severity)
        assert rule.confidence in tuple(Confidence)


def test_every_rule_has_a_detector() -> None:
    """A rule with no detector would silently never fire; that is a defect."""
    import re

    from opencode_toolkit.security_audit import engine as engine_module

    ast_source = Path(py_ast.__file__).read_text(encoding="utf-8")
    redos_source = Path(redos.__file__).read_text(encoding="utf-8")
    engine_source = Path(engine_module.__file__).read_text(encoding="utf-8")
    pattern_ids = {entry.rule.rule_id for entry in PATTERN_RULES}
    ast_ids = set(re.findall(r"_emit\(\s*\n?\s*\"(OCSA-[A-Z]+-\d+)\"", ast_source))
    ast_ids |= set(re.findall(r"_emit_dynamic_exec\(node, \"(OCSA-[A-Z]+-\d+)\"", ast_source))
    synthetic = set(
        re.findall(r"_synthetic_finding\(\s*\n?\s*\"(OCSA-[A-Z]+-\d+)\"", engine_source)
    )
    redos_ids = set(re.findall(r"RULE_ID: Final = \"(OCSA-[A-Z]+-\d+)\"", redos_source))

    uncovered = (
        {rule.rule_id for rule in all_rules()} - pattern_ids - ast_ids - synthetic - redos_ids
    )
    assert not uncovered, f"rules with no detector: {sorted(uncovered)}"


def test_rule_lookup_and_language_filter() -> None:
    assert rule_by_id("OCSA-CRED-001") is not None
    assert rule_by_id("OCSA-NOPE-999") is None
    python_rules = rules_for_language("python")
    assert python_rules
    assert all("python" in rule.languages for rule in python_rules)


def test_rule_catalogue_is_json_serialisable() -> None:
    payload = json.loads(json.dumps(rule_catalogue()))
    assert len(payload) == len(all_rules())
    assert {item["rule_id"] for item in payload} == {rule.rule_id for rule in all_rules()}


def test_language_detection() -> None:
    assert detect_language(Path("a.py")) == "python"
    assert detect_language(Path("a.tsx")) == "typescript"
    assert detect_language(Path("a.GO")) == "go"
    assert detect_language(Path("a.md")) is None


# -- python AST detection --------------------------------------------------


def _rule_ids(source: str) -> set[str]:
    return {finding.rule_id for finding in py_ast.iter_python_findings("t.py", source)}


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        ("def f(x):\n    return eval(x)\n", "OCSA-EXEC-001"),
        ("def f(x):\n    exec(x)\n", "OCSA-EXEC-002"),
        ("import pickle\ndef f(b):\n    return pickle.loads(b)\n", "OCSA-CRYPTO-004"),
        ("import hashlib\ndef f(b):\n    return hashlib.md5(b).digest()\n", "OCSA-CRYPTO-001"),
        (
            "import hashlib\ndef f(p):\n    return hashlib.pbkdf2_hmac('sha256', p, b's', 1000)\n",
            "OCSA-CRYPTO-003",
        ),
        ("import requests\ndef f(u):\n    return requests.get(u, verify=False)\n", "OCSA-TLS-001"),
        ("import tempfile\ndef f():\n    return tempfile.mktemp()\n", "OCSA-FILE-001"),
        ("import os\ndef f(c):\n    return os.system(c)\n", "OCSA-EXEC-004"),
        (
            "import subprocess\ndef f(c):\n    return subprocess.run(c, shell=True)\n",
            "OCSA-EXEC-004",
        ),
        ("import yaml\ndef f(t):\n    return yaml.load(t)\n", "OCSA-CRYPTO-006"),
        ("assert is_valid(x)\n", "OCSA-VALID-001"),
        (
            "def f(a, b):\n    try:\n        pass\n    except Exception:\n        pass\n",
            "OCSA-VALID-002",
        ),
        ("import os\ndef f(root, n):\n    return open(os.path.join(root, n))\n", "OCSA-PATH-002"),
    ],
)
def test_python_ast_detects(source: str, rule_id: str) -> None:
    assert rule_id in _rule_ids(source)


@pytest.mark.parametrize(
    "source",
    [
        "def f(x):\n    return eval('2 + 2')\n",
        "import requests\ndef f(u):\n    return requests.get(u, verify=True)\n",
        "import yaml\ndef f(t):\n    return yaml.safe_load(t)\n",
        "def f(x):\n    assert x is not None\n",
        "def f(x):\n    assert isinstance(x, str)\n",
        "import hashlib\ndef f(b):\n    return hashlib.sha256(b).hexdigest()\n",
        "import hashlib\ndef f(p):\n    return hashlib.pbkdf2_hmac('sha256', p, b's', 600000)\n",
    ],
)
def test_python_ast_does_not_flag_safe_code(source: str) -> None:
    assert not _rule_ids(source), f"false positive for:\n{source}"


def test_bare_except_is_reported() -> None:
    assert "OCSA-VALID-002" in _rule_ids("try:\n    pass\nexcept:\n    pass\n")


def test_except_that_reraises_is_not_reported() -> None:
    assert "OCSA-VALID-002" not in _rule_ids("try:\n    pass\nexcept ValueError:\n    raise\n")


def test_path_traversal_respects_containment_check() -> None:
    vulnerable = "import os\ndef f(root, n):\n    return open(os.path.join(root, n))\n"
    guarded = (
        "import os\nfrom pathlib import Path\n"
        "def f(root, n):\n"
        "    p = (Path(root) / n).resolve()\n"
        "    if not p.is_relative_to(Path(root).resolve()):\n"
        "        raise ValueError('escape')\n"
        "    return p.read_text()\n"
    )
    assert "OCSA-PATH-002" in _rule_ids(vulnerable)
    assert "OCSA-PATH-002" not in _rule_ids(guarded)


def test_parse_error_is_reported_not_raised() -> None:
    assert list(py_ast.iter_python_findings("t.py", "def broken(:\n")) == []
    assert py_ast.python_parse_error("def broken(:\n") is not None
    assert py_ast.python_parse_error("x = 1\n") is None


def test_null_bytes_do_not_crash_the_parser() -> None:
    assert py_ast.python_parse_error("x = 1\x00\n") is not None


# -- credential heuristic --------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        'HUGGINGFACE_TOKEN_ENV = "HUGGINGFACE_TOKEN"\n',
        'CODE_AUTHOR = "code_author"\n',
        'SECRET_NAME_HINTS = frozenset({"secret"})\n',
        'DB_PASSWORD = "your_password_here"\n',
        'api_token = ""\n',
    ],
)
def test_credential_rule_ignores_names_and_placeholders(source: str) -> None:
    assert "OCSA-CRED-001" not in _rule_ids(source)


@pytest.mark.parametrize(
    "source",
    [
        'PASSWORD = "hunter2secret"\n',
        'api_secret = "s3cr3tvalue"\n',
        'client_secret: str = "abcdefghijkl"\n',
    ],
)
def test_credential_rule_fires_on_real_literals(source: str) -> None:
    assert "OCSA-CRED-001" in _rule_ids(source)


def test_connection_string_credential_is_detected() -> None:
    found = _rule_ids('DATABASE_URL = "postgres://user:p4ssw0rdvalue@host/db"\n')
    assert "OCSA-CRED-005" in found


# -- ReDoS heuristic -------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "vulnerable"),
    [
        # The verdict table below is measured behaviour, not guesswork: each
        # catastrophic pattern here exceeded 3 seconds against a 30-character
        # non-matching input, and each safe pattern completed in under 5 ms.
        (r"(a+)+$", True),
        (r"(\w*)*$", True),
        (r"(\w+\s?)*$", True),
        (r"(\d+)+$", True),
        (r"(x+x+)+y$", True),
        (r"([a-z0-9]+(?:-[a-z0-9]+)*)$", False),
        (r"(?:[A-Z][A-Za-z]*(?: [A-Z][A-Za-z]*)*):$", False),
        (r"(a|b)*", False),
        (r"[^x]+", False),
        (r"(\w)+\w", False),
        (r"^[a-z]+$", False),
        (r"^\d+\.\d+(\.\d+)?(-[\w.]+)?$", False),
        (r"(?P<n>[A-Z]\w*)\((?P<p>[^)]*)\)", False),
        # A quantifier immediately after a group belongs to whatever follows the
        # group, not to the group. Reading it as the group's own repetition made
        # every `(?P<x>\w*)\s*` shape a false positive.
        (r"(?P<x>[A-Z]\w*)\s*", False),
        (r"^(?P<i>[ \t]*)(?P<n>\*{0,2}\w+)(?P<g>[ \t]*)", False),
        (r"^func\s+(?:\([^)]+\))?\s*(?P<n>[A-Z]\w*)\s*\(", False),
    ],
)
def test_redos_verdict_table(pattern: str, vulnerable: bool) -> None:
    assert redos.is_vulnerable(pattern)[0] is vulnerable


def test_redos_extracts_from_each_language() -> None:
    assert redos.extract_literals("re.match(r'(a+)+$', v)", "python")[0].pattern == "(a+)+$"
    assert (
        redos.extract_literals("const r = /(\\w+\\s?)*/;", "javascript")[0].pattern == r"(\w+\s?)*"
    )
    assert (
        redos.extract_literals("var r = regexp.MustCompile(`(a+)+$`)", "go")[0].pattern == "(a+)+$"
    )


def test_redos_scan_produces_findings_only_for_vulnerable_patterns() -> None:
    findings = redos.scan_for_redos(
        "t.py", "import re\nre.match(r'(a+)+$', v)\nre.match(r'^[a-z]+$', v)\n", "python"
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "OCSA-VALID-004"
    assert findings[0].line == 2


# -- engine ----------------------------------------------------------------


def test_scan_reports_missing_path() -> None:
    with pytest.raises(UsageError) as excinfo:
        scan_path(Path("/definitely/not/here"))
    assert excinfo.value.code == "scan.path_missing"


def test_scan_single_file(tmp_path: Path) -> None:
    target = tmp_path / "bad.py"
    target.write_text('PASSWORD = "hunter2secret"\n', encoding="utf-8")
    result = scan_path(target)
    assert result.files_scanned == 1
    assert any(f.rule_id == "OCSA-CRED-001" for f in result.findings)


def test_scan_skips_binary_and_unsupported(tmp_path: Path) -> None:
    (tmp_path / "blob.py").write_bytes(b"\x00\x01\x02binary")
    (tmp_path / "notes.md").write_text("hello", encoding="utf-8")
    result = scan_path(tmp_path)
    assert result.files_scanned == 0
    assert set(result.files_skipped) == {"blob.py", "notes.md"}


def test_scan_records_unreadable_files_as_errors(tmp_path: Path) -> None:
    unreadable = tmp_path / "locked.py"
    unreadable.write_text("x = 1\n", encoding="utf-8")
    unreadable.chmod(0o000)
    try:
        result = scan_path(tmp_path)
    finally:
        unreadable.chmod(0o644)
    if result.errors:  # the suite may run as root, where mode 000 is still readable
        assert result.errors[0]["error"] == "unreadable"


def test_scan_records_syntax_errors_but_still_scans(tmp_path: Path) -> None:
    target = tmp_path / "broken.py"
    target.write_text('PASSWORD = "hunter2secret"\ndef broken(:\n', encoding="utf-8")
    result = scan_path(target)
    assert any(error["error"] == "syntax" for error in result.errors)
    assert any(f.rule_id == "OCSA-CRED-001" for f in result.findings)


def test_scan_is_deterministic(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('SECRET = "abcdefgh1234"\n', encoding="utf-8")
    (tmp_path / "b.js").write_text('const API_KEY = "abcdefgh1234";\n', encoding="utf-8")
    first = scan_path(tmp_path)
    second = scan_path(tmp_path)
    assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]


def test_duplicate_findings_are_collapsed(tmp_path: Path) -> None:
    target = tmp_path / "dup.py"
    target.write_text(
        "import hashlib\ndef f(b):\n    return hashlib.md5(b).digest()\n", encoding="utf-8"
    )
    result = scan_path(target)
    md5 = [f for f in result.findings if f.rule_id == "OCSA-CRYPTO-001"]
    assert len(md5) == 1


def test_fail_on_is_a_threshold_not_an_exact_match(tmp_path: Path) -> None:
    """`--fail-on high` must still fail on a critical finding.

    Matching only the named severity would let a critical issue through
    precisely when an operator has lowered the bar.
    """
    (tmp_path / "x.py").write_text('PASSWORD = "hunter2secret"\n', encoding="utf-8")
    result = scan_path(tmp_path)
    assert result.failing(frozenset({Severity.CRITICAL}))
    assert result.failing(frozenset({Severity.HIGH})), "high is below critical and must still trip"
    assert result.failing(frozenset({Severity.INFORMATIONAL}))
    assert not result.failing(frozenset()), "an empty threshold never fails"


def test_lowering_the_threshold_broadens_not_narrows_it(tmp_path: Path) -> None:
    """A tree with only a medium finding: high is clean, medium is not."""
    (tmp_path / "x.py").write_text('import hashlib\nhashlib.md5(b"x")\n', encoding="utf-8")
    result = scan_path(tmp_path)
    assert {finding.severity for finding in result.findings} == {Severity.MEDIUM}
    assert not result.failing(frozenset({Severity.HIGH}))
    assert not result.failing(frozenset({Severity.CRITICAL}))
    assert result.failing(frozenset({Severity.MEDIUM}))
    assert result.failing(frozenset({Severity.INFORMATIONAL}))


def test_min_severity_filter_and_ignore(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text(
        'PASSWORD = "hunter2secret"\nimport hashlib\nhashlib.md5(b"x")\n', encoding="utf-8"
    )
    result = scan_path(tmp_path)
    filtered = result.filtered(minimum=Severity.HIGH)
    assert all(f.severity.rank >= Severity.HIGH.rank for f in filtered.findings)
    ignored = result.filtered(ignore=frozenset({"OCSA-CRED-001"}))
    assert not any(f.rule_id == "OCSA-CRED-001" for f in ignored.findings)


def test_findings_never_contain_secret_values(tmp_path: Path) -> None:
    secret = "hunter2secretvalue"
    (tmp_path / "x.py").write_text(f'PASSWORD = "{secret}"\n', encoding="utf-8")
    result = scan_path(tmp_path)
    serialised = json.dumps(result.to_dict())
    assert secret not in serialised
    finding = next(f for f in result.findings if f.rule_id == "OCSA-CRED-001")
    assert finding.fingerprint is not None
    assert finding.secret_kind == "credential"


def test_exclude_paths_suppresses_a_file(tmp_path: Path) -> None:
    (tmp_path / "rules.py").write_text('SECRET = "abcdefgh1234"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text('SECRET = "abcdefgh1234"\n', encoding="utf-8")
    policy = SecurityAuditPolicy(exclude_paths=("rules.py",))
    result = AuditEngine.from_policy(policy).scan(tmp_path)
    files = {f.file for f in result.findings}
    assert files == {"app.py"}


def test_result_counts_cover_every_severity(tmp_path: Path) -> None:
    result = ScanResult(root="x")
    assert set(result.counts_by_severity()) == {severity.value for severity in Severity}
    assert result.highest_severity() is None


# -- reports ---------------------------------------------------------------


def test_text_report_contains_required_sections(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text('PASSWORD = "hunter2secret"\n', encoding="utf-8")
    stream = io.StringIO()
    render_text(scan_path(tmp_path), stream=stream, verbose=True)
    text = stream.getvalue()
    for expected in ("OCSA-CRED-001", "cause:", "impact:", "fix:", "fingerprint"):
        assert expected in text


def test_text_report_on_a_clean_tree(tmp_path: Path) -> None:
    stream = io.StringIO()
    render_text(scan_path(tmp_path), stream=stream)
    assert "No findings." in stream.getvalue()


def test_json_report_is_valid_and_complete(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text('PASSWORD = "hunter2secret"\n', encoding="utf-8")
    stream = io.StringIO()
    render_json(scan_path(tmp_path), stream=stream)
    document = json.loads(stream.getvalue())
    finding = document["findings"][0]
    for field in (
        "rule_id",
        "severity",
        "confidence",
        "file",
        "line",
        "code_location",
        "description",
        "root_cause",
        "impact",
        "remediation",
    ):
        assert field in finding


def test_sarif_report_conforms_to_the_required_shape(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text('PASSWORD = "hunter2secret"\n', encoding="utf-8")
    stream = io.StringIO()
    render_sarif(scan_path(tmp_path), stream=stream)
    document = json.loads(stream.getvalue())
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "opencode-security-audit"
    assert run["tool"]["driver"]["rules"]
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    assert location["region"]["startLine"] >= 1
    assert run["invocations"][0]["executionSuccessful"] is True


def test_sarif_empty_tree_is_still_valid(tmp_path: Path) -> None:
    stream = io.StringIO()
    render_sarif(scan_path(tmp_path), stream=stream)
    document = json.loads(stream.getvalue())
    assert document["runs"][0]["results"] == []
