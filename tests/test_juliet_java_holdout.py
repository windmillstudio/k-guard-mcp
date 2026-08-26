from __future__ import annotations

import zipfile
from pathlib import Path

from scripts import run_juliet_java_holdout as juliet


def _source(tainted: bool) -> str:
    value = 'request.getParameter("account")' if tainted else '"fixed"'
    return f"""
class Sample {{
  public void bad(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    String value = {value};
    String sql = "select * from users where account='" + value + "'";
    java.sql.Statement statement = Database.statement();
    statement.execute(sql);
  }}
  public void good(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    String value = "fixed";
    String sql = "select * from users where account='" + value + "'";
    java.sql.Statement statement = Database.statement();
    statement.execute(sql);
  }}
}}
"""


def test_case_selector_is_exact_and_excludes_multifile_suffixes(tmp_path: Path) -> None:
    archive_path = tmp_path / "juliet.zip"
    prefix = "Juliet/src/testcases/CWE89_SQL_Injection/"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(prefix + "CWE89_SQL_Injection__getParameter_Servlet_execute_01.java", _source(True))
        archive.writestr(prefix + "CWE89_SQL_Injection__getParameter_Servlet_execute_53a.java", _source(True))
        archive.writestr(prefix + "CWE89_SQL_Injection__Environment_execute_01.java", _source(True))
    with zipfile.ZipFile(archive_path) as archive:
        selected = juliet._selected_members(archive)

    assert [Path(member).name for member, _ in selected] == [
        "CWE89_SQL_Injection__getParameter_Servlet_execute_01.java"
    ]


def test_entrypoint_scoring_separates_bad_and_good_methods() -> None:
    source = _source(True)

    bad = juliet.scan_java_sql_flows(source, entrypoint_names={"bad"})
    good = juliet.scan_java_sql_flows(source, entrypoint_names={"good"})

    assert len(bad) == 1
    assert good == []


def test_score_and_thresholds_use_paired_confusion_matrix() -> None:
    units = [
        {"unit_id": "a:bad", "expected": "vulnerable", "predicted": "vulnerable"},
        {"unit_id": "a:good", "expected": "clean", "predicted": "clean"},
        {"unit_id": "b:bad", "expected": "vulnerable", "predicted": "clean"},
        {"unit_id": "b:good", "expected": "clean", "predicted": "vulnerable"},
    ]
    metrics, cases = juliet._score(units)
    thresholds = {
        "minimum_total_units": 4,
        "minimum_vulnerable_units": 2,
        "minimum_clean_units": 2,
        "minimum_precision": 0.5,
        "minimum_precision_wilson_95_lower": 0.09,
        "minimum_recall": 0.5,
        "minimum_recall_wilson_95_lower": 0.09,
        "minimum_specificity": 0.5,
        "minimum_specificity_wilson_95_lower": 0.09,
    }

    assert metrics["true_positive"] == metrics["false_positive"] == 1
    assert metrics["false_negative"] == metrics["true_negative"] == 1
    assert all(juliet._threshold_checks(metrics, thresholds).values())
    assert [case["outcome"] for case in cases] == ["tp", "tn", "fn", "fp"]
