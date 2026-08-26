from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "run_java_xss_observe_ab.py"
SPEC = importlib.util.spec_from_file_location("run_java_xss_observe_ab_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _corpus(
    root: Path,
    *,
    include_encoded_control: bool = False,
    include_encoded_helper_control: bool = False,
    include_static_ternary_control: bool = False,
    include_static_switch_control: bool = False,
    include_static_if_control: bool = False,
) -> dict:
    positive = root / "src" / "main" / "java" / "Positive.java"
    negative = root / "src" / "main" / "java" / "Negative.java"
    positive.parent.mkdir(parents=True)
    positive.write_text(
        """
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class Positive {
  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    response.setContentType("text/html;charset=UTF-8");
    String value = request.getHeader("Referer");
    response.getWriter().printf("<p>%s</p>", value);
  }
}
""",
        encoding="utf-8",
    )
    negative.write_text(
        """
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class Negative {
  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    response.setContentType("text/html;charset=UTF-8");
    String value = request.getHeader("Referer");
    response.getWriter().format("fixed response", value);
  }
}
""",
        encoding="utf-8",
    )
    encoded = root / "src" / "main" / "java" / "Encoded.java"
    if include_encoded_control:
        encoded.write_text(
            """
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class Encoded {
  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    response.setContentType("text/html;charset=UTF-8");
    String value = request.getHeader("Referer");
    String encoded = org.springframework.web.util.HtmlUtils.htmlEscape(value);
    response.getWriter().println(encoded);
  }
}
""",
            encoding="utf-8",
        )
    encoded_helper = root / "src" / "main" / "java" / "EncodedHelper.java"
    if include_encoded_helper_control:
        encoded_helper.write_text(
            """
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class EncodedHelper {
  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    response.setContentType("text/html;charset=UTF-8");
    String value = request.getHeader("Referer");
    String encoded = new Encoder().encode(request, value);
    response.getWriter().println(encoded);
  }

  private class Encoder {
    public String encode(HttpServletRequest request, String value) {
      String encoded = org.owasp.esapi.ESAPI.encoder().encodeForHTML(value);
      return encoded;
    }
  }
}
""",
            encoding="utf-8",
        )
    static_ternary = root / "src" / "main" / "java" / "StaticTernary.java"
    if include_static_ternary_control:
        static_ternary.write_text(
            """
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class StaticTernary {
  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    response.setContentType("text/html;charset=UTF-8");
    String value = request.getHeader("Referer");
    int offset = 106;
    String output = (7 * 18) + offset > 200 ? "fixed" : value;
    response.getWriter().println(output);
  }
}
""",
            encoding="utf-8",
        )
    static_switch = root / "src" / "main" / "java" / "StaticSwitch.java"
    if include_static_switch_control:
        static_switch.write_text(
            """
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class StaticSwitch {
  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    response.setContentType("text/html;charset=UTF-8");
    String value = request.getHeader("Referer");
    String output = new Selector().select(request, value);
    response.getWriter().println(output);
  }

  private class Selector {
    public String select(HttpServletRequest request, String value) {
      String choice = "ABC";
      char selected = choice.charAt(1);
      String output;
      switch (selected) {
        case 'A':
          output = value;
          break;
        case 'B':
          output = "fixed";
          break;
        default:
          output = value;
          break;
      }
      return output;
    }
  }
}
""",
            encoding="utf-8",
        )
    static_if = root / "src" / "main" / "java" / "StaticIf.java"
    if include_static_if_control:
        static_if.write_text(
            """
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class StaticIf {
  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    response.setContentType("text/html;charset=UTF-8");
    String value = request.getHeader("Referer");
    String output = new Selector().select(request, value);
    response.getWriter().println(output);
  }

  private class Selector {
    public String select(HttpServletRequest request, String value) {
      String output;
      int threshold = 86;
      if ((7 * 42) - threshold > 200) output = "fixed";
      else output = value;
      return output;
    }
  }
}
""",
            encoding="utf-8",
        )
    expected = root / "expectedresults-1.2.csv"
    expected.write_text("BenchmarkTest00001,xss,true,CWE-79\nBenchmarkTest00002,xss,false,CWE-79\n", encoding="utf-8")
    license_path = root / "LICENSE"
    license_path.write_text("test license\n", encoding="utf-8")
    files = (
        [expected, license_path, positive, negative]
        + ([encoded] if include_encoded_control else [])
        + ([encoded_helper] if include_encoded_helper_control else [])
        + ([static_ternary] if include_static_ternary_control else [])
        + ([static_switch] if include_static_switch_control else [])
        + ([static_if] if include_static_if_control else [])
    )
    bindings = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": _sha256(path),
            "byte_count": path.stat().st_size,
            "git_blob_sha1": "0" * 40,
            "mode": "100644",
        }
        for path in files
    ]
    cases = [
        {
            "case_id": "BenchmarkTest00001",
            "category": "xss",
            "cwe": "CWE-79",
            "source_path": positive.relative_to(root).as_posix(),
            "source_sha256": _sha256(positive),
            "source_bytes": positive.stat().st_size,
            "truth": "present",
        },
        {
            "case_id": "BenchmarkTest00002",
            "category": "xss",
            "cwe": "CWE-79",
            "source_path": negative.relative_to(root).as_posix(),
            "source_sha256": _sha256(negative),
            "source_bytes": negative.stat().st_size,
            "truth": "absent",
        },
    ]
    if include_encoded_control:
        cases.append(
            {
                "case_id": "BenchmarkTest00003",
                "category": "xss",
                "cwe": "CWE-79",
                "source_path": encoded.relative_to(root).as_posix(),
                "source_sha256": _sha256(encoded),
                "source_bytes": encoded.stat().st_size,
                "truth": "absent",
            }
        )
    if include_encoded_helper_control:
        cases.append(
            {
                "case_id": "BenchmarkTest00004",
                "category": "xss",
                "cwe": "CWE-79",
                "source_path": encoded_helper.relative_to(root).as_posix(),
                "source_sha256": _sha256(encoded_helper),
                "source_bytes": encoded_helper.stat().st_size,
                "truth": "absent",
            }
        )
    if include_static_ternary_control:
        cases.append(
            {
                "case_id": "BenchmarkTest00005",
                "category": "xss",
                "cwe": "CWE-79",
                "source_path": static_ternary.relative_to(root).as_posix(),
                "source_sha256": _sha256(static_ternary),
                "source_bytes": static_ternary.stat().st_size,
                "truth": "absent",
            }
        )
    if include_static_switch_control:
        cases.append(
            {
                "case_id": "BenchmarkTest00006",
                "category": "xss",
                "cwe": "CWE-79",
                "source_path": static_switch.relative_to(root).as_posix(),
                "source_sha256": _sha256(static_switch),
                "source_bytes": static_switch.stat().st_size,
                "truth": "absent",
            }
        )
    if include_static_if_control:
        cases.append(
            {
                "case_id": "BenchmarkTest00007",
                "category": "xss",
                "cwe": "CWE-79",
                "source_path": static_if.relative_to(root).as_posix(),
                "source_sha256": _sha256(static_if),
                "source_bytes": static_if.stat().st_size,
                "truth": "absent",
            }
        )
    return {
        "corpus_id": "test-java-xss",
        "language": "java",
        "cases": cases,
        "source_tree": {
            "source_tree_sha256": "a" * 64,
            "file_count": len(bindings),
            "total_bytes": sum(path.stat().st_size for path in files),
            "files": bindings,
        },
        "expected_results": {
            "path": expected.name,
            "sha256": _sha256(expected),
            "byte_count": expected.stat().st_size,
        },
        "license": {
            "path": license_path.name,
            "sha256": _sha256(license_path),
            "byte_count": license_path.stat().st_size,
        },
    }


def test_h4a_measurement_is_repeatable_and_never_promotes_the_observer(tmp_path: Path) -> None:
    report = observer.measure_h4a(_corpus(tmp_path), tmp_path)

    assert report["complete"] is True
    assert report["status"] == "MEASURED_HOLD"
    assert report["repeat"]["exact"] is True
    assert report["hypothesis"]["stage"] == "observe"
    assert report["hypothesis"]["warning_promotion_admitted"] is False
    assert report["hypothesis"]["blocking_promotion_admitted"] is False
    assert report["comparison"]["control"]["confusion_matrix"] == {"tp": 0, "fp": 0, "fn": 1, "tn": 1}
    assert report["comparison"]["candidate"]["confusion_matrix"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 1}
    registry = report["runs"][0]["candidate"]["candidate_registry"]
    assert len(registry) == 1
    assert registry[0]["detector_subtype"] == observer.SUBTYPE
    assert registry[0]["severity"] == "medium"
    assert registry[0]["confidence"] == "medium"
    assert registry[0]["raw_returned"] is False
    assert report["claim_boundary"]["release_gate_passed"] is False


def test_h4b_only_compares_direct_known_html_encoder_suppression(tmp_path: Path) -> None:
    report = observer.measure_h4b(_corpus(tmp_path, include_encoded_control=True), tmp_path)

    assert report["hypothesis"]["id"] == "H4B"
    assert report["repeat"]["exact"] is True
    assert report["comparison"]["control"]["confusion_matrix"] == {"tp": 1, "fp": 1, "fn": 0, "tn": 1}
    assert report["comparison"]["candidate"]["confusion_matrix"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 2}
    assert report["comparison"]["delta"]["confusion_matrix_delta"] == {"tp": 0, "fp": -1, "fn": 0, "tn": 1}
    assert report["hypothesis"]["warning_promotion_admitted"] is False
    assert report["hypothesis"]["blocking_promotion_admitted"] is False


def test_h4c_only_compares_a_trivial_same_file_html_encoder_helper(tmp_path: Path) -> None:
    report = observer.measure_h4c(_corpus(tmp_path, include_encoded_helper_control=True), tmp_path)

    assert report["hypothesis"]["id"] == "H4C"
    assert report["repeat"]["exact"] is True
    assert report["comparison"]["control"]["confusion_matrix"] == {"tp": 1, "fp": 1, "fn": 0, "tn": 1}
    assert report["comparison"]["candidate"]["confusion_matrix"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 2}
    assert report["comparison"]["delta"]["confusion_matrix_delta"] == {"tp": 0, "fp": -1, "fn": 0, "tn": 1}
    assert report["hypothesis"]["warning_promotion_admitted"] is False
    assert report["hypothesis"]["blocking_promotion_admitted"] is False


def test_h4d_only_compares_static_ternary_literal_suppression(tmp_path: Path) -> None:
    report = observer.measure_h4d(_corpus(tmp_path, include_static_ternary_control=True), tmp_path)

    assert report["hypothesis"]["id"] == "H4D"
    assert report["repeat"]["exact"] is True
    assert report["comparison"]["control"]["confusion_matrix"] == {"tp": 1, "fp": 1, "fn": 0, "tn": 1}
    assert report["comparison"]["candidate"]["confusion_matrix"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 2}
    assert report["comparison"]["delta"]["confusion_matrix_delta"] == {"tp": 0, "fp": -1, "fn": 0, "tn": 1}
    assert report["hypothesis"]["warning_promotion_admitted"] is False
    assert report["hypothesis"]["blocking_promotion_admitted"] is False


def test_h4e_only_compares_closed_static_switch_literal_suppression(tmp_path: Path) -> None:
    report = observer.measure_h4e(_corpus(tmp_path, include_static_switch_control=True), tmp_path)

    assert report["hypothesis"]["id"] == "H4E"
    assert report["repeat"]["exact"] is True
    assert report["comparison"]["control"]["confusion_matrix"] == {"tp": 1, "fp": 1, "fn": 0, "tn": 1}
    assert report["comparison"]["candidate"]["confusion_matrix"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 2}
    assert report["comparison"]["delta"]["confusion_matrix_delta"] == {"tp": 0, "fp": -1, "fn": 0, "tn": 1}
    assert report["hypothesis"]["warning_promotion_admitted"] is False
    assert report["hypothesis"]["blocking_promotion_admitted"] is False


def test_h4f_only_compares_closed_static_if_literal_suppression(tmp_path: Path) -> None:
    report = observer.measure_h4f(_corpus(tmp_path, include_static_if_control=True), tmp_path)

    assert report["hypothesis"]["id"] == "H4F"
    assert report["repeat"]["exact"] is True
    assert report["comparison"]["control"]["confusion_matrix"] == {"tp": 1, "fp": 1, "fn": 0, "tn": 1}
    assert report["comparison"]["candidate"]["confusion_matrix"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 2}
    assert report["comparison"]["delta"]["confusion_matrix_delta"] == {"tp": 0, "fp": -1, "fn": 0, "tn": 1}
    assert report["hypothesis"]["warning_promotion_admitted"] is False
    assert report["hypothesis"]["blocking_promotion_admitted"] is False


def test_h4a_cli_exposes_pinned_inputs_and_non_promoting_output_contract() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "--manifest" in completed.stdout
    assert "--hypothesis" in completed.stdout
    assert "--benchmark-java" in completed.stdout
    assert "--baseline-receipt" in completed.stdout
    assert "--output-dir" in completed.stdout
