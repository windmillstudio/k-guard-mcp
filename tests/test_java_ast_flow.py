from __future__ import annotations

from k_guard_mcp.scanner import KGuardScanner


def _sql_findings(source: str) -> list:
    return [
        finding
        for finding in KGuardScanner().scan_text(source, "src/main/java/app/OrdersController.java").findings
        if finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_SQL"
    ]


def test_multiline_prepared_statement_tracks_request_sql() -> None:
    source = """
class OrdersController {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String account = request.getHeader("X-Account");
    String sql = "select * from orders where account='" + account + "'";
    java.sql.Connection connection = Database.open();
    java.sql.PreparedStatement statement = connection.prepareStatement(
        sql,
        java.sql.ResultSet.TYPE_FORWARD_ONLY,
        java.sql.ResultSet.CONCUR_READ_ONLY);
    statement.execute();
  }
}
"""

    findings = _sql_findings(source)

    assert len(findings) == 1
    assert "java_ast_prepared_sql" in findings[0].evidence


def test_parameter_binding_is_not_treated_as_dynamic_sql() -> None:
    source = """
class OrdersController {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String account = request.getParameter("account");
    java.sql.Connection connection = Database.open();
    java.sql.PreparedStatement statement = connection.prepareStatement(
        "select * from orders where account=?");
    statement.setString(1, account);
    statement.executeQuery();
  }
}
"""

    assert _sql_findings(source) == []


def test_literal_branch_eliminates_unreachable_tainted_path() -> None:
    source = """
class OrdersController {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String input = request.getParameter("q");
    int offset = 86;
    String chosen;
    if ((7 * 42) - offset > 200) chosen = "fixed";
    else chosen = input;
    String sql = "select * from orders where id='" + chosen + "'";
    java.sql.Statement statement = Database.statement();
    statement.execute(sql);
  }
}
"""

    assert _sql_findings(source) == []


def test_unknown_static_field_condition_keeps_tainted_branch_reachable() -> None:
    source = """
class OrdersController {
  private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

  public void bad(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String data;
    if (PRIVATE_STATIC_FINAL_FIVE == 5) data = request.getParameter("name");
    else data = null;
    if (PRIVATE_STATIC_FINAL_FIVE == 5) {
      java.sql.Statement statement = Database.statement();
      statement.executeQuery("select * from users where name='" + data + "'");
    }
  }
}
"""

    assert len(_sql_findings(source)) == 1


def test_unknown_instance_field_condition_does_not_taint_clean_source() -> None:
    source = """
class OrdersController {
  private int privateFive = 5;

  public void good(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String data;
    if (privateFive != 5) data = null;
    else data = "fixed";
    if (privateFive == 5) {
      java.sql.Statement statement = Database.statement();
      statement.executeQuery("select * from users where name='" + data + "'");
    }
  }
}
"""

    assert _sql_findings(source) == []


def test_constant_switch_follows_fallthrough_to_tainted_case() -> None:
    source = """
class OrdersController {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String input = request.getParameter("q");
    String chosen;
    char target = "ABC".charAt(2);
    switch (target) {
      case 'A': chosen = "fixed"; break;
      case 'C':
      case 'D': chosen = input; break;
      default: chosen = "fixed"; break;
    }
    String sql = "select * from orders where id='" + chosen + "'";
    java.sql.Statement statement = Database.statement();
    statement.execute(sql);
  }
}
"""

    assert len(_sql_findings(source)) == 1


def test_collection_index_precision_does_not_taint_safe_element() -> None:
    source = """
class OrdersController {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String input = request.getParameter("q");
    java.util.List<String> values = new java.util.ArrayList<String>();
    values.add("safe-first");
    values.add(input);
    values.add("safe-last");
    values.remove(0);
    String chosen = values.get(1);
    String sql = "select * from orders where id='" + chosen + "'";
    java.sql.Statement statement = Database.statement();
    statement.execute(sql);
  }
}
"""

    assert _sql_findings(source) == []


def test_same_file_helper_and_external_transform_preserve_taint() -> None:
    source = """
class OrdersController {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String input = request.getParameter("q");
    String chosen = normalize(request, input);
    String sql = "select * from orders where id='" + chosen + "'";
    java.sql.Statement statement = Database.statement();
    statement.execute(sql);
  }

  private static String normalize(HttpServletRequest request, String input) {
    TextAdapter adapter = AdapterFactory.create();
    return adapter.transform(input);
  }
}
"""

    assert len(_sql_findings(source)) == 1


def test_generic_execute_method_is_not_a_sql_sink() -> None:
    source = """
class UploadController {
  public Object upload(@RequestParam String filename) {
    return super.execute(filename);
  }
}
"""

    assert _sql_findings(source) == []
