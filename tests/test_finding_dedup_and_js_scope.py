from pathlib import Path

from k_guard_mcp.detectors.polyglot import PolyglotRiskDetector
from k_guard_mcp.models import Finding, FlowMap, ScanResult
from k_guard_mcp.taint import AstTaintAnalyzer


def _taint_finding(source_line: int, source_hash: str) -> Finding:
    return Finding(
        id=f"path-{source_line}",
        source="js-ts-taint",
        rule_id="JS_TS_TAINT_PII_TO_LOG",
        severity="high",
        confidence="medium",
        title="JS/TS taint reaches a log",
        file="routes/account.ts",
        line_start=12,
        line_end=12,
        evidence=(
            f"js_ts_source=request_body source_line={source_line} sink=log sink_line=12; "
            f"source_hash={source_hash} sink_hash=sink12 raw_returned=false"
        ),
        why_it_matters="x",
        recommendation="x",
    )


def test_finalize_collapses_multipath_sink_findings_and_preserves_source_traces() -> None:
    first = _taint_finding(3, "source03")
    second = _taint_finding(8, "source08")
    result = ScanResult(
        findings=[first, second],
        flow_map=FlowMap(findings=[first, second]),
    ).finalize()

    assert len(result.findings) == 1
    assert result.flow_map is not None
    assert len(result.flow_map.findings) == 1
    for finding in (result.findings[0], result.flow_map.findings[0]):
        traces = [component for component in finding.components if component.label == "source_trace:js-ts-taint"]
        assert {trace.line for trace in traces} == {3, 8}
        assert {trace.evidence for trace in traces} == {first.evidence, second.evidence}


def test_finalize_keeps_distinct_object_actions_on_the_same_line() -> None:
    common = {
        "source": "database-policy",
        "rule_id": "DB_POLICY_PERMISSIVE_TRUE",
        "severity": "high",
        "confidence": "high",
        "title": "Permissive policy",
        "file": "schema.sql",
        "line_start": 1,
        "line_end": 1,
        "why_it_matters": "x",
        "recommendation": "x",
    }
    using = Finding(id="using", evidence="detector_subtype=permissive_using_true object_ref=table1", **common)
    check = Finding(id="check", evidence="detector_subtype=permissive_with_check_true object_ref=table1", **common)

    result = ScanResult(findings=[using, check]).finalize()

    assert len(result.findings) == 2


def test_finalize_preserves_cross_detector_paths_for_one_action() -> None:
    common = {
        "rule_id": "WEB_UNTRUSTED_INPUT_TO_COMMAND",
        "severity": "critical",
        "confidence": "high",
        "title": "Command injection",
        "file": "app.ts",
        "line_start": 9,
        "line_end": 9,
        "why_it_matters": "x",
        "recommendation": "x",
    }
    direct = Finding(id="direct", source="app-risk", evidence="detector_subtype=direct_request_to_command", **common)
    bounded = Finding(id="bounded", source="polyglot-flow", evidence="detector_subtype=bounded_request_to_command", **common)

    result = ScanResult(findings=[direct, bounded]).finalize()

    assert len(result.findings) == 1
    assert {component.label for component in result.findings[0].components} == {
        "source_trace:app-risk",
        "source_trace:polyglot-flow",
    }


def _js_ts_flow_findings(source: str) -> list[Finding]:
    flow = FlowMap()
    AstTaintAnalyzer().append_file(flow, Path("routes/account.ts"), source)
    return flow.findings


def test_js_ts_taint_does_not_cross_sibling_function_boundaries() -> None:
    source = """function collect(req) {
  const email = req.body.email;
}
function publish() {
  console.log(email);
}
"""

    findings = _js_ts_flow_findings(source)

    assert "JS_TS_TAINT_PII_TO_LOG" not in {finding.rule_id for finding in findings}


def test_js_ts_taint_does_not_cross_sibling_arrow_function_boundaries() -> None:
    source = """const collect = (req) => {
  const email = req.body.email;
};
const publish = () => {
  console.log(email);
};
"""

    findings = _js_ts_flow_findings(source)

    assert "JS_TS_TAINT_PII_TO_LOG" not in {finding.rule_id for finding in findings}


def test_js_ts_taint_does_not_cross_sibling_method_boundaries() -> None:
    source = """class Handlers {
  collect(req) {
    const email = req.body.email;
  }
  publish() {
    console.log(email);
  }
}
"""

    findings = _js_ts_flow_findings(source)

    assert "JS_TS_TAINT_PII_TO_LOG" not in {finding.rule_id for finding in findings}


def test_js_ts_taint_preserves_same_function_and_nested_closure_flows() -> None:
    same_function = """function publish(req) {
  const email = req.body.email;
  console.log(email);
}
"""
    nested_closure = """function publish(req) {
  const email = req.body.email;
  return () => {
    console.log(email);
  };
}
"""

    assert "JS_TS_TAINT_PII_TO_LOG" in {finding.rule_id for finding in _js_ts_flow_findings(same_function)}
    assert "JS_TS_TAINT_PII_TO_LOG" in {finding.rule_id for finding in _js_ts_flow_findings(nested_closure)}


def test_js_ts_parameter_shadowing_blocks_parent_scope_taint() -> None:
    source = """const email = process.env.CUSTOMER_EMAIL;
function publish(email) {
  console.log(email);
}
"""

    findings = _js_ts_flow_findings(source)

    assert "JS_TS_TAINT_PII_TO_LOG" not in {finding.rule_id for finding in findings}


def test_js_ts_env_metadata_is_not_pii_but_named_secret_remains_sensitive() -> None:
    metadata = """const finalEnv = process.env.NODE_ENV || 'development';
const envConf = require('./env/' + finalEnv);
const config = { ...envConf };
console.log(config);
"""
    secret = """const apiKey = process.env.API_KEY;
console.log(apiKey);
"""

    assert "JS_TS_TAINT_PII_TO_LOG" not in {finding.rule_id for finding in _js_ts_flow_findings(metadata)}
    assert "JS_TS_TAINT_PII_TO_LOG" in {finding.rule_id for finding in _js_ts_flow_findings(secret)}


def test_js_ts_direct_env_metadata_ignores_unrelated_method_names() -> None:
    source = """app.listen(8080, function() {
  console.log(this.address().port, process.env.NODE_ENV);
});
"""

    assert "JS_TS_TAINT_PII_TO_LOG" not in {
        finding.rule_id for finding in _js_ts_flow_findings(source)
    }


def test_js_ts_generic_browser_event_needs_a_sensitive_field_before_log_finding() -> None:
    redirect_event = """export default {
  methods: {
    receiveMsg(event) {
      console.log('message', event);
      location.href = event.data.url;
    }
  }
};
"""
    sensitive_event = """function receiveMsg(event) {
  console.log(event.data.email);
}
"""

    assert "JS_TS_TAINT_PII_TO_LOG" not in {
        finding.rule_id for finding in _js_ts_flow_findings(redirect_event)
    }
    assert "JS_TS_TAINT_PII_TO_LOG" in {
        finding.rule_id for finding in _js_ts_flow_findings(sensitive_event)
    }


def test_js_ts_multiline_callback_does_not_bind_request_to_unrelated_error_log() -> None:
    source = """app.use((err, req, res, next) => {
  console.error(err.message);
  if (req.accepts('html')) {
    res.render('error');
  }
});
"""

    assert "JS_TS_TAINT_PII_TO_LOG" not in {
        finding.rule_id for finding in _js_ts_flow_findings(source)
    }


def test_js_ts_multiline_callback_preserves_real_log_and_command_flows() -> None:
    source = """app.post('/run', (req, res) => {
  const command =
    req.body.command;
  console.error(
    req.body.email
  );
  exec(
    command
  );
});
"""

    rules = {finding.rule_id for finding in _js_ts_flow_findings(source)}

    assert "JS_TS_TAINT_PII_TO_LOG" in rules
    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in rules


def test_js_ts_serverless_event_remains_untrusted_for_integrity_sinks() -> None:
    source = """export async function handler(event) {
  exec(event.body.command);
  db.query(event.body.sql);
}
"""

    rules = {finding.rule_id for finding in _js_ts_flow_findings(source)}

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in rules
    assert "WEB_UNTRUSTED_INPUT_TO_SQL" in rules


def test_polyglot_taint_does_not_cross_sibling_functions_but_keeps_local_flow() -> None:
    sibling_source = """function collect(req) {
  const command = req.body.command;
}
function run() {
  exec(command);
}
"""
    local_source = """function run(req) {
  const command = req.body.command;
  exec(command);
}
"""
    detector = PolyglotRiskDetector()

    sibling_rules = {finding.rule_id for finding in detector.scan_text(sibling_source, "routes/jobs.ts")}
    local_rules = {finding.rule_id for finding in detector.scan_text(local_source, "routes/jobs.ts")}

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" not in sibling_rules
    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in local_rules
