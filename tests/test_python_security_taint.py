from __future__ import annotations

from pathlib import Path

from k_guard_mcp.scanner import KGuardScanner


def _rules(tmp_path: Path, code: str) -> set[str]:
    app = tmp_path / "app"
    app.mkdir(parents=True)
    (app / "app.py").write_text(code, encoding="utf-8")
    return {finding.rule_id for finding in KGuardScanner().scan_workspace(app).findings}


def _command_findings(root: Path):
    return [
        finding
        for finding in KGuardScanner().scan_workspace(root).findings
        if finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_COMMAND"
    ]


def _proven_command_findings(root: Path):
    return [
        finding
        for finding in _command_findings(root)
        if finding.confidence == "high"
        and "python_ast_proven_unguarded" in finding.evidence
    ]


def _proven_weak_prefix_command_findings(root: Path):
    return [
        finding
        for finding in _command_findings(root)
        if finding.confidence == "high"
        and (
            "python_ast_proven_weak_prefix_guard_cross_file_command"
            in finding.evidence
        )
    ]


def test_python_security_taint_tracks_request_to_file_and_honors_containment_guard(tmp_path):
    vulnerable = _rules(
        tmp_path / "vulnerable",
        "from flask import request\n"
        "from pathlib import Path\n"
        "def route():\n"
        "    name = request.args.get('name')\n"
        "    path = Path('/srv/data') / name\n"
        "    return path.read_text()\n",
    )
    guarded = _rules(
        tmp_path / "guarded",
        "from flask import request\n"
        "from pathlib import Path\n"
        "def route():\n"
        "    root = Path('/srv/data')\n"
        "    path = (root / request.args.get('name')).resolve()\n"
        "    if not str(path).startswith(str(root)):\n"
        "        return 'invalid'\n"
        "    return path.read_text()\n",
    )

    assert "WEB_UNTRUSTED_INPUT_TO_FILE_PATH" in vulnerable
    assert "WEB_UNTRUSTED_INPUT_TO_FILE_PATH" not in guarded


def test_python_security_taint_distinguishes_sql_concatenation_from_parameters(tmp_path):
    vulnerable = _rules(
        tmp_path / "vulnerable",
        "from flask import request\n"
        "def route(cur):\n"
        "    user = request.form.get('user')\n"
        "    sql = f\"SELECT * FROM users WHERE name='{user}'\"\n"
        "    cur.execute(sql)\n",
    )
    parameterized = _rules(
        tmp_path / "safe",
        "from flask import request\n"
        "def route(cur):\n"
        "    user = request.form.get('user')\n"
        "    cur.execute('SELECT * FROM users WHERE name=?', (user,))\n",
    )

    assert "WEB_UNTRUSTED_INPUT_TO_SQL" in vulnerable
    assert "WEB_UNTRUSTED_INPUT_TO_SQL" not in parameterized


def test_python_security_taint_tracks_loop_keys_into_command(tmp_path):
    rules = _rules(
        tmp_path,
        "from flask import request\n"
        "import subprocess\n"
        "def route():\n"
        "    value = ''\n"
        "    for name in request.form.keys():\n"
        "        value = name\n"
        "        break\n"
        "    args = ['sh', '-c']\n"
        "    args.append(f'echo {value}')\n"
        "    subprocess.run(args)\n",
    )

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in rules


def test_python_security_taint_distinguishes_direct_and_allowlisted_redirect(tmp_path):
    vulnerable = _rules(
        tmp_path / "vulnerable",
        "from flask import request, redirect\n"
        "def route():\n"
        "    return redirect(request.args.get('next'))\n",
    )
    guarded = _rules(
        tmp_path / "guarded",
        "from flask import request, redirect\n"
        "from urllib.parse import urlparse\n"
        "def route():\n"
        "    target = request.args.get('next')\n"
        "    parsed = urlparse(target)\n"
        "    if parsed.netloc not in ['example.com'] or parsed.scheme != 'https':\n"
        "        return 'invalid'\n"
        "    return redirect(target)\n",
    )

    assert "API_OPEN_REDIRECT_REQUEST_INPUT" in vulnerable
    assert "API_OPEN_REDIRECT_REQUEST_INPUT" not in guarded


def test_python_security_taint_treats_authlib_request_as_context_not_destination(tmp_path):
    safe = _rules(
        tmp_path / "safe-authlib",
        "async def route(request):\n"
        "    return await oauth.google.authorize_redirect(request, CONFIGURED_REDIRECT_URI)\n",
    )
    vulnerable = _rules(
        tmp_path / "unsafe-authlib",
        "async def route(request):\n"
        "    target = request.query_params.get('next')\n"
        "    return await oauth.google.authorize_redirect(request, target)\n",
    )

    assert "API_OPEN_REDIRECT_REQUEST_INPUT" not in safe
    assert "API_OPEN_REDIRECT_REQUEST_INPUT" in vulnerable


def test_python_security_taint_handles_generic_request_first_redirects_and_keywords(tmp_path):
    safe = _rules(
        tmp_path / "safe-request-first",
        "async def route(request):\n"
        "    return await provider.login_redirect(request, FIXED_REDIRECT_URI)\n",
    )
    positional = _rules(
        tmp_path / "unsafe-request-first",
        "async def route(request):\n"
        "    return await provider.login_redirect(request, request.query_params.get('next'))\n",
    )
    keyword = _rules(
        tmp_path / "unsafe-keyword",
        "def route(request):\n"
        "    return redirect(to=request.query_params.get('next'))\n",
    )

    assert "API_OPEN_REDIRECT_REQUEST_INPUT" not in safe
    assert "API_OPEN_REDIRECT_REQUEST_INPUT" in positional
    assert "API_OPEN_REDIRECT_REQUEST_INPUT" in keyword


def test_python_ast_log_requires_a_sensitive_request_field(tmp_path):
    operational = _rules(
        tmp_path / "operational-log",
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "async def callback(request):\n"
        "    error = request.query_params.get('error')\n"
        "    logger.warning('OAuth error=%s', error)\n",
    )
    personal = _rules(
        tmp_path / "personal-log",
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "async def callback(request):\n"
        "    email = request.query_params.get('email')\n"
        "    logger.warning('OAuth email=%s', email)\n",
    )

    assert "AST_TAINT_PII_TO_LOG" not in operational
    assert "AST_TAINT_PII_TO_LOG" in personal


def test_python_ast_log_projects_direct_request_fields(tmp_path):
    operational = _rules(
        tmp_path / "direct-operational-log",
        "import logging\n"
        "async def callback(request):\n"
        "    logging.warning('%s', request.query_params.get('error'))\n",
    )
    personal = _rules(
        tmp_path / "direct-personal-log",
        "import logging\n"
        "async def callback(request):\n"
        "    logging.warning('%s', request.query_params.get('email'))\n",
    )
    whole_request = _rules(
        tmp_path / "whole-request-log",
        "import logging\n"
        "async def callback(request):\n"
        "    logging.warning('%s', request)\n",
    )

    assert "AST_TAINT_PII_TO_LOG" not in operational
    assert "AST_TAINT_PII_TO_LOG" in personal
    assert "AST_TAINT_PII_TO_LOG" in whole_request


def test_python_security_taint_distinguishes_html_escape_and_cookie_flags(tmp_path):
    vulnerable = _rules(
        tmp_path / "vulnerable",
        "from flask import request, make_response\n"
        "def route():\n"
        "    value = request.form.get('value')\n"
        "    response = make_response(f'<p>{value}</p>')\n"
        "    response.set_cookie('sid', value, secure=False, httponly=True)\n"
        "    return response\n",
    )
    escaped = _rules(
        tmp_path / "safe",
        "from flask import request\n"
        "import html\n"
        "def route():\n"
        "    response = f'<p>{html.escape(request.form.get(\"value\"))}</p>'\n"
        "    return response\n",
    )

    assert {"WEB_UNTRUSTED_INPUT_TO_HTML", "AUTH_COOKIE_SECURITY_FLAG_DISABLED"}.issubset(vulnerable)
    assert "WEB_UNTRUSTED_INPUT_TO_HTML" not in escaped


def test_python_html_sanitizer_helper_preserves_only_the_html_domain(tmp_path):
    root = tmp_path / "domain-specific-helper"
    root.mkdir()
    (root / "helpers.py").write_text(
        "import html\n"
        "def render(value):\n"
        "    response = '<p>'\n"
        "    response += html.escape(value).replace('\\n', '<br>')\n"
        "    return response\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "from helpers import render\n"
        "def route(cur):\n"
        "    value = request.form.get('value')\n"
        "    response = render(value)\n"
        "    cur.execute(f\"SELECT * FROM users WHERE name='{response}'\")\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules
    assert "WEB_UNTRUSTED_INPUT_TO_SQL" in rules


def test_python_html_sanitizer_summary_handles_command_output_shape(tmp_path):
    root = tmp_path / "command-output-helper"
    root.mkdir()
    (root / "helpers.py").write_text(
        "import html\n"
        "def commandOutput(proc):\n"
        "    response = '<p>stdout:<br>'\n"
        "    response += html.escape(proc.stdout).replace('\\n', '<br>')\n"
        "    response += '<br>stderr:<br>'\n"
        "    response += html.escape(proc.stderr).replace('\\n', '<br>')\n"
        "    return response\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "import subprocess\n"
        "def route():\n"
        "    import helpers\n"
        "    value = request.form.get('value')\n"
        "    proc = subprocess.run(['sh', '-c', f'echo {value}'], capture_output=True, text=True)\n"
        "    response = helpers.commandOutput(proc)\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_COMMAND" in rules
    assert "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules


def test_python_html_sanitizer_summary_requires_stable_helper_binding(tmp_path):
    builtin_wrapper = (
        "import html\n"
        "def render(value):\n"
        "    return html.escape(value)\n"
    )
    custom_encoder = (
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&#x{hex(ord(character))[2:]};'\n"
        "    return result\n"
        "def render(value):\n"
        "    return escape_for_html(value)\n"
    )
    sources = {
        "builtin-decorated": (
            "import html\n"
            "def replace_with_identity(function):\n"
            "    return lambda value: value\n"
            "@replace_with_identity\n"
            "def render(value):\n"
            "    return html.escape(value)\n"
        ),
        "builtin-direct-rebind": (
            f"{builtin_wrapper}"
            "render = lambda value: value\n"
        ),
        "builtin-globals-rebind": (
            f"{builtin_wrapper}"
            "globals()['render'] = lambda value: value\n"
        ),
        "builtin-setattr-rebind": (
            f"{builtin_wrapper}"
            "import sys\n"
            "setattr(sys.modules[__name__], 'render', lambda value: value)\n"
        ),
        "builtin-module-attribute-rebind": (
            f"{builtin_wrapper}"
            "import sys\n"
            "sys.modules[__name__].render = lambda value: value\n"
        ),
        "builtin-nested-global-rebind": (
            f"{builtin_wrapper}"
            "def replace_render():\n"
            "    global render\n"
            "    render = lambda value: value\n"
            "replace_render()\n"
        ),
        "custom-direct-rebind": (
            f"{custom_encoder}"
            "render = lambda value: value\n"
        ),
        "custom-globals-rebind": (
            f"{custom_encoder}"
            "globals()['render'] = lambda value: value\n"
        ),
    }
    route = (
        "from flask import make_response, request\n"
        "from helpers import render\n"
        "def route():\n"
        "    return make_response(render(request.form.get('value')))\n"
    )

    missed = []
    for variant, helper_source in sources.items():
        root = tmp_path / variant
        root.mkdir()
        compile(helper_source, "helpers.py", "exec")
        (root / "helpers.py").write_text(helper_source, encoding="utf-8")
        (root / "route.py").write_text(route, encoding="utf-8")
        rules = {
            finding.rule_id
            for finding in KGuardScanner().scan_workspace(root).findings
        }
        if "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules:
            missed.append(variant)

    assert missed == []


def test_python_html_sanitizer_summary_requires_stable_consumer_binding(tmp_path):
    helper_source = (
        "import html\n"
        "def render(value):\n"
        "    return html.escape(value)\n"
    )
    variants = {
        "module-direct-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "render = lambda value: value\n"
            "def route():\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "module-attribute-rebind": (
            "from flask import make_response, request\n"
            "import helpers\n"
            "helpers.render = lambda value: value\n"
            "def route():\n"
            "    return make_response(helpers.render(request.form.get('value')))\n"
        ),
        "function-parameter-shadow": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def route(render=lambda value: value):\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "function-local-shadow": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def route():\n"
            "    render = lambda value: value\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "function-local-import-rebind": (
            "from flask import make_response, request\n"
            "def route():\n"
            "    from helpers import render\n"
            "    render = lambda value: value\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "enclosing-function-direct-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def make_view():\n"
            "    render = lambda value: value\n"
            "    def route():\n"
            "        return make_response(render(request.form.get('value')))\n"
            "    return route\n"
        ),
        "enclosing-function-parameter-shadow": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def make_view(render=lambda value: value):\n"
            "    def route():\n"
            "        return make_response(render(request.form.get('value')))\n"
            "    return route\n"
        ),
        "enclosing-function-module-member-rebind": (
            "from flask import make_response, request\n"
            "import helpers\n"
            "def make_view():\n"
            "    helpers.render = lambda value: value\n"
            "    def route():\n"
            "        return make_response(helpers.render("
            "request.form.get('value')))\n"
            "    return route\n"
        ),
        "enclosing-function-class-body-module-member-rebind": (
            "from flask import make_response, request\n"
            "import helpers\n"
            "def make_view():\n"
            "    class Poison:\n"
            "        helpers.render = lambda value: value\n"
            "    def route():\n"
            "        return make_response(helpers.render("
            "request.form.get('value')))\n"
            "    return route\n"
            "route = make_view()\n"
        ),
        "enclosing-function-class-body-global-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def make_view():\n"
            "    class Poison:\n"
            "        global render\n"
            "        render = lambda value: value\n"
            "    def route():\n"
            "        return make_response(render(request.form.get('value')))\n"
            "    return route\n"
            "route = make_view()\n"
        ),
        "enclosing-function-class-body-nonlocal-rebind": (
            "from flask import make_response, request\n"
            "def make_view():\n"
            "    from helpers import render\n"
            "    class Poison:\n"
            "        nonlocal render\n"
            "        render = lambda value: value\n"
            "    def route():\n"
            "        return make_response(render(request.form.get('value')))\n"
            "    return route\n"
            "route = make_view()\n"
        ),
        "enclosing-function-nested-class-module-member-rebind": (
            "from flask import make_response, request\n"
            "import helpers\n"
            "def make_view():\n"
            "    class Outer:\n"
            "        class Inner:\n"
            "            helpers.render = lambda value: value\n"
            "    def route():\n"
            "        return make_response(helpers.render("
            "request.form.get('value')))\n"
            "    return route\n"
            "route = make_view()\n"
        ),
        "enclosing-function-class-decorator-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def replace_class(class_object):\n"
            "    global render\n"
            "    render = lambda value: value\n"
            "    return class_object\n"
            "def make_view():\n"
            "    @replace_class\n"
            "    class Poison:\n"
            "        pass\n"
            "    def route():\n"
            "        return make_response(render(request.form.get('value')))\n"
            "    return route\n"
            "route = make_view()\n"
        ),
        "enclosing-function-class-body-called-mutator-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def make_view():\n"
            "    def replace_render():\n"
            "        global render\n"
            "        render = lambda value: value\n"
            "    class Poison:\n"
            "        replace_render()\n"
            "    def route():\n"
            "        return make_response(render(request.form.get('value')))\n"
            "    return route\n"
            "route = make_view()\n"
        ),
        "enclosing-function-class-base-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def replace_render():\n"
            "    global render\n"
            "    render = lambda value: value\n"
            "    return object\n"
            "def make_view():\n"
            "    class Poison(replace_render()):\n"
            "        pass\n"
            "    def route():\n"
            "        return make_response(render(request.form.get('value')))\n"
            "    return route\n"
            "route = make_view()\n"
        ),
        "enclosing-function-decorator-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def replace_view(function):\n"
            "    global render\n"
            "    render = lambda value: value\n"
            "    return function\n"
            "@replace_view\n"
            "def make_view():\n"
            "    def route():\n"
            "        return make_response(render(request.form.get('value')))\n"
            "    return route\n"
        ),
        "enclosing-function-default-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def replace_render():\n"
            "    global render\n"
            "    render = lambda value: value\n"
            "    return None\n"
            "def make_view(marker=replace_render()):\n"
            "    def route():\n"
            "        return make_response(render(request.form.get('value')))\n"
            "    return route\n"
        ),
        "function-module-member-rebind": (
            "from flask import make_response, request\n"
            "def route():\n"
            "    import helpers\n"
            "    helpers.render = lambda value: value\n"
            "    return make_response(helpers.render(request.form.get('value')))\n"
        ),
        "module-globals-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "globals()['render'] = lambda value: value\n"
            "def route():\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "function-globals-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def route():\n"
            "    globals()['render'] = lambda value: value\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "module-globals-alias-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "namespace = globals\n"
            "namespace()['render'] = lambda value: value\n"
            "def route():\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "module-exec-alias-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "runner = exec\n"
            "runner('render = lambda value: value')\n"
            "def route():\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "module-nested-global-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def replace_render():\n"
            "    global render\n"
            "    render = lambda value: value\n"
            "replace_render()\n"
            "def route():\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "function-nested-nonlocal-rebind": (
            "from flask import make_response, request\n"
            "def route():\n"
            "    from helpers import render\n"
            "    def replace_render():\n"
            "        nonlocal render\n"
            "        render = lambda value: value\n"
            "    replace_render()\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "function-exception-shadow": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "class CallableError(Exception):\n"
            "    def __call__(self, value):\n"
            "        return value\n"
            "def route():\n"
            "    try:\n"
            "        raise CallableError()\n"
            "    except CallableError as render:\n"
            "        return make_response(render(request.form.get('value')))\n"
        ),
        "function-match-shadow": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def route(candidate=lambda value: value):\n"
            "    match candidate:\n"
            "        case render:\n"
            "            return make_response(render("
            "request.form.get('value')))\n"
        ),
        "module-import-star-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "from evil import *\n"
            "def route():\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "module-decorator-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def replace_route(function):\n"
            "    global render\n"
            "    render = lambda value: value\n"
            "    return function\n"
            "@replace_route\n"
            "def route():\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
        "module-default-rebind": (
            "from flask import make_response, request\n"
            "from helpers import render\n"
            "def replace_render():\n"
            "    global render\n"
            "    render = lambda value: value\n"
            "    return None\n"
            "def route(marker=replace_render()):\n"
            "    return make_response(render(request.form.get('value')))\n"
        ),
    }

    missed = []
    for variant, route_source in variants.items():
        root = tmp_path / variant
        root.mkdir()
        compile(route_source, "route.py", "exec")
        (root / "helpers.py").write_text(helper_source, encoding="utf-8")
        (root / "evil.py").write_text(
            "render = lambda value: value\n",
            encoding="utf-8",
        )
        (root / "route.py").write_text(route_source, encoding="utf-8")
        rules = {
            finding.rule_id
            for finding in KGuardScanner().scan_workspace(root).findings
        }
        if "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules:
            missed.append(variant)

    assert missed == []


def test_python_html_sanitizer_summary_allows_class_local_binding(tmp_path):
    root = tmp_path / "class-local-binding"
    root.mkdir()
    helper_source = (
        "import html\n"
        "def render(value):\n"
        "    return html.escape(value)\n"
    )
    route_source = (
        "from flask import make_response, request\n"
        "from helpers import render\n"
        "def make_view():\n"
        "    class LocalOnly:\n"
        "        render = lambda value: value\n"
        "    def route():\n"
        "        return make_response(render(request.form.get('value')))\n"
        "    return route\n"
        "route = make_view()\n"
    )
    compile(route_source, "route.py", "exec")
    (root / "helpers.py").write_text(helper_source, encoding="utf-8")
    (root / "route.py").write_text(route_source, encoding="utf-8")

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules


def test_python_html_sanitizer_summary_requires_authentic_standard_binding(
    tmp_path,
):
    variants = {
        "module-import-alias": (
            "import evil_html as html\n"
            "def render(value):\n"
            "    return html.escape(value)\n"
        ),
        "function-import-alias": (
            "def render(value):\n"
            "    import evil_html as html\n"
            "    return html.escape(value)\n"
        ),
        "module-import-star": (
            "import html\n"
            "from evil_html import *\n"
            "def render(value):\n"
            "    return html.escape(value)\n"
        ),
        "function-parameter-shadow": (
            "def render(value, html):\n"
            "    return html.escape(value)\n"
        ),
        "function-local-shadow": (
            "import html\n"
            "class Identity:\n"
            "    def escape(self, value):\n"
            "        return value\n"
            "def render(value):\n"
            "    html = Identity()\n"
            "    return html.escape(value)\n"
        ),
    }
    evil_source = (
        "class Identity:\n"
        "    def escape(self, value):\n"
        "        return value\n"
        "html = Identity()\n"
        "def escape(value):\n"
        "    return value\n"
    )

    missed = []
    for variant, helper_source in variants.items():
        root = tmp_path / variant
        root.mkdir()
        compile(helper_source, "helpers.py", "exec")
        (root / "evil_html.py").write_text(evil_source, encoding="utf-8")
        (root / "helpers.py").write_text(helper_source, encoding="utf-8")
        if variant == "function-parameter-shadow":
            route_source = (
                "from flask import make_response, request\n"
                "import evil_html\n"
                "from helpers import render\n"
                "def route():\n"
                "    return make_response(render("
                "request.form.get('value'), evil_html))\n"
            )
        else:
            route_source = (
                "from flask import make_response, request\n"
                "from helpers import render\n"
                "def route():\n"
                "    return make_response(render(request.form.get('value')))\n"
            )
        (root / "route.py").write_text(route_source, encoding="utf-8")
        rules = {
            finding.rule_id
            for finding in KGuardScanner().scan_workspace(root).findings
        }
        if "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules:
            missed.append(variant)

    assert missed == []


def test_python_html_sanitizer_rejects_workspace_module_shadowing(tmp_path):
    variants = {
        "html": "escape",
        "markupsafe": "escape",
        "bleach": "clean",
    }
    route_source = (
        "from flask import make_response, request\n"
        "from helpers import render\n"
        "def route():\n"
        "    return make_response(render(request.form.get('value')))\n"
    )

    missed = []
    for module_name, sanitizer_name in variants.items():
        root = tmp_path / module_name
        root.mkdir()
        (root / f"{module_name}.py").write_text(
            f"def {sanitizer_name}(value):\n"
            "    return value\n",
            encoding="utf-8",
        )
        (root / "helpers.py").write_text(
            f"import {module_name}\n"
            "def render(value):\n"
            f"    return {module_name}.{sanitizer_name}(value)\n",
            encoding="utf-8",
        )
        (root / "route.py").write_text(route_source, encoding="utf-8")
        rules = {
            finding.rule_id
            for finding in KGuardScanner().scan_workspace(root).findings
        }
        if "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules:
            missed.append(module_name)

    assert missed == []


def test_python_html_sanitizer_summary_rejects_deceptive_custom_sanitizer(tmp_path):
    root = tmp_path / "deceptive-custom-sanitizer"
    root.mkdir()
    (root / "helpers.py").write_text(
        "def escape_for_html(value):\n"
        "    return value\n"
        "def render(value):\n"
        "    return escape_for_html(value)\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "from helpers import render\n"
        "def route():\n"
        "    response = render(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_html_sanitizer_summary_rejects_unrelated_import_name(tmp_path):
    root = tmp_path / "unrelated-import-name"
    root.mkdir()
    (root / "safe_helpers.py").write_text(
        "import html\n"
        "def render(value):\n"
        "    return html.escape(value)\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "from unscanned_dependency import render\n"
        "def route():\n"
        "    response = render(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_html_sanitizer_summary_rejects_mutated_encoder_tables(tmp_path):
    root = tmp_path / "mutated-encoder-table"
    root.mkdir()
    (root / "helpers.py").write_text(
        "entity_names = {60: 'lt'}\n"
        "entity_names[60] = 'quot;><script'\n"
        "def encode(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&{entity_names[ord(character)]};'\n"
        "    return result\n"
        "def render(value):\n"
        "    return encode(value)\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "from helpers import render\n"
        "def route():\n"
        "    response = render(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_custom_html_encoder_requires_matching_import_source(tmp_path):
    encoder = (
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&#x{hex(ord(character))[2:]};'\n"
        "    return result\n"
    )
    matched = tmp_path / "matched-custom-encoder"
    matched.mkdir()
    (matched / "helpers.py").write_text(encoder, encoding="utf-8")
    (matched / "route.py").write_text(
        "from flask import request\n"
        "def route():\n"
        "    import helpers\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )
    unrelated = tmp_path / "unrelated-custom-encoder"
    unrelated.mkdir()
    (unrelated / "helpers.py").write_text(encoder, encoding="utf-8")
    (unrelated / "route.py").write_text(
        "from flask import request\n"
        "import unscanned_dependency\n"
        "def route():\n"
        "    response = unscanned_dependency.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    matched_rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(matched).findings
    }
    unrelated_rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(unrelated).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" not in matched_rules
    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in unrelated_rules


def test_python_custom_html_encoder_rejects_decorated_or_rebound_binding(tmp_path):
    encoder_body = (
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&#x{hex(ord(character))[2:]};'\n"
        "    return result\n"
    )
    route = (
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n"
    )

    decorated = tmp_path / "decorated-custom-encoder"
    decorated.mkdir()
    (decorated / "helpers.py").write_text(
        "def replace_with_identity(function):\n"
        "    return lambda value: value\n"
        "@replace_with_identity\n"
        "def escape_for_html(value):\n"
        f"{encoder_body}",
        encoding="utf-8",
    )
    (decorated / "route.py").write_text(route, encoding="utf-8")

    rebound = tmp_path / "rebound-custom-encoder"
    rebound.mkdir()
    (rebound / "helpers.py").write_text(
        "def escape_for_html(value):\n"
        f"{encoder_body}"
        "escape_for_html = lambda value: value\n",
        encoding="utf-8",
    )
    (rebound / "route.py").write_text(route, encoding="utf-8")

    missed = []
    for root in (decorated, rebound):
        rules = {
            finding.rule_id
            for finding in KGuardScanner().scan_workspace(root).findings
        }
        if "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules:
            missed.append(root.name)

    assert missed == []


def test_python_custom_html_encoder_rejects_dynamic_module_rebinding(tmp_path):
    encoder_body = (
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&#x{hex(ord(character))[2:]};'\n"
        "    return result\n"
    )
    route = (
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n"
    )
    variants = {
        "globals-subscript": (
            "globals()['escape_for_html'] = lambda value: value\n"
        ),
        "globals-alias": (
            "namespace = globals()\n"
            "namespace['escape_for_html'] = lambda value: value\n"
        ),
        "vars-subscript": (
            "vars()['escape_for_html'] = lambda value: value\n"
        ),
        "globals-update": (
            "globals().update(escape_for_html=lambda value: value)\n"
        ),
        "setattr-module": (
            "import sys\n"
            "setattr(sys.modules[__name__], 'escape_for_html', "
            "lambda value: value)\n"
        ),
        "module-attribute": (
            "import sys\n"
            "sys.modules[__name__].escape_for_html = lambda value: value\n"
        ),
        "exec-rebind": (
            "exec('escape_for_html = lambda value: value')\n"
        ),
        "nested-global": (
            "def replace_encoder():\n"
            "    global escape_for_html\n"
            "    escape_for_html = lambda value: value\n"
            "replace_encoder()\n"
        ),
    }

    missed = []
    for variant, rebinding in variants.items():
        root = tmp_path / variant
        root.mkdir()
        (root / "helpers.py").write_text(
            "def escape_for_html(value):\n"
            f"{encoder_body}"
            f"{rebinding}",
            encoding="utf-8",
        )
        (root / "route.py").write_text(route, encoding="utf-8")
        rules = {
            finding.rule_id
            for finding in KGuardScanner().scan_workspace(root).findings
        }
        if "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules:
            missed.append(variant)

    assert missed == []


def test_python_custom_html_encoder_rejects_dynamic_builtin_prebinding(tmp_path):
    encoder_body = (
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&#x{hex(ord(character))[2:]};'\n"
        "    return result\n"
    )
    route = (
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n"
    )
    variants = {
        "globals-hex": (
            "globals()['hex'] = "
            "lambda value: '0x\\\"><img src=x onerror=alert(1)>'\n"
        ),
        "globals-alias-ord": (
            "namespace = globals()\n"
            "namespace['ord'] = lambda value: 60\n"
        ),
        "exec-hex": (
            "exec(\"hex = lambda value: "
            "'0x\\\\\\\"><svg onload=alert(1)>'\")\n"
        ),
    }

    missed = []
    for variant, prebinding in variants.items():
        root = tmp_path / variant
        root.mkdir()
        helper_source = (
            f"{prebinding}"
            f"{encoder_body}"
        )
        compile(helper_source, "helpers.py", "exec")
        (root / "helpers.py").write_text(helper_source, encoding="utf-8")
        (root / "route.py").write_text(route, encoding="utf-8")
        rules = {
            finding.rule_id
            for finding in KGuardScanner().scan_workspace(root).findings
        }
        if "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules:
            missed.append(variant)

    assert missed == []


def test_python_custom_html_encoder_accepts_immutable_entity_table(tmp_path):
    root = tmp_path / "immutable-entity-table"
    root.mkdir()
    (root / "helpers.py").write_text(
        "entity_names = {38: 'amp', 60: 'lt', 62: 'gt'}\n"
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum() or character in {' ', '-', '_'}:\n"
        "            result += character\n"
        "        elif ord(character) in entity_names:\n"
        "            result += f'&{entity_names[ord(character)]};'\n"
        "        else:\n"
        "            result += f'&#x{hex(ord(character))[2:]};'\n"
        "    return result\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules


def test_python_custom_html_encoder_rejects_active_constant_and_prefix(tmp_path):
    active_constant = tmp_path / "active-constant-encoder"
    active_constant.mkdir()
    (active_constant / "helpers.py").write_text(
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += '<svg onload=alert(1)>'\n"
        "    return result\n",
        encoding="utf-8",
    )
    (active_constant / "route.py").write_text(
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )
    active_prefix = tmp_path / "active-prefix-encoder"
    active_prefix.mkdir()
    (active_prefix / "helpers.py").write_text(
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&\"><img src=x onerror=alert(1) x=\"{ord(character)};'\n"
        "    return result\n",
        encoding="utf-8",
    )
    (active_prefix / "route.py").write_text(
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    constant_rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(active_constant).findings
    }
    prefix_rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(active_prefix).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in constant_rules
    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in prefix_rules


def test_python_custom_html_encoder_requires_exact_hex_slice(tmp_path):
    root = tmp_path / "wrong-hex-slice"
    root.mkdir()
    (root / "helpers.py").write_text(
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&#x{hex(ord(character))[1:]};'\n"
        "    return result\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_custom_html_encoder_accepts_safe_constant_entities(tmp_path):
    root = tmp_path / "safe-constant-entities"
    root.mkdir()
    (root / "helpers.py").write_text(
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        elif ord(character) < 32:\n"
        "            result += '&#xfffd;'\n"
        "        else:\n"
        "            result += f'&#x{hex(ord(character))[2:]};'\n"
        "    return result\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" not in rules


def test_python_custom_html_encoder_rejects_active_initial_accumulator(tmp_path):
    root = tmp_path / "active-initial-accumulator"
    root.mkdir()
    (root / "helpers.py").write_text(
        "def escape_for_html(value):\n"
        "    result = '<img src=x onerror=alert(1)>'\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&#x{hex(ord(character))[2:]};'\n"
        "    return result\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_custom_html_encoder_rejects_shadowed_entity_builtins(tmp_path):
    root = tmp_path / "shadowed-entity-builtins"
    root.mkdir()
    (root / "helpers.py").write_text(
        "def hex(value):\n"
        "    return '0x\\\"><img src=x onerror=alert(1)>'\n"
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&#x{hex(ord(character))[2:]};'\n"
        "    return result\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_custom_html_encoder_rejects_aliased_mutable_entity_table(tmp_path):
    root = tmp_path / "aliased-mutable-entity-table"
    root.mkdir()
    (root / "helpers.py").write_text(
        "entity_names = {60: 'lt'}\n"
        "alias = entity_names\n"
        "alias[60] = 'quot;><img src=x onerror=alert(1) x='\n"
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&{entity_names[ord(character)]};'\n"
        "    return result\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_html_sanitizer_summary_rejects_active_markup_replacement(tmp_path):
    cross_file = tmp_path / "active-replacement-cross-file"
    cross_file.mkdir()
    (cross_file / "helpers.py").write_text(
        "import html\n"
        "def render(value):\n"
        "    return html.escape(value).replace('x', '<img src=x onerror=alert(1)>')\n",
        encoding="utf-8",
    )
    (cross_file / "route.py").write_text(
        "from flask import request\n"
        "from helpers import render\n"
        "def route():\n"
        "    response = render(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )
    same_file = tmp_path / "active-replacement-same-file"
    same_file.mkdir()
    (same_file / "route.py").write_text(
        "import html\n"
        "from flask import request\n"
        "def render(value):\n"
        "    return html.escape(value).replace('x', '<svg onload=alert(1)>')\n"
        "def route():\n"
        "    response = render(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    cross_file_rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(cross_file).findings
    }
    same_file_rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(same_file).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in cross_file_rules
    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in same_file_rules


def test_python_html_runtime_replace_shares_the_fail_closed_policy(tmp_path):
    active = tmp_path / "active-inline-replacement"
    active.mkdir()
    (active / "route.py").write_text(
        "import html\n"
        "from flask import request\n"
        "def route():\n"
        "    response = html.escape(request.form.get('value')).replace(\n"
        "        'x', '<svg onload=alert(1)>'\n"
        "    )\n"
        "    return response\n",
        encoding="utf-8",
    )
    inert = tmp_path / "inert-inline-replacement"
    inert.mkdir()
    (inert / "route.py").write_text(
        "import html\n"
        "from flask import request\n"
        "def route():\n"
        "    response = html.escape(request.form.get('value')).replace('\\n', '<br>')\n"
        "    return response\n",
        encoding="utf-8",
    )

    active_rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(active).findings
    }
    inert_rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(inert).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in active_rules
    assert "WEB_UNTRUSTED_INPUT_TO_HTML" not in inert_rules


def test_python_html_runtime_rejects_unknown_post_escape_transform(tmp_path):
    root = tmp_path / "unknown-inline-transform"
    root.mkdir()
    (root / "route.py").write_text(
        "import html\n"
        "from flask import request\n"
        "def decode(value):\n"
        "    return value\n"
        "def route():\n"
        "    response = decode(html.escape(request.form.get('value')))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_html_runtime_allows_plain_constant_format_only(tmp_path):
    safe = _rules(
        tmp_path / "plain-format",
        "from flask import request\n"
        "import html\n"
        "def route():\n"
        "    value = html.escape(request.form.get('value'))\n"
        "    payload = {'value': value, 'label': 'ok'}\n"
        "    response = 'value={0[value]} label={0[label]}'.format(payload)\n"
        "    return response\n",
    )
    conversion = _rules(
        tmp_path / "conversion-format",
        "from flask import request\n"
        "import html\n"
        "def route():\n"
        "    value = html.escape(request.form.get('value'))\n"
        "    response = 'value={!r}'.format(value)\n"
        "    return response\n",
    )
    format_spec = _rules(
        tmp_path / "specified-format",
        "from flask import request\n"
        "import html\n"
        "def route():\n"
        "    value = html.escape(request.form.get('value'))\n"
        "    response = 'value={:>10}'.format(value)\n"
        "    return response\n",
    )

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" not in safe
    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in conversion
    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in format_spec


def test_python_html_summary_rejects_fstring_conversion(tmp_path):
    root = tmp_path / "fstring-conversion"
    root.mkdir()
    (root / "helpers.py").write_text(
        "import html\n"
        "def render(value):\n"
        "    return f'{html.escape(value)!r}'\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "from helpers import render\n"
        "def route():\n"
        "    response = render(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_custom_html_encoder_rejects_entity_format_spec(tmp_path):
    root = tmp_path / "entity-format-spec"
    root.mkdir()
    (root / "helpers.py").write_text(
        "entity_names = {38: 'amp', 60: 'lt', 62: 'gt'}\n"
        "def escape_for_html(value):\n"
        "    result = ''\n"
        "    for character in value:\n"
        "        if character.isalnum():\n"
        "            result += character\n"
        "        else:\n"
        "            result += f'&{entity_names[ord(character)]:>4};'\n"
        "    return result\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "import helpers\n"
        "def route():\n"
        "    response = helpers.escape_for_html(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_html_sanitizer_summary_rejects_mixed_and_unknown_transforms(tmp_path):
    mixed = tmp_path / "mixed-return"
    mixed.mkdir()
    (mixed / "helpers.py").write_text(
        "import html\n"
        "def render(value, safe):\n"
        "    if safe:\n"
        "        return html.escape(value)\n"
        "    return value\n",
        encoding="utf-8",
    )
    (mixed / "route.py").write_text(
        "from flask import request\n"
        "from helpers import render\n"
        "def route():\n"
        "    response = render(request.form.get('value'), request.form.get('safe'))\n"
        "    return response\n",
        encoding="utf-8",
    )
    unknown = tmp_path / "unknown-transform"
    unknown.mkdir()
    (unknown / "helpers.py").write_text(
        "import html\n"
        "def decode(value):\n"
        "    return value\n"
        "def render(value):\n"
        "    escaped = html.escape(value)\n"
        "    return decode(escaped)\n",
        encoding="utf-8",
    )
    (unknown / "route.py").write_text(
        "from flask import request\n"
        "from helpers import render\n"
        "def route():\n"
        "    response = render(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    mixed_rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(mixed).findings
    }
    unknown_rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(unknown).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in mixed_rules
    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in unknown_rules


def test_python_html_sanitizer_summary_fails_closed_on_same_named_conflicts(tmp_path):
    root = tmp_path / "summary-conflict"
    root.mkdir()
    (root / "safe_helpers.py").write_text(
        "import html\n"
        "def render(value):\n"
        "    return html.escape(value)\n",
        encoding="utf-8",
    )
    (root / "unsafe_helpers.py").write_text(
        "def render(value):\n"
        "    return value\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "from safe_helpers import render\n"
        "def route():\n"
        "    response = render(request.form.get('value'))\n"
        "    return response\n",
        encoding="utf-8",
    )

    rules = {
        finding.rule_id
        for finding in KGuardScanner().scan_workspace(root).findings
    }

    assert "WEB_UNTRUSTED_INPUT_TO_HTML" in rules


def test_python_ast_recovers_newer_fstring_line_and_fails_closed_other_syntax(tmp_path):
    recovered = _rules(
        tmp_path / "recovered",
        "from flask import make_response\n"
        "def route():\n"
        "    note = f\"value {\"literal\"}\"\n"
        "    response = make_response(note)\n"
        "    response.set_cookie('sid', 'x', secure=False, httponly=True)\n"
        "    return response\n",
    )
    failed = _rules(tmp_path / "failed", "def broken(:\n    pass\n")

    assert "PYTHON_AST_FSTRING_RECOVERY_USED" in recovered
    assert "AUTH_COOKIE_SECURITY_FLAG_DISABLED" in recovered
    assert "PYTHON_AST_PARSE_FAILED" in failed


def test_python_security_taint_tracks_unique_imported_helper_parameter_to_command(tmp_path):
    root = tmp_path / "cross-file"
    root.mkdir()
    (root / "service.py").write_text(
        "import subprocess\n"
        "def run_command(value):\n"
        "    prepared = value\n"
        "    subprocess.run(prepared, shell=True)\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "from service import run_command\n"
        "def route():\n"
        "    command = request.args.get('command')\n"
        "    run_command(command)\n",
        encoding="utf-8",
    )

    result = KGuardScanner().scan_workspace(root)
    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_COMMAND"
        and "python_ast_bounded_cross_file_parameter_flow" in finding.evidence
    )

    assert finding.severity == "critical"
    assert finding.file == str(root / "route.py")
    assert "helper_file_hash=" in finding.evidence
    assert "raw_returned=false" in finding.evidence


def test_python_security_taint_does_not_invent_cross_file_flow_for_constant_helper(tmp_path):
    root = tmp_path / "safe-cross-file"
    root.mkdir()
    (root / "service.py").write_text(
        "import subprocess\n"
        "def status(label):\n"
        "    subprocess.run(['echo', 'ok'])\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from flask import request\n"
        "from service import status\n"
        "def route():\n"
        "    status(request.args.get('label'))\n",
        encoding="utf-8",
    )

    result = KGuardScanner().scan_workspace(root)

    assert not any(
        finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_COMMAND"
        and "python_ast_bounded_cross_file_parameter_flow" in finding.evidence
        for finding in result.findings
    )


def test_python_cross_file_flow_binds_same_named_helpers_to_the_imported_module(tmp_path):
    root = tmp_path / "module-bound-cross-file"
    services = root / "services"
    services.mkdir(parents=True)
    (services / "__init__.py").write_text("", encoding="utf-8")
    (services / "captcha.py").write_text(
        "import requests\n"
        "def verify(token):\n"
        "    return requests.get(token).ok\n",
        encoding="utf-8",
    )
    (services / "otp.py").write_text(
        "def verify(user_id, code):\n"
        "    return code == '123456'\n",
        encoding="utf-8",
    )
    (root / "otp_route.py").write_text(
        "from services import otp\n"
        "async def route(request):\n"
        "    otp.verify(1, request.query_params.get('otp'))\n",
        encoding="utf-8",
    )
    (root / "captcha_route.py").write_text(
        "from services import captcha\n"
        "async def route(request):\n"
        "    captcha.verify(request.query_params.get('url'))\n",
        encoding="utf-8",
    )

    findings = [
        finding
        for finding in KGuardScanner().scan_workspace(root).findings
        if finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_OUTBOUND_REQUEST"
        and "python_ast_bounded_cross_file_parameter_flow" in finding.evidence
    ]

    assert [Path(finding.file).name for finding in findings] == ["captcha_route.py"]


def test_python_cross_file_flow_resolves_relative_imports(tmp_path):
    package = tmp_path / "relative" / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "service.py").write_text(
        "import subprocess\n"
        "def execute(command):\n"
        "    subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    (package / "route.py").write_text(
        "from .service import execute\n"
        "async def route(request):\n"
        "    execute(request.query_params.get('command'))\n",
        encoding="utf-8",
    )

    findings = KGuardScanner().scan_workspace(tmp_path / "relative").findings

    assert any(
        finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_COMMAND"
        and "python_ast_bounded_cross_file_parameter_flow" in finding.evidence
        for finding in findings
    )


def test_python_same_file_request_backfill_survives_project_name_ambiguity(tmp_path):
    root = tmp_path / "vulnpy-shape"
    root.mkdir()
    (root / "flask_blueprint.py").write_text(
        "from flask import Blueprint, request\n"
        "vulnerable_blueprint = Blueprint('vulnpy', __name__)\n"
        "def _get_user_input():\n"
        "    if request.headers.get('User-Input') is not None:\n"
        "        return request.headers.get('User-Input')\n"
        "    if request.method == 'GET':\n"
        "        return request.args.get('user_input', '')\n"
        "    return request.form.get('user_input', '')\n"
        "def get_trigger_view(name, trigger):\n"
        "    def _view():\n"
        "        user_input = _get_user_input()\n"
        "        template = '<html>fixed</html>'\n"
        "        if name == 'xss' and trigger == 'raw':\n"
        "            template += '<p>XSS: ' + user_input + '</p>'\n"
        "        return template\n"
        "    return _view\n"
        "get_trigger_view('xss', 'raw')\n",
        encoding="utf-8",
    )
    (root / "other_framework.py").write_text(
        "def _get_user_input(request):\n"
        "    return request.query_params.get('user_input', '')\n",
        encoding="utf-8",
    )

    findings = [
        finding
        for finding in KGuardScanner().scan_workspace(root).findings
        if finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_HTML"
        and Path(finding.file).name == "flask_blueprint.py"
    ]

    assert len(findings) == 1
    assert findings[0].line_start == 15
    assert "detector_subtype=html_response" in findings[0].evidence


def test_python_same_file_request_backfill_rejects_async_consumer_scopes(tmp_path):
    variants = {
        "sync-control": (
            "from quart import request\n"
            "def _get_user_input():\n"
            "    return request.args.get('user_input', '')\n"
            "def route():\n"
            "    response = '<p>' + _get_user_input() + '</p>'\n"
            "    return response\n"
        ),
        "async-current": (
            "from quart import request\n"
            "def _get_user_input():\n"
            "    return request.args.get('user_input', '')\n"
            "async def route():\n"
            "    response = '<p>' + _get_user_input() + '</p>'\n"
            "    return response\n"
        ),
        "async-enclosing": (
            "from quart import request\n"
            "def _get_user_input():\n"
            "    return request.args.get('user_input', '')\n"
            "async def route_factory():\n"
            "    def route():\n"
            "        response = '<p>' + _get_user_input() + '</p>'\n"
            "        return response\n"
            "    return route\n"
        ),
    }
    unsafe_variants = []
    for name, source in variants.items():
        root = tmp_path / name
        root.mkdir()
        (root / "route.py").write_text(source, encoding="utf-8")
        (root / "other_framework.py").write_text(
            "def _get_user_input(request):\n"
            "    return request.query_params.get('user_input', '')\n",
            encoding="utf-8",
        )
        if any(
            finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_HTML"
            for finding in KGuardScanner().scan_workspace(root).findings
        ):
            unsafe_variants.append(name)

    assert unsafe_variants == ["sync-control"]


def test_python_same_file_request_backfill_does_not_cross_wrong_binding(tmp_path):
    root = tmp_path / "wrong-binding"
    root.mkdir()
    (root / "request_source.py").write_text(
        "def _get_user_input(request):\n"
        "    return request.args.get('user_input', '')\n",
        encoding="utf-8",
    )
    (root / "fixed_helper.py").write_text(
        "def _get_user_input():\n"
        "    return 'fixed'\n",
        encoding="utf-8",
    )
    (root / "route.py").write_text(
        "from fixed_helper import _get_user_input\n"
        "def route():\n"
        "    response = '<p>' + _get_user_input() + '</p>'\n"
        "    return response\n",
        encoding="utf-8",
    )
    (root / "direct_unsafe.py").write_text(
        "from flask import request\n"
        "def route():\n"
        "    response = '<p>' + request.args.get('user_input', '') + '</p>'\n"
        "    return response\n",
        encoding="utf-8",
    )

    findings = KGuardScanner().scan_workspace(root).findings

    assert not any(
        finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_HTML"
        and Path(finding.file).name == "route.py"
        for finding in findings
    )
    assert any(
        finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_HTML"
        and Path(finding.file).name == "direct_unsafe.py"
        for finding in findings
    )


def test_python_same_file_request_backfill_preserves_safe_paths(tmp_path):
    variants = {
        "unsafe-sync": (
            "from flask import request\n"
            "def _get_user_input():\n"
            "    return request.args.get('user_input', '')\n"
            "def route():\n"
            "    response = '<p>' + _get_user_input() + '</p>'\n"
            "    return response\n"
        ),
        "constant": (
            "def _get_user_input():\n"
            "    return 'fixed'\n"
            "def route():\n"
            "    response = '<p>' + _get_user_input() + '</p>'\n"
            "    return response\n"
        ),
        "escaped-callsite": (
            "import html\n"
            "from flask import request\n"
            "def _get_user_input():\n"
            "    return request.args.get('user_input', '')\n"
            "def route():\n"
            "    response = '<p>' + html.escape(_get_user_input()) + '</p>'\n"
            "    return response\n"
        ),
        "escaped-helper": (
            "import html\n"
            "from flask import request\n"
            "def _get_user_input():\n"
            "    return html.escape(request.args.get('user_input', ''))\n"
            "def route():\n"
            "    response = '<p>' + _get_user_input() + '</p>'\n"
            "    return response\n"
        ),
        "verified-custom-helper": (
            "from flask import request\n"
            "def escape_for_html(value):\n"
            "    result = ''\n"
            "    for character in value:\n"
            "        if character.isalnum():\n"
            "            result += character\n"
            "        else:\n"
            "            result += f'&#x{hex(ord(character))[2:]};'\n"
            "    return result\n"
            "def _get_user_input():\n"
            "    return escape_for_html(request.args.get('user_input', ''))\n"
            "def route():\n"
            "    response = '<p>' + _get_user_input() + '</p>'\n"
            "    return response\n"
        ),
        "reassigned": (
            "from flask import request\n"
            "def _get_user_input():\n"
            "    return request.args.get('user_input', '')\n"
            "_get_user_input = lambda: 'fixed'\n"
            "def route():\n"
            "    response = '<p>' + _get_user_input() + '</p>'\n"
            "    return response\n"
        ),
        "shadowed": (
            "from flask import request\n"
            "def _get_user_input():\n"
            "    return request.args.get('user_input', '')\n"
            "def route():\n"
            "    _get_user_input = lambda: 'fixed'\n"
            "    response = '<p>' + _get_user_input() + '</p>'\n"
            "    return response\n"
        ),
        "called-mutator": (
            "from flask import request\n"
            "def _get_user_input():\n"
            "    return request.args.get('user_input', '')\n"
            "def replace_helper():\n"
            "    global _get_user_input\n"
            "    _get_user_input = lambda: 'fixed'\n"
            "replace_helper()\n"
            "def route():\n"
            "    response = '<p>' + _get_user_input() + '</p>'\n"
            "    return response\n"
        ),
        "exec-rebound": (
            "from flask import request\n"
            "def _get_user_input():\n"
            "    return request.args.get('user_input', '')\n"
            "exec(\"_get_user_input = lambda: 'fixed'\")\n"
            "def route():\n"
            "    response = '<p>' + _get_user_input() + '</p>'\n"
            "    return response\n"
        ),
    }
    unsafe_variants = []
    for name, source in variants.items():
        root = tmp_path / name
        root.mkdir()
        (root / "route.py").write_text(source, encoding="utf-8")
        (root / "other_framework.py").write_text(
            "def _get_user_input(request):\n"
            "    return request.query_params.get('user_input', '')\n",
            encoding="utf-8",
        )
        if any(
            finding.rule_id == "WEB_UNTRUSTED_INPUT_TO_HTML"
            for finding in KGuardScanner().scan_workspace(root).findings
        ):
            unsafe_variants.append(name)

    assert unsafe_variants == ["unsafe-sync"]


def test_python_command_proof_promotes_only_three_sealed_shapes(tmp_path):
    root = tmp_path / "sealed-shapes"
    core = root / "core"
    trigger = root / "vulnpy" / "trigger"
    core.mkdir(parents=True)
    trigger.mkdir(parents=True)
    (core / "__init__.py").write_text("", encoding="utf-8")
    (root / "vulnpy" / "__init__.py").write_text("", encoding="utf-8")
    (trigger / "__init__.py").write_text("", encoding="utf-8")
    (core / "helpers.py").write_text(
        "import os\n"
        "def run_cmd(command):\n"
        "    return os.popen(command).read()\n",
        encoding="utf-8",
    )
    (core / "security.py").write_text(
        "def allowed_cmds(command):\n"
        "    if command.startswith(('echo', 'ps')):\n"
        "        return True\n"
        "    return False\n",
        encoding="utf-8",
    )
    (core / "directives.py").write_text(
        "Marker = object()\n",
        encoding="utf-8",
    )
    (core / "views.py").write_text(
        "from core import helpers, security\n"
        "from core.directives import *\n"
        "class Query:\n"
        "    def resolve_system_diagnostics(self, info, cmd='whoami'):\n"
        "        if security.allowed_cmds(cmd):\n"
        "            return helpers.run_cmd(cmd)\n"
        "    def resolve_system_debug(self, info, arg=None):\n"
        "        if arg:\n"
        "            return helpers.run_cmd('ps {}'.format(arg))\n",
        encoding="utf-8",
    )
    (root / "falcon_app.py").write_text(
        "import os\n"
        "class FileUpload:\n"
        "    def on_post(self, req, resp):\n"
        "        value = req._params['upload'].file.read()\n"
        "        command = 'echo ' + str(value[:10])\n"
        "        os.system(command)\n",
        encoding="utf-8",
    )
    (trigger / "cmdi.py").write_text(
        "import os\n"
        "def do_os_system(command):\n"
        "    return os.system(command)\n",
        encoding="utf-8",
    )
    (root / "quart_app.py").write_text(
        "from quart import request\n"
        "from vulnpy.trigger.cmdi import do_os_system\n"
        "async def upload_return_large_file():\n"
        "    files = await request.files\n"
        "    stream = files.get('file')\n"
        "    do_os_system(stream.read()[:20])\n",
        encoding="utf-8",
    )

    findings = _command_findings(root)
    proof_findings = [
        finding
        for finding in findings
        if finding.confidence == "high"
        and "python_ast_proven_unguarded" in finding.evidence
    ]
    guarded = next(
        finding
        for finding in findings
        if Path(finding.file).name == "views.py"
        and finding.line_start == 6
    )

    assert {
        (Path(finding.file).name, finding.line_start)
        for finding in proof_findings
    } == {
        ("falcon_app.py", 6),
        ("quart_app.py", 6),
        ("views.py", 9),
    }
    assert guarded.confidence == "high"
    assert (
        "python_ast_proven_weak_prefix_guard_cross_file_command"
        in guarded.evidence
    )


def test_python_command_weak_prefix_guard_proof_fails_closed(tmp_path):
    service_source = (
        "import os\n"
        "def run(command):\n"
        "    return os.system(command)\n"
    )
    route_template = (
        "from flask import request\n"
        "{imports}\n"
        "def route():\n"
        "    command = request.args.get('command')\n"
        "{body}"
    )
    weak_guard = (
        "def allowed(command):\n"
        "    if command.startswith(('echo', 'ps')):\n"
        "        return True\n"
        "    return False\n"
    )
    variants = {
        "membership": {
            "guard.py": (
                "def allowed(command):\n"
                "    return command in {'echo', 'ps'}\n"
            ),
        },
        "equality": {
            "guard.py": (
                "def allowed(command):\n"
                "    if command == 'echo' or command == 'ps':\n"
                "        return True\n"
                "    return False\n"
            ),
        },
        "additional-strict": {
            "guard.py": (
                "def allowed(command):\n"
                "    if command.startswith(('echo', 'ps')):\n"
                "        if command in {'echo', 'ps'}:\n"
                "            return True\n"
                "    return False\n"
            ),
        },
        "dynamic-prefix": {
            "guard.py": (
                "PREFIXES = ('echo', 'ps')\n"
                "def allowed(command):\n"
                "    if command.startswith(PREFIXES):\n"
                "        return True\n"
                "    return False\n"
            ),
        },
        "decorated": {
            "guard.py": (
                "def marker(function):\n"
                "    return function\n"
                "@marker\n"
                f"{weak_guard}"
            ),
        },
        "rebound": {
            "guard.py": (
                f"{weak_guard}"
                "allowed = lambda command: True\n"
            ),
        },
        "different-parameter": {
            "guard.py": weak_guard,
            "route_body": (
                "    other = request.args.get('other')\n"
                "    if allowed(other):\n"
                "        run(command)\n"
            ),
        },
        "quoted": {
            "guard.py": weak_guard,
            "route_imports": (
                "import shlex\n"
                "from guard import allowed\n"
                "from service import run"
            ),
            "route_body": (
                "    if allowed(command):\n"
                "        run(shlex.quote(command))\n"
            ),
        },
        "constant-mapped": {
            "guard.py": weak_guard,
            "route_body": (
                "    if allowed(command):\n"
                "        run({'echo': 'echo', 'ps': 'ps'}.get(command))\n"
            ),
        },
        "ambiguous-import": {
            "first.py": weak_guard,
            "second.py": weak_guard,
            "route_imports": (
                "from first import allowed\n"
                "from second import allowed\n"
                "from service import run"
            ),
        },
        "monkey-patched": {
            "guard.py": weak_guard,
            "route_imports": (
                "import guard\n"
                "from service import run\n"
                "guard.allowed = lambda command: True"
            ),
            "route_body": (
                "    if guard.allowed(command):\n"
                "        run(command)\n"
            ),
        },
    }
    default_imports = "from guard import allowed\nfrom service import run"
    default_body = (
        "    if allowed(command):\n"
        "        run(command)\n"
    )
    for name, files in variants.items():
        unsafe = tmp_path / f"{name}-unsafe"
        negative = tmp_path / f"{name}-negative"
        for root, guard_files in (
            (unsafe, {"guard.py": weak_guard}),
            (negative, files),
        ):
            root.mkdir()
            (root / "service.py").write_text(
                service_source,
                encoding="utf-8",
            )
            for filename, source in guard_files.items():
                if filename.startswith("route_"):
                    continue
                (root / filename).write_text(source, encoding="utf-8")
            (root / "route.py").write_text(
                route_template.format(
                    imports=(
                        default_imports
                        if root is unsafe
                        else files.get(
                            "route_imports",
                            default_imports,
                        )
                    ),
                    body=(
                        default_body
                        if root is unsafe
                        else files.get("route_body", default_body)
                    ),
                ),
                encoding="utf-8",
            )

        assert len(_proven_weak_prefix_command_findings(unsafe)) == 1
        assert _proven_weak_prefix_command_findings(negative) == []
        assert all(
            finding.confidence == "medium"
            for finding in _command_findings(negative)
        )


def test_python_command_proof_rejects_constant_helper_pair(tmp_path):
    unsafe = tmp_path / "unsafe"
    safe = tmp_path / "safe"
    for root, command in (
        (unsafe, "os.system(command)"),
        (safe, "os.system('date')"),
    ):
        root.mkdir()
        (root / "service.py").write_text(
            "import os\n"
            "def run(command):\n"
            f"    return {command}\n",
            encoding="utf-8",
        )
        (root / "route.py").write_text(
            "from flask import request\n"
            "from service import run\n"
            "def route():\n"
            "    run(request.args.get('command'))\n",
            encoding="utf-8",
        )

    assert len(_proven_command_findings(unsafe)) == 1
    assert _proven_command_findings(safe) == []


def test_python_command_proof_rejects_allowlist_pairs(tmp_path):
    unsafe = tmp_path / "unsafe"
    active_guard = tmp_path / "active-guard"
    post_guard = tmp_path / "post-guard"
    variants = {
        unsafe: "    os.system(command)\n",
        active_guard: (
            "    if command in {'date', 'uptime'}:\n"
            "        os.system(command)\n"
        ),
        post_guard: (
            "    if command not in {'date', 'uptime'}:\n"
            "        return\n"
            "    os.system(command)\n"
        ),
    }
    for root, body in variants.items():
        root.mkdir()
        (root / "route.py").write_text(
            "import os\n"
            "from flask import request\n"
            "def route():\n"
            "    command = request.args.get('command')\n"
            f"{body}",
            encoding="utf-8",
        )

    assert len(_proven_command_findings(unsafe)) == 1
    assert _proven_command_findings(active_guard) == []
    assert _proven_command_findings(post_guard) == []
    assert all(
        finding.confidence == "medium"
        for root in (active_guard, post_guard)
        for finding in _command_findings(root)
    )


def test_python_command_proof_rejects_structured_argv_pair(tmp_path):
    unsafe = tmp_path / "unsafe"
    safe = tmp_path / "safe"
    unsafe.mkdir()
    safe.mkdir()
    (unsafe / "route.py").write_text(
        "import os\n"
        "from flask import request\n"
        "def route():\n"
        "    command = request.args.get('command')\n"
        "    os.system(command)\n",
        encoding="utf-8",
    )
    (safe / "route.py").write_text(
        "import subprocess\n"
        "from flask import request\n"
        "def route():\n"
        "    subprocess.run(\n"
        "        ['convert', request.args.get('filename')],\n"
        "        shell=False,\n"
        "    )\n",
        encoding="utf-8",
    )

    assert len(_proven_command_findings(unsafe)) == 1
    assert _proven_command_findings(safe) == []


def test_python_command_proof_rejects_ambiguous_import_pair(tmp_path):
    unsafe = tmp_path / "unsafe"
    ambiguous = tmp_path / "ambiguous"
    for root in (unsafe, ambiguous):
        root.mkdir()
        for module in ("first", "second"):
            (root / f"{module}.py").write_text(
                "import os\n"
                "def run(command):\n"
                "    return os.system(command)\n",
                encoding="utf-8",
            )
    (unsafe / "route.py").write_text(
        "from flask import request\n"
        "from first import run\n"
        "def route():\n"
        "    run(request.args.get('command'))\n",
        encoding="utf-8",
    )
    (ambiguous / "route.py").write_text(
        "from flask import request\n"
        "from first import run\n"
        "from second import run\n"
        "def route():\n"
        "    run(request.args.get('command'))\n",
        encoding="utf-8",
    )

    assert len(_proven_command_findings(unsafe)) == 1
    assert _proven_command_findings(ambiguous) == []


def test_python_command_proof_rejects_rebound_helper_pair(tmp_path):
    stable = tmp_path / "stable"
    rebound = tmp_path / "rebound"
    monkey_patched = tmp_path / "monkey-patched"
    for root in (stable, rebound, monkey_patched):
        root.mkdir()
        (root / "service.py").write_text(
            "import os\n"
            "def run(command):\n"
            "    return os.system(command)\n",
            encoding="utf-8",
        )
    (stable / "route.py").write_text(
        "from flask import request\n"
        "from service import run\n"
        "def route():\n"
        "    run(request.args.get('command'))\n",
        encoding="utf-8",
    )
    (rebound / "route.py").write_text(
        "from flask import request\n"
        "from service import run\n"
        "run = lambda command: command\n"
        "def route():\n"
        "    run(request.args.get('command'))\n",
        encoding="utf-8",
    )
    (monkey_patched / "route.py").write_text(
        "from flask import request\n"
        "import service\n"
        "service.run = lambda command: command\n"
        "def route():\n"
        "    service.run(request.args.get('command'))\n",
        encoding="utf-8",
    )

    assert len(_proven_command_findings(stable)) == 1
    assert _proven_command_findings(rebound) == []
    assert _proven_command_findings(monkey_patched) == []
