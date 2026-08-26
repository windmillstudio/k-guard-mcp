from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import pytest

from k_guard_mcp.dashboard import DASHBOARD_CSRF_TOKEN, DashboardHandler, _dashboard_html, main


def test_dashboard_exposure_map_uses_svg_dom_nodes_instead_of_inner_html() -> None:
    html = _dashboard_html()

    assert "document.createElementNS(SVG_NS" in html
    assert "box.replaceChildren(svg)" in html
    assert "box.innerHTML" not in html


def test_dashboard_rejects_cross_origin_scan_before_target_probe() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = json.dumps({"url": "http://127.0.0.1:9", "authorized": True}).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/api/scan",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-K-Guard-CSRF": DASHBOARD_CSRF_TOKEN,
                "Origin": "https://attacker.example",
                "Sec-Fetch-Site": "cross-site",
            },
            method="POST",
        )
        with patch("k_guard_mcp.dashboard.scan_url") as scan:
            with pytest.raises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=5)
            assert raised.value.code == 403
            scan.assert_not_called()
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_dashboard_rejects_non_json_scan_before_target_probe() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/api/scan",
            data=b'{"url":"http://127.0.0.1:9"}',
            headers={"Content-Type": "text/plain", "X-K-Guard-CSRF": DASHBOARD_CSRF_TOKEN},
            method="POST",
        )
        with patch("k_guard_mcp.dashboard.scan_url") as scan:
            with pytest.raises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=5)
            assert raised.value.code == 403
            scan.assert_not_called()
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_dashboard_refuses_non_loopback_bind() -> None:
    with pytest.raises(SystemExit) as raised:
        main(["--host", "0.0.0.0", "--port", "0"])

    assert raised.value.code == 2
