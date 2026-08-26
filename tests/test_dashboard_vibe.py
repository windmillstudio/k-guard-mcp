from __future__ import annotations

import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from k_guard_mcp.dashboard import DashboardHandler, _dashboard_html, _scope_html


def test_glasses_senpai_dashboard_keeps_the_operational_workbench_first() -> None:
    html = _dashboard_html()

    assert '/assets/glasses-senpai-hero.png' in html
    assert '<title>안경선배 | 사이트 동적 검수</title>' in html
    assert '<a href="/">사이트 점검</a>' in html
    assert '일단 만들어. 출하 전에는 선배가 본다.' in html
    assert 'id="results" class="panel" aria-live="polite" aria-busy="false"' in html
    assert 'WAITING_FOR_TARGET' in html
    assert 'HOLD_FIX' in html
    assert 'DYNAMIC_REVIEW_CLEAR' in html
    assert '요청 오류가 있어 발견 없음이나 정상으로 판정하지 않았습니다.' in html
    assert 'error.message' not in html
    assert "item.status === 'unknown'" in html
    assert 'DYNAMIC_REVIEW_HAS_FINDINGS' in html
    assert 'check_my_app → continue_review' in html
    assert '배포 버튼 누르기 전, 한 번 더 보는 선배' in html
    assert '실전 단련 기록' in html
    assert '최신 실효성 게이트는 출하 보류입니다.' in html
    assert '28개' in html
    assert '1,000곳' in html
    assert '85.7%' in html
    assert '30.0%' in html
    assert '실제 문제 3개, 오탐 7개' in html
    assert "technical.appendChild(text('summary', '기술 근거 보기'))" in html
    assert "labels[code] || code" in html
    assert html.count('이 화면에서 확인 안 됨') == 2
    assert 'id="dynamicStageStatus" class="pending" aria-live="polite">현재 화면 · 실행 전' in html
    assert "setDynamicStage('running', '현재 화면 · 검사 중')" in html
    assert "setDynamicStage('failed', '중단 · 검수 미완료')" in html
    assert "findingCount ? 'review' : 'complete'" in html
    assert 'role="tablist" aria-label="검수 결과 보기"' in html
    assert 'role="tab" tabindex="-1"' in html
    assert "event.key === 'ArrowRight'" in html
    assert 'data-panel="findings"' in html
    assert 'data-panel="log"' in html
    assert 'data-panel="map"' in html
    assert '@media (max-width: 680px)' in html
    assert 'min-width: 320px' not in html
    assert 'min-width: 0;' in html
    assert '.workbench { order: 3; }' in html
    assert '.scope-brief { order: 4; }' in html
    assert 'grid-template-columns: minmax(310px, 370px) minmax(0, 1fr)' in html
    assert 'font-size: 40px' in html
    assert 'letter-spacing: 0' in html
    assert '--bg: #f7f7f4' in html
    assert 'color-scheme: light' in html


def test_scope_page_uses_the_same_brand_and_claim_boundary() -> None:
    html = _scope_html()

    assert '/assets/glasses-senpai-hero.png' in html
    assert '안경선배가 어디까지 보는지' in html
    assert 'Guardian 네 영역' in html
    assert '사이트' in html
    assert 'API 노출' in html
    assert '데이터 관리' in html
    assert '운영 위험' in html
    assert '인간의 사업 판단이나 무결점 보증을 대신하지 않으며' in html
    assert '지금까지의 실전 기록' in html
    assert '최신 실효성 게이트 판정은 HOLD' in html
    assert '과거 OWASP Python 지원 부분집합 후보 정밀도는 81.6%' in html
    assert 'stdio JSON-RPC와 공식 SDK 기반 Streamable HTTP' in html
    assert 'line-delimited stdio JSON-RPC에 한정됩니다' not in html
    assert 'min-width:320px' not in html
    assert 'min-width:0' in html


def test_dashboard_serves_packaged_brand_asset() -> None:
    asset = Path(__file__).parents[1] / 'src' / 'k_guard_mcp' / 'assets' / 'glasses-senpai-hero.png'
    expected_size = asset.stat().st_size
    assert expected_size > 100_000

    server = ThreadingHTTPServer(('127.0.0.1', 0), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = urllib.request.urlopen(
            f'http://127.0.0.1:{server.server_port}/assets/glasses-senpai-hero.png',
            timeout=5,
        )
        payload = response.read()
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert response.status == 200
    assert response.headers.get_content_type() == 'image/png'
    assert len(payload) == expected_size
    assert payload.startswith(b'\x89PNG\r\n\x1a\n')


def test_dashboard_responses_enforce_nonce_csp_and_browser_boundaries() -> None:
    server = ThreadingHTTPServer(('127.0.0.1', 0), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}/', timeout=5)
        html = response.read().decode('utf-8')
    finally:
        server.shutdown()
        thread.join(timeout=5)

    csp = response.headers['Content-Security-Policy']
    assert "default-src 'none'" in csp
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "script-src 'nonce-" in csp
    assert "style-src 'nonce-" in csp
    assert "'unsafe-inline'" not in csp
    assert '<style nonce="' in html
    assert '<script nonce="' in html
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['Referrer-Policy'] == 'no-referrer'
    assert response.headers['Permissions-Policy'] == 'camera=(), microphone=(), geolocation=()'
    assert response.headers['Cache-Control'] == 'no-store'
