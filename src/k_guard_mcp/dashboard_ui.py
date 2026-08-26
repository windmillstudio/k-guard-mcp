from __future__ import annotations

import json
from typing import Any


def render_dashboard(
    checks: list[dict[str, Any]],
    non_goals: list[str],
    active_paths: list[str],
    active_deep_paths: list[str],
    verification: dict[str, Any],
) -> str:
    replacements = {
        "__CHECKS__": json.dumps(checks, ensure_ascii=False),
        "__NON_GOALS__": json.dumps(non_goals, ensure_ascii=False),
        "__ACTIVE_PATHS__": json.dumps(active_paths, ensure_ascii=False),
        "__ACTIVE_DEEP_PATHS__": json.dumps(active_deep_paths, ensure_ascii=False),
        "__VERIFY__": json.dumps(verification, ensure_ascii=False),
    }
    html = DASHBOARD_TEMPLATE
    for marker, value in replacements.items():
        html = html.replace(marker, value)
    return html


def render_scope() -> str:
    return SCOPE_TEMPLATE


DASHBOARD_TEMPLATE = r"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#f7f7f4">
  <title>안경선배 | 사이트 동적 검수</title>
  <style>
    :root {
      --bg: #f7f7f4;
      --surface: #ffffff;
      --surface-2: #f0f2ee;
      --ink: #1d211f;
      --muted: #626964;
      --line: #d7dcd7;
      --line-strong: #aeb6af;
      --green: #176b4a;
      --cyan: #246a91;
      --pink: #9f3042;
      --flannel: #b23346;
      --danger: #b42332;
      --warn: #9a5a00;
      --ok: #176b4a;
      --soft-red: #fff1f2;
      --soft-green: #edf8f2;
      --soft-blue: #edf6fa;
    }
    * { box-sizing: border-box; }
    html { color-scheme: light; }
    body {
      margin: 0;
      min-width: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: "Pretendard", "Noto Sans KR", Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    button, input { font: inherit; }
    button:focus-visible, input:focus-visible, summary:focus-visible, a:focus-visible {
      outline: 3px solid var(--cyan);
      outline-offset: 2px;
    }
    a { color: inherit; }
    .shell { width: min(1240px, 100%); margin: 0 auto; padding: 14px 22px 44px; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 18px; min-height: 52px; border-bottom: 1px solid var(--line); }
    .brand { display: flex; align-items: baseline; gap: 12px; min-width: 0; }
    .brand strong { color: var(--ink); font-size: 21px; }
    .brand span { color: var(--flannel); font: 750 11px ui-monospace, SFMono-Regular, Consolas, monospace; }
    nav { display: flex; gap: 6px; }
    nav a { padding: 8px 10px; border-radius: 5px; color: var(--muted); font-size: 13px; font-weight: 750; text-decoration: none; }
    nav a:hover { color: var(--flannel); background: var(--surface-2); }
    .mentor-strip { display: grid; grid-template-columns: 190px minmax(0, 1fr) 245px; min-height: 208px; margin-top: 14px; overflow: hidden; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); }
    .mentor-visual { margin: 0; min-width: 0; overflow: hidden; border-right: 1px solid var(--line); }
    .mentor-visual img { width: 100%; height: 100%; display: block; object-fit: cover; object-position: 49% 29%; filter: saturate(.92) contrast(1.04); }
    .mentor-copy { display: flex; flex-direction: column; justify-content: center; min-width: 0; padding: 22px 30px; }
    .eyebrow { margin-bottom: 9px; color: var(--flannel); font: 800 11px ui-monospace, SFMono-Regular, Consolas, monospace; }
    h1 { margin: 0; max-width: 780px; font-size: 40px; line-height: 1.12; letter-spacing: 0; }
    .mentor-copy p { max-width: 720px; margin: 13px 0 0; color: var(--muted); font-size: 15px; line-height: 1.65; }
    .mentor-terminal { align-self: center; margin: 20px 18px 20px 0; padding: 15px 16px; border: 1px solid var(--line); border-left: 4px solid var(--flannel); border-radius: 6px; background: #fafaf8; font: 12px/1.7 ui-monospace, SFMono-Regular, Consolas, monospace; }
    .mentor-terminal b { display: block; color: var(--ink); font-size: 14px; }
    .mentor-terminal span { display: block; color: var(--muted); }
    .mentor-terminal .online { color: var(--green); }
    .scope-brief { display: grid; grid-template-columns: minmax(0, 1fr) minmax(280px, 1fr); align-items: center; gap: 10px 20px; margin-top: 14px; padding: 14px 16px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); }
    .scope-brief h2 { margin: 0; font-size: 15px; color: var(--ink); }
    .scope-brief p { margin: 0; color: var(--muted); font-size: 13px; line-height: 1.5; text-align: right; }
    .review-stages { grid-column: 1 / -1; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); border-top: 1px solid var(--line); }
    .review-stage { min-width: 0; padding: 10px 12px 0 0; color: var(--muted); font: 11px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace; }
    .review-stage + .review-stage { padding-left: 12px; border-left: 1px solid var(--line); }
    .review-stage b { display: block; color: var(--ink); font-size: 12px; }
    .review-stage .pending { color: var(--warn); }
    .review-stage .unknown { color: var(--muted); }
    .review-stage .running { color: var(--cyan); }
    .review-stage .complete { color: var(--ok); }
    .review-stage .review { color: var(--warn); }
    .review-stage .failed { color: var(--danger); }
    .workbench { display: grid; grid-template-columns: minmax(310px, 370px) minmax(0, 1fr); margin-top: 14px; overflow: hidden; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); }
    .panel { min-width: 0; padding: 24px; }
    .scan-box { border-right: 1px solid var(--line); background: #fafaf8; }
    .panel-kicker { margin: 0 0 6px; color: var(--flannel); font: 800 11px ui-monospace, SFMono-Regular, Consolas, monospace; }
    h2 { margin: 0; font-size: 18px; letter-spacing: 0; }
    .section-note { margin: 7px 0 0; color: var(--muted); font-size: 13px; line-height: 1.55; }
    .field { margin-top: 22px; }
    label { display: block; margin-bottom: 7px; color: var(--ink); font-size: 13px; font-weight: 750; }
    input[type="url"] { width: 100%; height: 46px; border: 1px solid var(--line-strong); border-radius: 5px; padding: 0 12px; background: var(--surface); color: var(--ink); font-size: 15px; }
    input[type="url"]::placeholder { color: #8b918d; }
    .toggle-row { display: grid; grid-template-columns: 34px minmax(0, 1fr); gap: 10px; align-items: start; margin-top: 15px; cursor: pointer; }
    .toggle-row input { position: absolute; opacity: 0; pointer-events: none; }
    .toggle { position: relative; width: 34px; height: 19px; margin-top: 1px; border: 1px solid var(--line-strong); border-radius: 10px; background: #e3e6e2; }
    .toggle::after { content: ""; position: absolute; top: 3px; left: 3px; width: 11px; height: 11px; border-radius: 50%; background: #7d857f; transition: transform .16s ease, background .16s ease; }
    .toggle-row input:checked + .toggle { border-color: var(--green); background: #d7eee2; }
    .toggle-row input:checked + .toggle::after { transform: translateX(15px); background: var(--green); }
    .toggle-row input:focus-visible + .toggle { outline: 3px solid var(--cyan); outline-offset: 2px; }
    .toggle-copy strong { display: block; font-size: 13px; }
    .toggle-copy span { display: block; margin-top: 3px; color: var(--muted); font-size: 12px; line-height: 1.45; }
    .scan-action { width: 100%; height: 46px; margin-top: 20px; border: 1px solid var(--flannel); border-radius: 5px; background: var(--flannel); color: #fff; font-weight: 850; cursor: pointer; }
    .scan-action:hover { border-color: #8d2234; background: #8d2234; }
    .scan-action:disabled { opacity: .55; cursor: wait; }
    details { margin-top: 18px; border-top: 1px solid var(--line); padding-top: 14px; }
    summary { color: var(--cyan); cursor: pointer; font-size: 13px; font-weight: 750; }
    .advanced { display: grid; gap: 16px; margin-top: 14px; }
    .advanced h3 { margin: 0 0 7px; font-size: 13px; }
    .code { padding: 10px; border: 1px solid var(--line); border-radius: 5px; background: #f4f5f2; color: #4e5650; font: 11px/1.55 ui-monospace, SFMono-Regular, Consolas, monospace; overflow-wrap: anywhere; }
    .paths { display: flex; flex-wrap: wrap; gap: 5px; }
    .pill { padding: 4px 7px; border: 1px solid var(--line); border-radius: 4px; color: #bec8c0; font: 11px ui-monospace, SFMono-Regular, Consolas, monospace; }
    #results { background: var(--surface); }
    .result-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; }
    .result-head p { margin: 7px 0 0; color: var(--muted); font-size: 13px; }
    .status-light { flex: 0 0 auto; padding: 5px 8px; border: 1px solid var(--line); border-radius: 4px; color: var(--muted); font: 700 11px ui-monospace, SFMono-Regular, Consolas, monospace; }
    .status-light.busy { color: var(--warn); border-color: #70552c; }
    .status-light.done { color: var(--ok); border-color: #2f6848; }
    #status { min-height: 96px; margin-top: 18px; padding: 18px 18px 17px; border: 1px solid #b9d4c7; border-left: 5px solid var(--green); border-radius: 5px; background: var(--soft-green); }
    #status .verdict-code { display: block; margin-bottom: 7px; color: var(--green); font: 800 11px ui-monospace, SFMono-Regular, Consolas, monospace; }
    #status .verdict-copy { display: block; max-width: 760px; color: var(--ink); font-size: 17px; font-weight: 800; line-height: 1.5; }
    #status.error { border-color: #e2b5bb; border-left-color: var(--danger); background: var(--soft-red); color: var(--ink); }
    #status.error .verdict-code { color: var(--danger); }
    #status.empty { color: var(--ink); }
    .metrics { display: grid; grid-template-columns: repeat(5, minmax(72px, 1fr)); gap: 1px; margin-top: 14px; border: 1px solid var(--line); background: var(--line); }
    .metric { min-width: 0; min-height: 70px; padding: 11px; background: #fafaf8; }
    .metric strong { display: block; margin-bottom: 5px; font: 800 22px ui-monospace, SFMono-Regular, Consolas, monospace; }
    .metric span { color: var(--muted); font-size: 11px; text-transform: uppercase; }
    .metric.critical strong, .metric.high strong { color: var(--danger); }
    .metric.medium strong { color: var(--warn); }
    .metric.low strong { color: var(--cyan); }
    .metric.info strong { color: var(--ok); }
    .tabs { display: flex; gap: 3px; margin-top: 18px; border-bottom: 1px solid var(--line); }
    .tab { min-height: 38px; padding: 0 12px; border: 0; border-bottom: 2px solid transparent; background: transparent; color: var(--muted); font-size: 12px; font-weight: 750; cursor: pointer; }
    .tab:hover { color: var(--ink); }
    .tab[aria-selected="true"] { border-bottom-color: var(--green); color: var(--green); }
    .tab-panel { min-height: 180px; padding-top: 14px; }
    .tab-panel[hidden] { display: none; }
    .finding { padding: 14px 2px; border-bottom: 1px solid var(--line); }
    .finding:first-child { padding-top: 2px; }
    .finding h3 { margin: 0 0 6px; color: var(--ink); font-size: 14px; }
    .finding h4 { margin: 13px 0 0; color: var(--ink); font-size: 12px; }
    .finding.critical h3, .finding.high h3 { color: var(--danger); }
    .finding.medium h3 { color: var(--warn); }
    .finding p { margin: 0; color: #4e5650; font-size: 13px; line-height: 1.6; }
    .finding dl { display: grid; grid-template-columns: 92px minmax(0, 1fr); gap: 6px 12px; margin: 12px 0 0; font-size: 12px; }
    .finding dt { color: #788079; }
    .finding dd { margin: 0; color: #343a36; overflow-wrap: anywhere; }
    .finding details { margin-top: 12px; }
    .steps { margin: 11px 0 0; padding-left: 20px; color: #343a36; font-size: 12px; line-height: 1.65; }
    .empty-note { min-height: 120px; display: grid; place-items: center; padding: 22px; border: 1px dashed var(--line); color: var(--ok); font-size: 13px; text-align: center; }
    .audit-wrap, .flow-wrap { min-width: 0; }
    .audit-head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
    .audit-head strong { font-size: 13px; }
    .audit-head span { color: var(--muted); font-size: 11px; }
    .audit-list { max-height: 430px; overflow: auto; }
    .audit-row { padding: 12px 2px; border-bottom: 1px solid var(--line); }
    .audit-title { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; font-size: 12px; font-weight: 750; }
    .audit-meta, .audit-outcome { margin-top: 5px; color: var(--muted); font-size: 11px; line-height: 1.5; overflow-wrap: anywhere; }
    .audit-outcome { color: #3f4741; }
    .badge { padding: 2px 6px; border: 1px solid var(--line); border-radius: 4px; color: #5e665f; font: 700 10px ui-monospace, SFMono-Regular, Consolas, monospace; }
    .badge.pass { color: var(--ok); border-color: #2f6848; }
    .badge.finding { color: var(--warn); border-color: #70552c; }
    .badge.review { color: var(--cyan); border-color: #315f70; }
    .badge.error { color: var(--danger); border-color: #783932; }
    .flow-wrap svg { width: 100%; height: auto; display: block; }
    .proof-band { margin-top: 14px; padding: 22px 24px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); }
    .proof-head { display: flex; justify-content: space-between; gap: 24px; align-items: end; }
    .proof-head p { max-width: 620px; margin: 0; color: var(--muted); font-size: 12px; line-height: 1.55; text-align: right; }
    .proof-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 16px; border: 1px solid var(--line); }
    .proof-item { min-width: 0; padding: 14px; background: #fafaf8; }
    .proof-item + .proof-item { border-left: 1px solid var(--line); }
    .proof-item strong { display: block; color: var(--ink); font-size: 20px; }
    .proof-item b { display: block; margin-top: 5px; color: var(--flannel); font-size: 12px; }
    .proof-item span { display: block; margin-top: 5px; color: var(--muted); font-size: 11px; line-height: 1.5; }
    .proof-warning { margin: 14px 0 0; padding: 11px 13px; border-left: 4px solid var(--warn); background: #fff8e8; color: #604817; font-size: 12px; line-height: 1.55; }
    .checks-panel { margin-top: 14px; overflow: visible; padding: 22px 24px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); }
    .checks-panel .checks { grid-template-columns: repeat(2, minmax(0, 1fr));
      display: grid; gap: 0 28px; margin-top: 13px; }
    .check-card { min-width: 0; padding: 12px 0; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
    .check-card strong { display: block; margin-bottom: 4px; font-size: 13px; }
    .check-card span { display: block; color: var(--muted); font-size: 11px; line-height: 1.5; }
    .rule-list { display: block; margin-top: 5px; color: #6f7771; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
    .footer-note { margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--line); color: #747c76; font-size: 11px; line-height: 1.6; }
    @media (max-width: 960px) {
      .mentor-strip { grid-template-columns: 150px minmax(0, 1fr); }
      .mentor-terminal { display: none; }
      .workbench { grid-template-columns: 1fr; }
      .scan-box { border-right: 0; border-bottom: 1px solid var(--line); }
      .proof-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .proof-item:nth-child(3) { border-left: 0; border-top: 1px solid var(--line); }
      .proof-item:nth-child(4) { border-top: 1px solid var(--line); }
    }
    @media (max-width: 680px) {
      .shell { display: flex; flex-direction: column; padding: 10px 14px 30px; }
      .topbar { order: 1; }
      .mentor-strip { order: 2; }
      .workbench { order: 3; }
      .scope-brief { order: 4; }
      .proof-band { order: 5; }
      .checks-panel { order: 6; }
      .footer-note { order: 7; }
      .topbar { align-items: flex-start; padding: 8px 0 12px; }
      .brand { display: block; }
      .brand span { display: block; margin-top: 3px; }
      nav a { padding: 7px 5px; }
      .mentor-strip { grid-template-columns: 88px minmax(0, 1fr); min-height: 174px; }
      .mentor-copy { padding: 18px 16px; }
      h1 { font-size: 27px; }
      .mentor-copy p { font-size: 13px; line-height: 1.55; }
      .scope-brief { display: block; }
      .scope-brief p { margin-top: 7px; text-align: left; }
      .review-stages { grid-template-columns: 1fr; margin-top: 12px; }
      .review-stage { padding: 8px 0; }
      .review-stage + .review-stage { padding-left: 0; border-left: 0; border-top: 1px solid var(--line); }
      .panel { padding: 20px 14px; }
      .metrics { grid-template-columns: repeat(5, minmax(54px, 1fr)); overflow-x: auto; }
      .metric { padding: 9px 7px; }
      .metric strong { font-size: 19px; }
      .tab { flex: 1 1 0; padding: 0 4px; }
      .finding dl { grid-template-columns: 76px minmax(0, 1fr); }
      .checks-panel .checks { grid-template-columns: 1fr; }
      .proof-band, .checks-panel { padding: 19px 14px; }
      .proof-head { display: block; }
      .proof-head p { margin-top: 7px; text-align: left; }
      .proof-grid { grid-template-columns: 1fr; }
      .proof-item + .proof-item, .proof-item:nth-child(3), .proof-item:nth-child(4) { border-left: 0; border-top: 1px solid var(--line); }
    }
  </style>
</head>
<body>
<main class="shell">
  <header class="topbar">
    <div class="brand"><strong>안경선배</strong><span>VIBE CODING RELEASE REVIEW</span></div>
    <nav aria-label="주요 메뉴"><a href="/">사이트 점검</a><a href="/scope">검수 범위</a></nav>
  </header>

  <section class="mentor-strip" aria-labelledby="hero-title">
    <figure class="mentor-visual"><img src="/assets/glasses-senpai-hero.png" alt="안경선배 바이브코딩 선배 작업실" width="1003" height="1568"></figure>
    <div class="mentor-copy">
      <span class="eyebrow">배포 버튼 누르기 전, 한 번 더 보는 선배</span>
      <h1 id="hero-title">일단 만들어. 출하 전에는 선배가 본다.</h1>
      <p>어려운 말로 겁주지 않습니다. 지금 막아야 할 것, 왜 문제인지, 무엇부터 고칠지만 분명하게 말합니다.</p>
    </div>
    <div class="mentor-terminal" aria-label="안경선배 설정 기준">
      <b>안경선배가 지키는 순서</b>
      <span class="online">1. 출하 가능 여부</span>
      <span>2. 지금 고칠 것</span>
      <span>3. 확인한 근거</span>
    </div>
  </section>

  <section class="scope-brief">
    <h2>이 화면은 사이트를 빠르게 보고, 전체 출하 판정은 MCP에서 끝냅니다.</h2>
    <p>사이트 응답 점검과 코드·설정·데이터 전체 검수는 서로 다른 단계입니다. 확인하지 못한 범위는 통과로 세지 않습니다.</p>
    <div class="review-stages" aria-label="검수 단계 상태">
      <div class="review-stage"><b>1. MCP 전체검수</b><span class="unknown">이 화면에서 확인 안 됨 · check_my_app → continue_review</span></div>
      <div class="review-stage"><b>2. 사이트 응답</b><span id="dynamicStageStatus" class="pending" aria-live="polite">현재 화면 · 실행 전</span></div>
      <div class="review-stage"><b>3. 출하 게이트</b><span class="unknown">이 화면에서 확인 안 됨 · start_review_before_ship → continue_review</span></div>
    </div>
  </section>

  <div class="workbench">
    <section class="panel scan-box" aria-labelledby="scan-title">
      <p class="panel-kicker">사이트 빠른 점검</p>
      <h2 id="scan-title">검수할 주소를 넣어주세요</h2>
      <p class="section-note">로컬 개발 서버 또는 점검 권한이 있는 사이트만 넣어주세요.</p>
      <div class="field">
        <label for="url">검수할 사이트</label>
        <input id="url" type="url" placeholder="http://127.0.0.1:3000" autocomplete="off" inputmode="url">
      </div>
      <label class="toggle-row">
        <input id="authorized" type="checkbox">
        <span class="toggle" aria-hidden="true"></span>
        <span class="toggle-copy"><strong>점검 권한 확인</strong><span>내 앱, 파트너 승인, 공개 점검 범위 중 하나에 해당합니다.</span></span>
      </label>
      <label class="toggle-row">
        <input id="deepActive" type="checkbox">
        <span class="toggle" aria-hidden="true"></span>
        <span class="toggle-copy"><strong>민감 경로도 보기</strong><span>.env, .git, 백업, 디버그처럼 자주 놓치는 고정 경로를 더 봅니다.</span></span>
      </label>
      <button id="scan" class="scan-action" type="button">선배 검수 시작</button>
      <details>
        <summary>고급 검수 범위</summary>
        <div class="advanced">
          <div><h3>권한 근거</h3><div id="verification" class="code"></div></div>
          <div><h3>실행 경로</h3><div id="paths" class="paths"></div></div>
          <div><h3>점검하지 않는 것</h3><div id="nonGoals"></div></div>
        </div>
      </details>
    </section>

    <section id="results" class="panel" aria-live="polite" aria-busy="false">
      <div class="result-head">
        <div><p class="panel-kicker">검수 결과</p><h2>지금 출하해도 될까요?</h2><p>결론을 먼저 말하고, 고칠 것과 근거를 차례로 보여드립니다.</p></div>
        <span id="statusLight" class="status-light">준비</span>
      </div>
      <div id="status" class="empty" role="status" aria-live="polite" aria-atomic="true">
        <span class="verdict-code" data-code="WAITING_FOR_TARGET">점검 전</span>
        <span class="verdict-copy">주소를 넣으면 배포 전에 막아야 할 문제부터 확인합니다.</span>
      </div>
      <div id="metrics" class="metrics" hidden></div>
      <div class="tabs" role="tablist" aria-label="검수 결과 보기">
        <button class="tab" id="tab-findings" type="button" role="tab" tabindex="0" aria-selected="true" aria-controls="panel-findings" data-panel="findings">지금 고칠 것</button>
        <button class="tab" id="tab-log" type="button" role="tab" tabindex="-1" aria-selected="false" aria-controls="panel-log" data-panel="log">확인한 근거</button>
        <button class="tab" id="tab-map" type="button" role="tab" tabindex="-1" aria-selected="false" aria-controls="panel-map" data-panel="map">노출 경로</button>
      </div>
      <div id="panel-findings" class="tab-panel" role="tabpanel" aria-labelledby="tab-findings"><div id="findings" aria-live="polite" aria-relevant="additions text"><div class="empty-note">아직 검수를 시작하지 않았습니다.</div></div></div>
      <div id="panel-log" class="tab-panel" role="tabpanel" aria-labelledby="tab-log" hidden><div id="auditLog" class="audit-wrap"></div></div>
      <div id="panel-map" class="tab-panel" role="tabpanel" aria-labelledby="tab-map" hidden><div id="exposureMap" class="flow-wrap"></div></div>
    </section>
  </div>

  <section class="proof-band" aria-labelledby="proof-title">
    <div class="proof-head"><div><p class="panel-kicker">실전 단련 기록</p><h2 id="proof-title">좋아진 것과 아직 부족한 것을 같이 공개합니다</h2></div><p>숫자는 취약점 보증률이 아니라, 고정된 공개 자료에서 어떤 조건으로 반복 검증했는지를 보여 주는 기록입니다.</p></div>
    <div class="proof-grid">
      <div class="proof-item"><strong>28개</strong><b>공개 취약 앱 누적</b><span>12개 개발 캠페인과 새 16개 다언어 앱을 각각 두 번 재현했습니다.</span></div>
      <div class="proof-item"><strong>1,000곳</strong><b>공개 홈페이지 수동 표본</b><span>GET / 수동 신호만 확인했습니다. 침투나 로그인 검증으로 말하지 않습니다.</span></div>
      <div class="proof-item"><strong>85.7%</strong><b>Juliet Java SQLi 재현율</b><span>420개 사전등록 단위, 정밀도 100%. Java 전체 성능을 뜻하지 않습니다.</span></div>
      <div class="proof-item"><strong>30.0%</strong><b>새 공개 앱 후보 정밀도</b><span>16개 앱의 평가 가능 후보 10개 중 실제 문제 3개, 오탐 7개였습니다.</span></div>
    </div>
    <p class="proof-warning"><strong>최신 실효성 게이트는 출하 보류입니다.</strong> 후보를 놓치지 않는 것과 정확히 말하는 것은 다릅니다. 지금 안경선배는 실제 문제보다 오탐을 더 많이 냈고, 이 수치를 낮추기 전에는 현장 정확도를 주장하지 않습니다.</p>
  </section>

  <section class="panel checks-panel">
    <p class="panel-kicker">검수 항목</p>
    <h2>우리가 점검하는 것</h2>
    <div id="checks" class="checks"></div>
  </section>
  <p class="footer-note">안경선배는 시니어 개발자의 출하 전 검수 질문을 자동화합니다. 인간의 사업 판단, 법률 자문, 무결점 보증을 대신하지 않습니다.</p>
</main>
<script>
const CHECKS = __CHECKS__;
const NON_GOALS = __NON_GOALS__;
const ACTIVE_PATHS = __ACTIVE_PATHS__;
const ACTIVE_DEEP_PATHS = __ACTIVE_DEEP_PATHS__;
const VERIFY = __VERIFY__;
const scanButton = document.getElementById('scan');
const urlInput = document.getElementById('url');
const authInput = document.getElementById('authorized');
const deepInput = document.getElementById('deepActive');
const resultsBox = document.getElementById('results');
const statusBox = document.getElementById('status');
const statusLight = document.getElementById('statusLight');
const metricsBox = document.getElementById('metrics');
const findingsBox = document.getElementById('findings');
const auditBox = document.getElementById('auditLog');
const dynamicStageStatus = document.getElementById('dynamicStageStatus');

function text(tag, value, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = value;
  return node;
}

function setVerdict(code, message, isError) {
  const labels = {
    WAITING_FOR_TARGET: '점검 전',
    REVIEWING: '확인 중',
    REVIEW_INCOMPLETE: '검수 미완료',
    HOLD_FIX: '출하 보류',
    DYNAMIC_REVIEW_HAS_FINDINGS: '확인 필요',
    DYNAMIC_REVIEW_CLEAR: '사이트 점검 완료'
  };
  statusBox.className = isError ? 'error' : 'empty';
  const codeNode = text('span', labels[code] || code, 'verdict-code');
  codeNode.dataset.code = code;
  statusBox.replaceChildren(codeNode, text('span', message, 'verdict-copy'));
}

function setDynamicStage(state, message) {
  dynamicStageStatus.className = state;
  dynamicStageStatus.textContent = message;
}

function selectTab(name) {
  document.querySelectorAll('.tab').forEach(tab => {
    const selected = tab.dataset.panel === name;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
  });
  document.querySelectorAll('.tab-panel').forEach(panel => { panel.hidden = panel.id !== 'panel-' + name; });
}

function renderStatic() {
  const checks = document.getElementById('checks');
  CHECKS.forEach(item => {
    const row = document.createElement('div');
    row.className = 'check-card';
    row.appendChild(text('strong', item.name));
    row.appendChild(text('span', item.description));
    const technical = document.createElement('details');
    technical.appendChild(text('summary', '기술 규칙 보기'));
    technical.appendChild(text('span', item.rule_ids.join(', '), 'rule-list'));
    row.appendChild(technical);
    checks.appendChild(row);
  });
  const paths = document.getElementById('paths');
  ACTIVE_PATHS.forEach(path => paths.appendChild(text('span', path, 'pill')));
  ACTIVE_DEEP_PATHS.forEach(path => paths.appendChild(text('span', '심화 ' + path, 'pill')));
  const nonGoals = document.getElementById('nonGoals');
  NON_GOALS.forEach(item => nonGoals.appendChild(text('div', item, 'check-card')));
  document.getElementById('verification').textContent =
    VERIFY.allowlist_env + '=example.com,api.example.com\n' +
    VERIFY.domain_proof_path + ' -> ' + VERIFY.domain_proof_value;
}

function renderMetrics(summary) {
  const labels = {critical: '치명', high: '높음', medium: '중간', low: '낮음', info: '정보'};
  metricsBox.hidden = false;
  metricsBox.replaceChildren();
  ['critical', 'high', 'medium', 'low', 'info'].forEach(key => {
    const item = document.createElement('div');
    item.className = 'metric ' + key;
    item.appendChild(text('strong', String(summary[key] || 0)));
    item.appendChild(text('span', labels[key]));
    metricsBox.appendChild(item);
  });
}

function renderFindings(findings) {
  findingsBox.replaceChildren();
  if (!findings.length) {
    findingsBox.appendChild(text('div', '이번 동적 범위에서는 발견된 항목이 없습니다. Guardian으로 코드와 검수 범위를 이어서 확인하세요.', 'empty-note'));
    return;
  }
  findings.forEach(finding => {
    const row = document.createElement('article');
    row.className = 'finding ' + finding.severity;
    row.appendChild(text('h3', finding.ko_title || finding.title));
    row.appendChild(text('p', finding.easy_explanation || '확인이 필요한 항목입니다.'));
    if (finding.fix_steps && finding.fix_steps.length) {
      row.appendChild(text('h4', '먼저 이렇게 고치세요'));
      const list = document.createElement('ol');
      list.className = 'steps';
      finding.fix_steps.forEach(step => list.appendChild(text('li', step)));
      row.appendChild(list);
    }
    const technical = document.createElement('details');
    technical.appendChild(text('summary', '기술 근거 보기'));
    const dl = document.createElement('dl');
    const rows = [
      ['규칙', finding.rule_id || ''], ['위험도', finding.severity], ['확신도', finding.confidence || ''], ['URL', finding.url || ''],
      ['요청', finding.method || ''], ['상태', finding.status == null ? '' : String(finding.status)],
      ['근거', finding.evidence || ''], ['개인정보 분류', finding.privacy_class || ''],
      ['검사 깊이', finding.audit_depth ? 'Depth ' + finding.audit_depth : ''], ['개보위 참고', finding.pipc_basis || ''],
      ['검사 범위', finding.inspected_scope || ''], ['미검사 범위', finding.not_inspected || '']
    ];
    rows.forEach(([key, value]) => { if (value) { dl.appendChild(text('dt', key)); dl.appendChild(text('dd', value)); } });
    technical.appendChild(dl);
    row.appendChild(technical);
    findingsBox.appendChild(row);
  });
}

function renderAuditLog(items) {
  auditBox.replaceChildren();
  const head = document.createElement('div');
  head.className = 'audit-head';
  head.appendChild(text('strong', '검사 로그'));
  head.appendChild(text('span', '응답 원문과 값은 저장하지 않음'));
  auditBox.appendChild(head);
  const list = document.createElement('div');
  list.className = 'audit-list';
  (items || []).forEach(item => {
    const row = document.createElement('div');
    row.className = 'audit-row ' + (item.result || 'pass');
    const title = document.createElement('div');
    title.className = 'audit-title';
    title.appendChild(text('span', item.result || 'pass', 'badge ' + (item.result || 'pass')));
    title.appendChild(text('span', item.check || '검사'));
    title.appendChild(text('span', (item.method || '') + ' ' + (item.probe_path || ''), 'badge'));
    if (item.status !== null && item.status !== undefined) title.appendChild(text('span', 'HTTP ' + item.status, 'badge'));
    row.appendChild(title);
    row.appendChild(text('div', item.looked_for || '', 'audit-meta'));
    row.appendChild(text('div', item.outcome || '', 'audit-outcome'));
    if (item.rule_ids && item.rule_ids.length) row.appendChild(text('div', item.rule_ids.join(', '), 'audit-meta'));
    row.appendChild(text('div', item.url || '', 'audit-meta'));
    list.appendChild(row);
  });
  auditBox.appendChild(list);
}

const SVG_NS = 'http://www.w3.org/2000/svg';

function svgElement(name, attributes, content) {
  const node = document.createElementNS(SVG_NS, name);
  Object.entries(attributes || {}).forEach(([key, value]) => node.setAttribute(key, String(value)));
  if (content !== undefined) node.textContent = String(content);
  return node;
}

function renderExposureMap(data) {
  const box = document.getElementById('exposureMap');
  const items = data.exposure_map || [];
  const width = 880;
  const height = 260;
  const site = data.target ? data.target.host : 'target';
  const positions = [[228, 58], [458, 38], [680, 60], [235, 166], [470, 178], [690, 166]];
  const svg = svgElement('svg', {viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': '노출 흐름 지도'});
  svg.append(
    svgElement('rect', {width, height, rx: 5, fill: '#fafaf8'}),
    svgElement('text', {x: 16, y: 25, 'font-size': 14, 'font-weight': 700, fill: '#1d211f'}, '노출 경로'),
    svgElement('text', {x: 16, y: 45, 'font-size': 11, fill: '#626964'}, '고정 경로 GET/OPTIONS 응답에서 위험 신호를 찾습니다.'),
    svgElement('rect', {x: 24, y: 94, width: 118, height: 62, rx: 5, fill: '#edf8f2', stroke: '#176b4a'}),
    svgElement('text', {x: 40, y: 120, 'font-size': 13, 'font-weight': 700, fill: '#1d211f'}, '안경선배'),
    svgElement('text', {x: 40, y: 141, 'font-size': 11, fill: '#626964'}, site)
  );
  items.forEach((item, index) => {
    const [x, y] = positions[index] || [240 + index * 80, 150];
    const count = item.rule_ids.length;
    const unknown = item.status === 'unknown';
    const stroke = unknown ? '#9a5a00' : (count ? '#b42332' : '#176b4a');
    const title = item.label + (unknown ? ' · 미확인' : (count ? ' · ' + count + '개' : ' · 정상'));
    const rules = unknown ? '요청 실패로 확인하지 못함' : (count ? item.rule_ids.join(', ') : '검출 없음');
    svg.append(
      svgElement('line', {x1: 138, y1: 126, x2: x, y2: y + 34, stroke: '#aeb6af', 'stroke-width': 1.5}),
      svgElement('rect', {x, y, width: 170, height: 72, rx: 5, fill: '#ffffff', stroke}),
      svgElement('text', {x: x + 11, y: y + 23, 'font-size': 13, 'font-weight': 700, fill: '#1d211f'}, title),
      svgElement('text', {x: x + 11, y: y + 43, 'font-size': 11, fill: '#626964'}, item.path),
      svgElement('text', {x: x + 11, y: y + 60, 'font-size': 10, fill: '#747c76'}, rules.slice(0, 42))
    );
  });
  box.replaceChildren(svg);
}

async function scan() {
  scanButton.disabled = true;
  resultsBox.setAttribute('aria-busy', 'true');
  statusLight.className = 'status-light busy';
  statusLight.textContent = '확인 중';
  setDynamicStage('running', '현재 화면 · 검사 중');
  setVerdict('REVIEWING', deepInput.checked ? '기본 경로와 심화 민감 경로를 확인하고 있습니다.' : '고정 경로의 응답을 확인하고 있습니다.', false);
  metricsBox.hidden = true;
  findingsBox.replaceChildren(text('div', '응답을 기다리는 중입니다.', 'empty-note'));
  auditBox.replaceChildren();
  document.getElementById('exposureMap').replaceChildren();
  try {
    const response = await fetch('/api/scan', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-K-Guard-CSRF': '__K_GUARD_CSRF__'},
      body: JSON.stringify({url: urlInput.value, authorized: authInput.checked, deep_active: deepInput.checked})
    });
    const data = await response.json();
    if (!data.ok && data.review_status === 'incomplete') {
      setVerdict('REVIEW_INCOMPLETE', '검수가 끝난 게 아닙니다. 실행 상태와 주소를 확인한 뒤 다시 시도하세요.', true);
      statusLight.className = 'status-light';
      statusLight.textContent = '중단';
      setDynamicStage('failed', '중단 · 검수 미완료');
      findingsBox.replaceChildren(text('div', '요청 오류가 있어 발견 없음이나 정상으로 판정하지 않았습니다.', 'empty-note'));
      renderAuditLog(data.audit_log || []);
      renderExposureMap(data);
      selectTab('log');
      return;
    }
    if (!response.ok || !data.ok) throw new Error('scan failed');
    const blockingCount = Number(data.summary.critical || 0) + Number(data.summary.high || 0);
    const findingCount = Array.isArray(data.findings) ? data.findings.length : 0;
    const verdictCode = blockingCount ? 'HOLD_FIX' : (findingCount ? 'DYNAMIC_REVIEW_HAS_FINDINGS' : 'DYNAMIC_REVIEW_CLEAR');
    setVerdict(
      verdictCode,
      blockingCount
        ? '지금은 출하를 멈추세요. 우선순위가 높은 문제 ' + blockingCount + '개를 고친 뒤 다시 검수하세요.'
        : (findingCount
          ? '출하를 바로 막을 수준은 아니지만 확인할 항목이 ' + findingCount + '개 있습니다. 지금 고칠 것부터 확인하세요.'
          : '이번 사이트 응답에서는 막을 신호를 찾지 못했습니다. 이 결과만으로 출하 승인은 아니며, MCP에서 전체 검수를 이어가야 합니다.'),
      blockingCount > 0
    );
    statusLight.className = 'status-light done';
    statusLight.textContent = blockingCount ? '출하 보류' : (findingCount ? '확인 필요' : '점검 완료');
    setDynamicStage(
      blockingCount ? 'failed' : (findingCount ? 'review' : 'complete'),
      blockingCount
        ? '완료 · high 이상 ' + blockingCount + '개'
        : (findingCount ? '완료 · 확인 항목 ' + findingCount + '개' : '완료 · 발견 항목 없음')
    );
    renderMetrics(data.summary);
    renderFindings(data.findings);
    renderAuditLog(data.audit_log);
    renderExposureMap(data);
    selectTab(findingCount ? 'findings' : 'log');
  } catch (error) {
    setVerdict('REVIEW_INCOMPLETE', '검수가 끝난 게 아닙니다. 입력 주소와 권한 범위를 확인한 뒤 다시 시도하세요.', true);
    statusLight.className = 'status-light';
    statusLight.textContent = '중단';
    setDynamicStage('failed', '중단 · 검수 미완료');
    findingsBox.replaceChildren(text('div', '입력과 권한 범위를 확인한 뒤 다시 실행하세요.', 'empty-note'));
    selectTab('findings');
  } finally {
    scanButton.disabled = false;
    resultsBox.setAttribute('aria-busy', 'false');
  }
}

const tabs = Array.from(document.querySelectorAll('.tab'));
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectTab(tab.dataset.panel));
  tab.addEventListener('keydown', event => {
    let nextIndex = null;
    if (event.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') nextIndex = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = tabs.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    selectTab(tabs[nextIndex].dataset.panel);
    tabs[nextIndex].focus();
  });
});
scanButton.addEventListener('click', scan);
urlInput.addEventListener('keydown', event => { if (event.key === 'Enter') scan(); });
renderStatic();
</script>
</body>
</html>"""


SCOPE_TEMPLATE = r"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#f7f7f4">
  <title>안경선배 검수 범위 | K-Guard MCP</title>
  <style>
    :root { --bg:#f7f7f4; --surface:#fff; --surface-2:#f0f2ee; --ink:#1d211f; --muted:#626964; --line:#d7dcd7; --green:#176b4a; --cyan:#246a91; --pink:#9f3042; --flannel:#b23346; --danger:#b42332; --warn:#9a5a00; --ok:#176b4a; }
    * { box-sizing:border-box; }
    body { margin:0; min-width:0; background:var(--bg); color:var(--ink); font-family:"Pretendard","Noto Sans KR",Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    a { color:inherit; }
    .shell { width:min(1180px,100%); margin:0 auto; padding:14px 22px 48px; }
    .topbar { display:flex; align-items:center; justify-content:space-between; gap:16px; min-height:54px; border-bottom:1px solid var(--line); }
    .brand { display:flex; align-items:baseline; gap:12px; }
    .brand strong { font-size:20px; }
    .brand span { color:var(--flannel); font:750 11px ui-monospace,SFMono-Regular,Consolas,monospace; }
    nav a { padding:8px 10px; border-radius:5px; color:var(--muted); font-size:13px; font-weight:750; text-decoration:none; }
    nav a:hover { color:var(--flannel); background:var(--surface-2); }
    .scope-hero { display:grid; grid-template-columns:150px minmax(0,1fr); min-height:180px; margin-top:14px; overflow:hidden; border:1px solid var(--line); border-radius:8px; background:var(--surface); }
    .scope-hero img { width:100%; height:180px; object-fit:cover; object-position:49% 28%; border-right:1px solid var(--line); }
    .hero-copy { display:flex; flex-direction:column; justify-content:center; padding:24px 30px; }
    .eyebrow { margin-bottom:8px; color:var(--flannel); font:800 11px ui-monospace,SFMono-Regular,Consolas,monospace; }
    h1 { margin:0; font-size:40px; line-height:1.12; letter-spacing:0; }
    .hero-copy p { max-width:760px; margin:12px 0 0; color:var(--muted); font-size:14px; line-height:1.65; }
    .verdict { margin:14px 0 0; padding:16px 18px; border:1px solid #e7d29c; border-left:5px solid var(--warn); border-radius:6px; background:#fff8e8; }
    .verdict strong { color:var(--warn); }
    .verdict p { margin:6px 0 0; color:#5c4b23; font-size:13px; line-height:1.6; }
    section.band { padding:26px 0; border-bottom:1px solid var(--line); }
    h2 { margin:0 0 14px; font-size:18px; letter-spacing:0; }
    .lead { margin:-5px 0 17px; color:var(--muted); font-size:13px; line-height:1.6; }
    .steps { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); border:1px solid var(--line); background:var(--surface); }
    .step { min-width:0; min-height:116px; padding:15px; border-right:1px solid var(--line); border-bottom:1px solid var(--line); }
    .step:nth-child(3n) { border-right:0; }
    .step:nth-last-child(-n+3) { border-bottom:0; }
    .step b { display:block; margin-bottom:8px; color:var(--green); font:800 12px ui-monospace,SFMono-Regular,Consolas,monospace; }
    .step strong { display:block; font-size:13px; }
    .step span { display:block; margin-top:5px; color:var(--muted); font-size:12px; line-height:1.5; }
    .domains { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:1px; border:1px solid var(--line); background:var(--line); }
    .domain { min-width:0; padding:16px; background:var(--surface); }
    .domain b { color:var(--cyan); font-size:13px; }
    .domain p { margin:7px 0 0; color:var(--muted); font-size:12px; line-height:1.55; }
    .matrix-wrap { overflow-x:auto; border:1px solid var(--line); }
    table { width:100%; min-width:850px; border-collapse:collapse; font-size:12px; }
    th,td { padding:12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; line-height:1.55; }
    th { background:#edf8f2; color:var(--green); font-size:11px; }
    td { color:#3f4741; }
    tbody tr:last-child td { border-bottom:0; }
    .depth { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:0 24px; }
    .depth-row { padding:13px 0; border-bottom:1px solid var(--line); }
    .depth-row strong { display:flex; align-items:center; justify-content:space-between; gap:12px; font-size:13px; }
    .depth-row p { margin:6px 0 0; color:var(--muted); font-size:12px; line-height:1.55; }
    .chip { flex:0 0 auto; padding:2px 6px; border:1px solid var(--line); border-radius:4px; font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace; }
    .chip.l5 { color:var(--ok); border-color:#2f6848; } .chip.l4 { color:var(--cyan); border-color:#315f70; } .chip.l3 { color:var(--warn); border-color:#70552c; } .chip.l0 { color:var(--danger); border-color:#783932; }
    .split { display:grid; grid-template-columns:1fr 1fr; gap:30px; }
    .list-row { padding:12px 0; border-bottom:1px solid var(--line); }
    .list-row strong { display:block; font-size:13px; }
    .list-row span { display:block; margin-top:5px; color:var(--muted); font-size:12px; line-height:1.55; }
    .list-row.ok strong { color:var(--ok); } .list-row.todo strong { color:var(--warn); } .list-row.bad strong { color:var(--danger); }
    .evidence-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); border:1px solid var(--line); background:var(--surface); }
    .evidence-cell { min-width:0; padding:15px; }
    .evidence-cell + .evidence-cell { border-left:1px solid var(--line); }
    .evidence-cell strong { display:block; font-size:22px; }
    .evidence-cell b { display:block; margin-top:5px; color:var(--flannel); font-size:12px; }
    .evidence-cell span { display:block; margin-top:5px; color:var(--muted); font-size:11px; line-height:1.5; }
    .evidence-warning { margin:12px 0 0; padding:11px 13px; border-left:4px solid var(--warn); background:#fff8e8; color:#604817; font-size:12px; line-height:1.55; }
    .foot { margin-top:20px; color:#747c76; font-size:11px; line-height:1.6; }
    @media(max-width:780px){
      .shell{padding:10px 14px 32px}.brand{display:block}.brand span{display:block;margin-top:3px}.scope-hero{grid-template-columns:82px minmax(0,1fr)}.scope-hero img{height:166px}.hero-copy{padding:18px 15px}h1{font-size:27px}.steps{grid-template-columns:1fr 1fr}.step:nth-child(3n){border-right:1px solid var(--line)}.step:nth-child(2n){border-right:0}.step:nth-last-child(-n+3){border-bottom:1px solid var(--line)}.step:nth-last-child(-n+2){border-bottom:0}.domains{grid-template-columns:1fr 1fr}.depth,.split{grid-template-columns:1fr}.split{gap:22px}.evidence-grid{grid-template-columns:1fr 1fr}.evidence-cell:nth-child(3){border-left:0;border-top:1px solid var(--line)}.evidence-cell:nth-child(4){border-top:1px solid var(--line)}
      .matrix-wrap{overflow:visible;border:0}.matrix{display:block;min-width:0}.matrix thead{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.matrix tbody,.matrix tr,.matrix td{display:block;width:100%}.matrix tr{margin-bottom:10px;border:1px solid var(--line);background:var(--surface)}.matrix td{display:grid;grid-template-columns:82px minmax(0,1fr);gap:10px;padding:10px 12px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.matrix td:last-child{border-bottom:0}.matrix td::before{content:attr(data-label);color:var(--green);font:750 10px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace}
    }
  </style>
</head>
<body>
<main class="shell">
  <header class="topbar"><div class="brand"><strong>안경선배</strong><span>WHAT WE CHECK, WHAT WE DO NOT</span></div><nav><a href="/">사이트 점검</a></nav></header>
  <section class="scope-hero">
    <img src="/assets/glasses-senpai-hero.png" alt="안경선배 바이브코딩 선배" width="1003" height="1568">
    <div class="hero-copy"><span class="eyebrow">검사 범위와 한계를 같은 화면에</span><h1>안경선배가 어디까지 보는지</h1><p>사이트, API, 데이터, 운영 위험을 함께 봅니다. 확인한 것과 확인하지 못한 것을 나누고, 출하 판정의 근거를 남깁니다.</p></div>
  </section>
  <div class="verdict"><strong>판정 경계</strong><p>시니어 개발자의 출하 전 검수 질문을 자동화합니다. 인간의 사업 판단이나 무결점 보증을 대신하지 않으며, 최종 권한은 Guardian high 게이트와 현재 증거 묶음에만 부여됩니다.</p></div>

  <section class="band">
    <h2>지금까지의 실전 기록</h2>
    <p class="lead">좋은 숫자만 골라 말하지 않습니다. 서로 다른 공개 자료에서 결과가 얼마나 흔들리는지도 함께 공개합니다.</p>
    <div class="evidence-grid">
      <div class="evidence-cell"><strong>28개</strong><b>공개 취약 앱 누적</b><span>두 캠페인에서 앱별 2회 재현. Python, PHP, Java, Go, JavaScript, TypeScript 포함</span></div>
      <div class="evidence-cell"><strong>1,000곳</strong><b>공개 홈페이지 표본</b><span>홈 응답의 수동 후보 신호만 확인. 능동 침투나 로그인 뒤 검증은 아님</span></div>
      <div class="evidence-cell"><strong>85.7%</strong><b>Juliet Java SQLi 재현율</b><span>420개 사전등록 단위, 정밀도 100%. 해당 구성요소에만 유효</span></div>
      <div class="evidence-cell"><strong>30.0%</strong><b>새 공개 앱 후보 정밀도</b><span>평가 가능 후보 10개 중 실제 문제 3개, 오탐 7개. 23개 전체 후보는 3인이 모두 판정</span></div>
    </div>
    <p class="evidence-warning"><strong>최신 실효성 게이트 판정은 HOLD입니다.</strong> 최소 평가 후보 12개에 못 미쳤고, 정밀도 30.0%와 Wilson 95% 하한 10.8%도 잠근 기준 75%와 60%를 통과하지 못했습니다. 과거 OWASP Python 지원 부분집합 후보 정밀도는 81.6%였지만, 새 공개 앱 결과보다 앞세우지 않습니다.</p>
  </section>

  <section class="band">
    <h2>검수 흐름</h2>
    <p class="lead">전체 검수는 끝까지 이어 보고, Guardian은 출하 직전의 대표 게이트로 판정합니다.</p>
    <div class="steps">
      <div class="step"><b>01</b><strong>코드와 설정</strong><span>secret, 한국 개인정보, 프레임워크 설정, MCP 구성을 정적 검사</span></div>
      <div class="step"><b>02</b><strong>흐름</strong><span>request/DB/env source가 log, response, DB, 외부 HTTP, LLM/MCP로 가는지 확인</span></div>
      <div class="step"><b>03</b><strong>사이트·API</strong><span>권한 있는 대상에 GET/OPTIONS only probe와 bounded deep 확인</span></div>
      <div class="step"><b>04</b><strong>데이터</strong><span>SQLite/log/storage connector, 보존·삭제 marker, 한국형 결합 개인정보 검토</span></div>
      <div class="step"><b>05</b><strong>MCP runtime</strong><span>MCP runtime observer와 stdio proxy에서 block/redact 경계 확인</span></div>
      <div class="step"><b>06</b><strong>판정과 증거</strong><span>원문 없는 증거 그래프, 소스 스냅샷, 서명 묶음, SARIF와 CI 결과 생성</span></div>
    </div>
  </section>

  <section class="band">
    <h2>Guardian 네 영역</h2>
    <div class="domains">
      <div class="domain"><b>사이트</b><p>헤더, CORS, debug, source map, 민감 경로, 공개 관리자 기능을 봅니다.</p></div>
      <div class="domain"><b>API 노출</b><p>무인증 JSON, IDOR·auth boundary 후보, OpenAPI와 공개 endpoint를 봅니다.</p></div>
      <div class="domain"><b>데이터 관리</b><p>한국 개인정보, 저장·로그·응답·외부 전송, 보존과 삭제 근거를 봅니다.</p></div>
      <div class="domain"><b>운영 위험</b><p>secret, 환경 설정, MCP tool 위험, 공급망·배포 증거와 검수 누락을 봅니다.</p></div>
    </div>
  </section>

  <section class="band">
    <h2>무엇을 어떻게 보는가</h2>
    <div class="matrix-wrap"><table class="matrix">
      <thead><tr><th>영역</th><th>검사 방법</th><th>찾는 신호</th><th>현재 한계</th></tr></thead>
      <tbody>
        <tr><td data-label="영역">코드·텍스트</td><td data-label="검사 방법">정적 rule + Python AST taint + JS/TS lightweight taint</td><td data-label="찾는 신호">PII, secret, request-to-sink, auth boundary</td><td data-label="현재 한계">완전한 inter-procedural 타입·프레임워크 분석은 아님</td></tr>
        <tr><td data-label="영역">웹 런타임</td><td data-label="검사 방법">GET/OPTIONS only probe + bounded deep + read-only session header</td><td data-label="찾는 신호">무인증 API, .env/.git/backup/debug, CORS, source map</td><td data-label="현재 한계">로그인 우회, mutation, brute force, exploit payload는 실행하지 않음</td></tr>
        <tr><td data-label="영역">데이터</td><td data-label="검사 방법">flow graph + local DB/log/storage connector + governance rule</td><td data-label="찾는 신호">한국 개인정보의 저장·로그·응답·외부 전송, 보존·삭제 gap</td><td data-label="현재 한계">원격 운영 DB와 실제 backup purge 실행은 별도 검증 필요</td></tr>
        <tr><td data-label="영역">MCP·LLM</td><td data-label="검사 방법">정적 위협 rule + JSONL observer + stdio·Streamable HTTP live proxy</td><td data-label="찾는 신호">hidden instruction, exfiltration, PII-to-tool, block/redact</td><td data-label="현재 한계">binary framing·비표준 transport의 범용 proxy는 아직 아님</td></tr>
        <tr><td data-label="영역">보고·운영</td><td data-label="검사 방법">JSON, Markdown, HTML, SARIF, CI fail-on</td><td data-label="찾는 신호">raw-free evidence, drift, source snapshot, release authority</td><td data-label="현재 한계">법률 인증이나 인간 시니어의 사업 판단을 대신하지 않음</td></tr>
      </tbody>
    </table></div>
  </section>

  <section class="band">
    <h2>감사 깊이 지도</h2>
    <div class="depth">
      <div class="depth-row"><strong>Python AST taint <span class="chip l5">L4-L5</span></strong><p>request, DB, env source에서 log, response, DB write, 외부 HTTP, LLM/MCP sink까지 연결합니다.</p></div>
      <div class="depth-row"><strong>동적·세션 웹 검증 <span class="chip l4">L4</span></strong><p>허용된 origin의 고정 경로와 심화 민감 경로를 read-only로 확인합니다.</p></div>
      <div class="depth-row"><strong>MCP runtime observer <span class="chip l4">L4-L5</span></strong><p>이벤트 상관관계와 PII·hidden instruction·agentic sink의 block/redact 결정을 냅니다.</p></div>
      <div class="depth-row"><strong>DB/log/storage connector <span class="chip l4">L4</span></strong><p>로컬 SQLite, log, JSON/CSV/TSV를 read-only로 열고 count-only 근거를 남깁니다.</p></div>
      <div class="depth-row"><strong>한국 개인정보·결합 규칙 <span class="chip l3">L2-L3</span></strong><p>주민번호, 외국인번호, 여권, 운전면허, CI/DI, 건강·계좌·카드와 결합 위험을 봅니다.</p></div>
      <div class="depth-row"><strong>원격 DB·실제 삭제 실행 <span class="chip l0">L0-L1</span></strong><p>운영 저장소와 백업 purge는 자동 통과시키지 않고 별도 증거가 없으면 범위 부족으로 남깁니다.</p></div>
    </div>
  </section>

  <section class="band split">
    <div><h2>현재 하는 것</h2>
      <div class="list-row ok"><strong>원문 미반환</strong><span>개인정보와 secret 값 대신 masked value와 evidence hash를 남깁니다.</span></div>
      <div class="list-row ok"><strong>권한·범위 기록</strong><span>외부 assertion은 증명서로 꾸미지 않고 raw-free ref와 경계를 기록합니다.</span></div>
      <div class="list-row ok"><strong>실패 시 출하 보류</strong><span>검수 제어 오류와 coverage gap은 문제가 없다는 뜻으로 처리하지 않습니다.</span></div>
    </div>
    <div><h2>아직 하지 않는 것</h2>
      <div class="list-row bad"><strong>공격적 침투</strong><span>비밀번호 대입, fuzzing, 공격 payload, mutation, exploit chain을 실행하지 않습니다.</span></div>
      <div class="list-row todo"><strong>모든 전송 방식의 범용 프록시</strong><span>stdio JSON-RPC와 공식 SDK 기반 Streamable HTTP는 집행할 수 있지만, binary framing과 비표준 transport까지 모두 중계하지는 않습니다.</span></div>
      <div class="list-row todo"><strong>인간의 사업 판단</strong><span>사업 의도와 허용 범위는 운영자가 명시하고 K-Guard는 그 증거의 완결성을 검수합니다.</span></div>
    </div>
  </section>
  <p class="foot">안경선배는 검사한 것과 검사하지 못한 것을 분리해서 말합니다. `SHIP`은 현재 앱, 현재 소스, 현재 증거 묶음에만 유효합니다.</p>
</main>
</body>
</html>"""
