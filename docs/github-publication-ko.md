# GitHub 공개 안내

이 문서는 K-Guard MCP 공개 소스 스냅샷을 새 GitHub 저장소에 올릴 때의 최소 절차를 설명합니다.

## 공개 묶음의 구성

- `k-guard-mcp-github/`: GitHub 저장소 루트로 사용할 소스 폴더
- `k-guard-mcp-github-source.zip`: 같은 파일을 담은 전달용 소스 ZIP
- `k-guard-contest-demo.mp4`: 소스와 분리한 3분 시연 영상
- `k-guard-contest-demo.verification.json`: 영상 전체 디코딩 검증서
- `SOURCE-MANIFEST.json`: 공개 소스 파일별 크기와 SHA-256
- `SHA256SUMS`: 공개 묶음 최상위 산출물의 SHA-256

공개 소스에는 제품 코드, 테스트, 문서, 예제, 벤치마크·합성 데이터, GitHub Actions, 라이선스와 공개용 루트 보고서가 포함됩니다. `evidence/`, `submission/`, `runtime/`, `tmp/`, 로컬 캐시, 터미널 기록, 음성 원본과 영상 중간본은 포함하지 않습니다. 내부 개발 문서에 기록됐던 이 컴퓨터의 사용자 홈 절대경로는 공개 스냅샷에서 `<LOCAL_USER_HOME>`으로 치환됩니다.

## GitHub에 소스 올리기

GitHub에서 빈 공개 저장소를 만든 뒤 `k-guard-mcp-github` 폴더에서 실행합니다. 웹에서 저장소를 만들 때 README, 라이선스, `.gitignore`를 추가로 생성하지 않아야 충돌이 없습니다.

```powershell
cd .\k-guard-mcp-github
git init -b main
git add .
git status
git commit -m "Initial public release of K-Guard MCP 0.1.0"
git remote add origin https://github.com/OWNER/k-guard-mcp.git
git push -u origin main
```

GitHub CLI를 이미 로그인해 사용한다면 다음 방식도 가능합니다.

```powershell
cd .\k-guard-mcp-github
git init -b main
git add .
git commit -m "Initial public release of K-Guard MCP 0.1.0"
gh repo create k-guard-mcp --public --source . --remote origin --push
```

실제 저장소 소유자와 이름을 확인하기 전에는 원격 주소나 `gh repo create`를 실행하지 않습니다.

## 영상 공개

영상은 Git 기록을 불필요하게 키우지 않도록 소스 저장소에 커밋하지 않고 다음 중 하나로 공개하는 것을 권장합니다.

1. GitHub Release의 첨부 파일로 `k-guard-contest-demo.mp4` 업로드
2. 공모전 제출 페이지 또는 동영상 서비스에 업로드한 뒤 README에 링크

GitHub Release를 사용할 경우 먼저 공개 소스를 커밋하고 태그 경계를 확인합니다.

```powershell
gh release create v0.1.0 ..\k-guard-contest-demo.mp4 `
  --title "K-Guard MCP 0.1.0" `
  --notes "Initial open-source contest release"
```

## 업로드 전 확인

```powershell
python -m pip install -e ".[dev]"
python scripts\public_source_tests.py
python scripts\release_hygiene.py --json
git diff --check
```

`public_source_tests.py`는 공개 소스만으로 재현 가능한 제품 회귀를 실행합니다. 전체 저장소의 내부 증거·공모전 문서·릴리스 바이너리 결속 테스트는 별도 배포되는 evidence, DOCX/PDF, wheel 및 커밋된 Git 경계가 필요하므로 소스 전용 CI에서 명시적으로 분리됩니다. 해당 테스트 파일은 삭제하지 않고 공개 저장소에 남겨 검증 범위를 확인할 수 있게 합니다.

공개 소스 전용 CI는 분리된 증거 검증군을 제외한 결합 statement·branch 커버리지에 `88%`, 같은 범위의 `redaction.py`에 `85%`를 적용합니다. 전체 내부 릴리스 저장소의 90% 게이트를 공개 소스 전용 수치로 오인하지 않도록 두 경계를 나눕니다.

- `SOURCE-MANIFEST.json`과 `SHA256SUMS`를 보관합니다.
- GitHub의 Private Vulnerability Reporting을 활성화합니다.
- 실제 API 키, 개인 데이터, 세션 파일, 로컬 절대경로가 없는지 마지막으로 확인합니다.
- `LICENSE`, `THIRD_PARTY_NOTICES.md`, `LICENSES/`를 삭제하지 않습니다.
- 공개 후 생성된 전체 40자리 커밋 SHA를 공모전 결과보고서와 제출 문서에 기록합니다.
