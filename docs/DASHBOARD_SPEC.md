# PwnPilot Dashboard 명세

## 1. 목적

Dashboard는 통계 카드 모음이 아니라 분석을 시작하거나 이어 가는 작업 화면이다. 사용자는
화면 진입 후 즉시 최근 artifact, 실패/대기 작업, 중요한 finding, 다음 액션을 확인할 수
있어야 한다.

## 2. Phase 1 레이아웃

```text
Dashboard Header
├── "Analysis workspace"
├── API 상태
└── compact Upload Binary action

Primary Work Area
├── Recent Workspaces (2/3 width)
│   ├── filename / arch / bits / size
│   ├── short SHA
│   ├── analysis status
│   └── open Workspace
└── Analysis Queue (1/3 width)
    ├── queued/running/failed/completed summaries
    └── recovery/next action

Priority Area
├── High-Priority Findings
│   ├── severity / heuristic status
│   ├── symbol / category / description
│   └── open binary
└── Getting Started or Empty State
```

동적 session과 technique distribution은 실제 API가 생기는 Phase에 추가한다. 의미 없는
차트와 placeholder 수치는 만들지 않는다.

## 3. 실제 데이터 연결

| UI | API |
|---|---|
| Recent Workspaces | `GET /api/v1/binaries` |
| Upload | `POST /api/v1/binaries` |
| Start analysis | `POST /api/v1/binaries/:id/analyze` |
| Job state | binary `analysis_status`, 최신 `GET .../analysis` |
| Priority findings | 최근 artifact의 `GET .../vulns` |
| Binary identity | `GET /api/v1/binaries/:id` |

Phase 1 finding은 symbol heuristic이므로 `Confirmed`로 표시하지 않는다. 호출 위치와
인자 증거가 없을 때는 `Possible · symbol evidence`라고 명시한다.

## 4. 상태

### Loading

- `Loading recent workspaces`
- `Reading analysis queue`
- `Scanning symbol-based findings`
- skeleton row는 최종 레이아웃 크기와 비슷하게 사용
- 정확한 진행률을 모르면 percentage를 표시하지 않음

### Empty

```text
No binaries yet
Upload an ELF you own or are authorized to analyze.
The Phase 1 pipeline validates and stores it without executing it.
[Upload Binary]
```

### Upload Error

- 요약: `The binary could not be accepted`
- 오류 코드: `UnsupportedFormatError`, `PayloadTooLargeError`, `ParseError`
- 실패 단계: `Upload validation`
- 해결: ELF 확인, 32MiB 제한 확인, 손상 여부 확인
- 업로드 action 유지

### Analysis Failed

- artifact row는 유지
- `× Failed` text/icon 표시
- 기술적 error는 expandable detail에 표시
- `Retry static analysis` action

### Partial

Phase 2부터 parser metadata는 성공했지만 특정 analyzer가 실패한 경우 성공한 section을
유지하고 실패한 panel에만 ErrorState를 표시한다.

## 5. 인터랙션

- Workspace row 클릭 또는 Enter: `/binaries/:id/overview`
- 분석되지 않은 row의 primary action: `Start analysis`
- failed row: `Retry analysis`
- Upload 성공: 분석 시작 후 해당 Workspace로 이동
- 파일 drag-and-drop은 compact target에서만 활성화
- 32MiB와 ELF-only 제한을 업로드 action 옆에 항상 표시

## 6. 시각 우선순위

1. 현재 작업을 이어 갈 artifact
2. queued/running/failed job
3. critical/high finding 후보
4. 새 upload
5. 보조 통계

보호 기법과 finding은 텍스트 의미를 함께 표시한다. 예: `NX · Enabled · stack execution
restricted`, `Canary · Not detected · overwrite protection not observed`.

## 7. 반응형

- ≥1440px: recent workspaces와 queue를 2열, findings 전체 폭
- 1024~1439px: 2열 유지하되 세부 column 축소
- <1024px: 단일 열, status/finding/report 중심
- 모바일에서 disassembly 편집 action은 제공하지 않고 Workspace 보고서만 연다.

## 8. Phase 1 완료 조건

- 업로드, 목록, 분석 시작, Workspace 이동이 실제 API로 동작
- loading/empty/upload error/analysis failed/completed 상태 구현
- 상태가 색상뿐 아니라 icon/text로 식별
- 1440px와 1920px에서 주요 정보가 첫 viewport에 표시
- 키보드로 upload action과 Workspace row에 접근 가능
- 기능 없는 버튼과 가짜 통계가 없음
