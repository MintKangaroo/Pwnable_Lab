# PwnPilot 정보 구조

## 1. 제품 원칙

PwnPilot의 프런트엔드는 일반 관리 화면이 아니라 하나의 분석 작업 공간이다. 사용자가
언제나 답할 수 있어야 하는 질문은 다음 네 가지다.

1. 지금 어떤 artifact와 session을 보고 있는가?
2. 무엇이 도구로 확인됐고 무엇이 추론 또는 미확인 상태인가?
3. 가장 중요한 위험과 근거는 무엇인가?
4. 다음으로 검증할 액션은 무엇인가?

분석 화면은 높은 정보 밀도를 유지하되, 기본 요약 → evidence → raw data 순으로 정보를
점진 공개한다. 한 패널의 오류가 다른 패널을 가리지 않게 기능별 error boundary를 둔다.

## 2. 전역 구조

```text
Global Header
├── Product identity
├── Global search / command palette
├── Current job state
├── Notifications
├── Theme
└── User menu

Application Body
├── Main Navigation (collapsible)
│   ├── Dashboard
│   ├── Binaries
│   ├── Dynamic Analysis
│   ├── Crash Analyzer
│   ├── ROP Studio
│   ├── Exploit Studio
│   ├── Technique Intelligence
│   ├── Jobs
│   └── Settings
└── Route Workspace
    ├── Context Header
    ├── Workspace Tabs
    ├── Primary Workspace
    ├── Inspector
    └── Optional Bottom Panel

Status Bar
├── API connection
├── execution mode
└── background job summary
```

현재는 실제 API가 존재하는 Dashboard, Binaries, Crash Analyzer, Payload Studio,
Challenges만 활성화한다. 후속 화면은 라우트와 데이터 계약이 구현된 Phase에서 노출하며
기능 없는 장식 버튼을 만들지 않는다.

## 3. 라우트 모델

URL은 공유·새로고침·뒤로 가기가 가능한 Workspace 상태의 source of truth다.

| Route | 목적 | Phase |
|---|---|---|
| `/` | Dashboard | 1 |
| `/binaries` | artifact 목록과 업로드 | 1 |
| `/binaries/:binaryId/:tab?` | Binary Workspace | 1~3 |
| `/payload` | 정적 payload 도구 | 기존/1 |
| `/challenges` | 교육용 fixture 문제 | 기존/1 |
| `/dynamic/:sessionId?` | GDB/MI 동적 분석 | 6B |
| `/crashes/:crashId?` | text crash-log 분석; core는 후속 | 4 |
| `/rop/:binaryId` | ROP Studio | 3 |
| `/exploits/:binaryId/:draftId?` | Exploit Studio | 5 |
| `/techniques/:binaryId` | Technique Intelligence | 5~6C |
| `/jobs` | 전체 작업 큐 | 1 이후 |
| `/settings` | 사용자 표현/환경 설정 | 3 이후 |

Binary Workspace의 주소·함수·선택 상태는 query string으로 표현한다.

```text
/binaries/:id/disassembly?address=0x401196
/binaries/:id/functions?symbol=vuln
/binaries/:id/hex?offset=0x120&page=2
```

패널 크기, density, theme처럼 공유할 필요가 없는 표현 설정만 local storage에 둔다.

## 4. 화면 계층과 우선순위

### P0 — Phase 1 핵심

- AppShell
- Dashboard
- Binary list/upload
- Binary Context Header
- Binary Overview
- loading/empty/error/job 상태

### P1 — 정적 분석 핵심

- Functions/Disassembly/CFG
- Symbols/Strings/GOT/PLT/Relocations
- Findings detail Inspector
- Hex View
- ROP gadget browser

### P2 — 동적 분석

- Dynamic session shell
- Registers/Stack/Memory/Disassembly
- Timeline/Syscalls/Breakpoints/Logs
- Crash Analyzer text-log workspace 완료; core/snapshot 후속

### P3 — 전략 도구

- ROP Studio
- Exploit Studio
- Technique Intelligence
- Packing/Obfuscation comparison

## 5. Binary Workspace

```text
Binary Context Header
├── filename / architecture / bits / short SHA
├── analysis status / execution mode
├── compact protection summary
└── Analyze / upload related artifact / more actions

Workspace Tabs
├── Overview
├── Checksec
├── Functions
├── Disassembly
├── CFG
├── Symbols
├── Strings
├── GOT/PLT
├── ROP
├── Findings
├── Hex
├── Memory
└── Exploit Plan

Workspace Body
├── Navigator: functions, symbols, strings, findings
├── Primary: current analysis representation
├── Inspector: evidence, xrefs, value interpretation
└── Bottom: logs, timeline, console, jobs
```

Phase 1의 기존 분석 탭은 단일 primary view로 유지하되, Context Header와 URL 탭 상태를
먼저 적용한다. Resizable Navigator/Inspector/Bottom Panel은 데이터 관계가 생기는
Phase 2~3에 추가한다.

## 6. 데이터 탐색 관계

```text
Binary
├── Function ──▶ Disassembly ──▶ Basic Block ──▶ CFG
├── Symbol ──▶ Definition / Xrefs
├── String ──▶ References / Runtime observations
├── Finding ──▶ Evidence / Function / Technique
├── Gadget ──▶ Disassembly / ROP chain
├── Crash ──▶ Instruction / Registers / Stack / Timeline
├── Packing evidence ──▶ Section / Memory / Derived artifact
└── Technique ──▶ Primitives / Mitigations / Attack chain
```

각 링크는 주소와 provenance를 유지해야 하며, 확인되지 않은 대상은 링크처럼 보이게
렌더링하지 않는다.

## 7. 반응형 정책

- 1440px 이상: 전체 navigation과 primary Workspace를 표시한다.
- 1920px 이상: Navigator/Inspector/Bottom Panel 동시 표시를 허용한다.
- 1024~1439px: 보조 패널을 접거나 drawer/tab으로 전환한다.
- 1024px 미만: 상태, finding, 보고서 중심의 제한 UI를 제공한다.
- 모바일: 디스어셈블리/메모리 편집/ROP 체인 편집을 축소판으로 제공하지 않는다.
