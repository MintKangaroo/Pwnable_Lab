# PwnPilot 디자인 시스템

## 1. 시각 원칙

- 정보 탐색과 상태 이해가 장식보다 우선한다.
- 큰 순수 검정 배경, 과도한 neon/glow/blur/gradient를 사용하지 않는다.
- 모든 내용을 동일한 카드로 감싸지 않고 table, split panel, list, code view를 구분한다.
- 색상은 selection, verification, severity, AI provenance처럼 의미가 있을 때만 사용한다.
- 주소, opcode, register, memory, symbol은 monospace와 tabular number로 표시한다.

## 2. 색상 토큰

초기 dark theme 기준값:

```css
:root {
  --color-bg-app: #0b1118;
  --color-bg-workspace: #0f1720;
  --color-bg-panel: #131d27;
  --color-bg-raised: #182431;
  --color-bg-interactive: #1c2a38;

  --color-text-primary: #e6edf3;
  --color-text-secondary: #a9b6c3;
  --color-text-muted: #748395;

  --color-border-subtle: #243241;
  --color-border-strong: #3a4c5f;

  --color-accent: #58a9f5;
  --color-info: #55bfd0;
  --color-success: #55b986;
  --color-warning: #e4a853;
  --color-danger: #eb6577;
  --color-ai: #a98cf3;
  --color-unknown: #8794a3;
}
```

라이트 테마는 같은 semantic token 이름만 재정의한다. 컴포넌트는 raw hex 값을 직접
사용하지 않는다.

## 3. 상태 언어

색상과 함께 기호와 전체 텍스트를 표시한다.

| 상태 | 기호 | 의미 | 색 |
|---|---:|---|---|
| Verified | ✓ | 도구/실행으로 확인 | success |
| Inferred | ≈ | 근거 기반 추론 | warning |
| Unknown | ? | 데이터 부족 | unknown |
| Confirmed | ● | 취약점/기법 확인 | danger 또는 success 문맥 |
| Likely | ◐ | 강한 다중 근거 | warning |
| Possible | ◇ | 후보 | info |
| Disproven | × | 반증됨 | unknown |

`used`와 `available`은 별도 label과 영역으로 표현하며 색만 바꾸지 않는다. AI에서 나온
내용은 `AI inferred` provenance badge와 보라색 보조선을 사용한다.

## 4. Typography

- UI: `Inter`, `Pretendard`, system sans-serif
- 분석 데이터: `JetBrains Mono`, `SFMono-Regular`, `Cascadia Code`, monospace
- 기본 UI: 14px / 1.5 이상
- 보조 설명: 12px 이상
- 고밀도 분석 table/code: 11~13px
- 주소/숫자: `font-variant-numeric: tabular-nums`

텍스트 hierarchy:

| Token | Size | Weight | 사용 |
|---|---:|---:|---|
| display | 32 | 650 | 화면 제목 |
| heading | 20 | 650 | 주요 section |
| subheading | 15 | 650 | panel title |
| body | 14 | 400 | 설명/상태 |
| dense | 12 | 400 | table/code |
| label | 11 | 600 | column/status label |

## 5. Spacing과 형태

- spacing scale: 4 / 8 / 12 / 16 / 24 / 32 / 48
- header: 56px
- expanded sidebar: 240px
- collapsed sidebar: 56px
- context header: 72~96px
- code/table radius: 2~4px
- modal/onboarding radius: 최대 8px
- panel 경계는 shadow보다 1px border를 우선한다.

## 6. 핵심 컴포넌트

Phase 1:

- `AppShell`: header, navigation, route Workspace, status bar
- `GlobalHeader`: product, page context, job/API state
- `Sidebar`: route navigation, recent artifacts, collapse
- `ContextHeader`: binary identity, analysis status, primary actions
- `StatusBadge`, `VerificationBadge`, `SeverityBadge`
- `DataTable`, `LoadingState`, `EmptyState`, `ErrorState`
- `JobProgress`: 정확한 percentage 없이 단계와 상태
- `UploadAction`

후속:

- `ResizablePanel`, `BottomPanel`, `Inspector`
- `AddressLink`, `SymbolLink`, `EvidenceList`, `FindingCard`
- `HexViewer`, `Timeline`, `CommandPalette`
- `TechniqueCard`, `ProtectionCard`, `ConfidenceIndicator`
- `ConfirmationDialog`, `Toast`

모든 interactive component는 default/hover/focus/active/selected/disabled/loading/error
상태를 정의한다.

## 7. Code와 data color

- address: accent
- symbol: text primary + underline on actionable
- register: info
- instruction: text primary
- immediate: warning
- string: success
- comment: muted
- error/current crash: danger
- current execution: accent background + arrow/icon
- breakpoint: danger icon + accessible label

mnemonic마다 무작위 색을 쓰지 않는다.

## 8. 접근성

- WCAG 2.1 AA 대비를 목표로 axe와 수동 검사를 병행한다.
- 모든 keyboard action에는 visible focus ring이 있다.
- icon-only button은 `aria-label`과 tooltip을 함께 제공한다.
- status는 `aria-live` 또는 적절한 role로 알린다.
- tab은 semantic tablist/tab/tabpanel 관계를 갖는다.
- modal은 focus trap과 Esc 닫기를 제공한다.
- `prefers-reduced-motion`에서 register highlight와 panel transition을 축소한다.
- tooltip을 유일한 정보 전달 수단으로 쓰지 않는다.

## 9. Motion

- panel/tab/toast transition: 120~180ms
- register delta highlight: 최대 600ms, 1회
- 지속 pulse/glow/scanline/typing animation 금지
- `prefers-reduced-motion: reduce`에서는 필수 상태 전환 외 animation 제거

## 10. 품질 검증

- 1440×900, 1920×1080, 1024×768에서 layout 확인
- keyboard-only smoke test
- axe 접근성 검사
- loading/empty/error/partial/permission/disconnected 상태 Story/fixture
- Playwright upload → analysis → Workspace 이동 flow
- 주요 화면 screenshot visual regression
