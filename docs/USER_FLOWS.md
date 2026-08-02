# PwnPilot 주요 사용자 흐름

## 1. 첫 ELF 분석

```text
Dashboard
  → Upload Binary
  → client size check
  → POST /api/v1/binaries
  → ELF validation + SHA-256 storage
  → POST /api/v1/binaries/:id/analyze
  → queued/running/completed or failed
  → Binary Overview
  → protection summary + important evidence + next action
```

규칙:

- 업로드 진행 중에는 대상 이름과 현재 단계만 표시하고 가짜 percentage는 쓰지 않는다.
- parser 실패 시 업로드 화면을 유지하고 오류 코드와 해결 방법을 표시한다.
- 분석이 실패해도 업로드된 artifact 상세와 가능한 정적 데이터는 유지한다.
- 동일 SHA는 새 바이트를 만들지 않고 기존 Workspace로 이동한다.

## 2. 최근 작업 이어가기

```text
Dashboard Recent Workspaces
  → select artifact
  → /binaries/:id/overview
  → URL에서 binary/tab 복구
  → 마지막 분석 상태 표시
  → 필요한 경우 Re-run Analysis
```

사용자는 파일명, architecture, short SHA, 작업 상태로 대상을 구분한다.

## 3. 분석 실패 복구

```text
Analysis Queue: Failed
  → open job detail
  → friendly summary + technical error + failed stage
  → retry static analysis
  → previous artifact and completed panels remain visible
```

Phase 1은 최신 작업 상태만 제공한다. 전체 job history, 단계별 progress, cancellation은
worker가 도입되는 Phase에서 추가한다.

## 4. 함수에서 CFG와 디스어셈블리로 이동

```text
Functions
  → verified start / inferred boundary 확인
  → select function (URL address 유지)
  → CFG basic blocks + direct edges
  → incoming xref 선택 또는 block address 선택
  → Disassembly at exact address
```

Raw binary에는 이 흐름을 제공하지 않는다. ELF/PE에서도 indirect branch target은
정적으로 확인되지 않으면 edge나 함수 주소를 만들지 않는다.

## 5. Finding에서 근거로 이동

```text
Finding row
  → Finding Inspector
  → evidence source 선택
  → affected function/address
  → Disassembly at exact address
  → xref / argument inference / runtime evidence
```

ELF direct-call은 확인된 call address와 제한적 인자 추정을 제공한다. PE import는
IAT address를 검증하지만 call-site data flow를 복원하지 않았으므로 `possible/inferred`로
표시하며 가짜 call address를 만들지 않는다.

## 6. 크래시에서 익스플로잇 전략으로 이동

```text
Upload core/log
  → normalize crash
  → inspect RIP/fault/stack
  → cyclic offset or primitive inference
  → related finding
  → Technique Intelligence
  → Exploit Plan
  → verified local sandbox validation
```

정적 추론과 런타임 확인 결과를 합칠 때 provenance를 잃지 않는다.

## 7. Interactive Debugging

```text
Create Session
  → disposable sandbox prepared
  → WebSocket connected
  → GDB/MI start
  → breakpoint / run / stop event
  → register, stack, memory snapshot
  → timeline event selection
  → stop/crash/timeout/disconnect grace
  → artifact collection + sandbox deletion
```

동시에 하나의 실행 명령만 허용한다. 메모리/레지스터 수정은 old/new 값을 보여 준 뒤
확인하며 audit event를 남긴다.

## 8. ROP Chain 작성

```text
Finding / Technique
  → Open ROP Studio
  → filter verified gadgets
  → add gadget/literal/symbol
  → simulate stack/register state
  → resolve PIE/libc unknowns
  → convert to pwntools draft
```

존재하지 않거나 unresolved인 주소는 0과 TODO로 유지한다. 잘못된 chain은 색상뿐 아니라
alignment, clobber, bad byte, unresolved base 등 구체적인 이유를 표시한다.

## 9. Packing 분석

```text
Packing: likely
  → review multiple evidence rows
  → safe supported unpack
  → create derived artifact
  → compare source / derived
  → reanalyze derived artifact
```

원본, unpacked, reconstructed artifact의 상태를 구분하고 원본을 덮어쓰지 않는다.

## 10. 키보드 흐름

- `Ctrl/Cmd + K`: command palette
- `G`: Workspace에서 주소 이동
- `F`: 현재 데이터 검색
- `Esc`: 선택/Inspector/palette 닫기
- `Enter`: 선택 항목 열기

브라우저 기본 단축키를 덮어쓰지 않으며 입력 필드에 포커스가 있을 때 단일 키 단축키를
발동하지 않는다.
