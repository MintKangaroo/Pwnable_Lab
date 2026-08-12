# PwnPilot 구현 계획

## 1. 문서 목적

이 문서는 기존 `Pwnable_Lab` 코드베이스를 보존하면서 프로젝트를 PwnPilot로 확장하기 위한
단계별 구현 기준이다. 분석 대상은 교육용 CTF, 사용자가 소유한 바이너리, 명시적인 분석
권한을 받은 바이너리로 제한한다.

핵심 원칙은 다음과 같다.

- 업로드한 바이너리를 API/웹 백엔드 호스트에서 직접 실행하지 않는다.
- 정적 분석과 동적 실행의 신뢰 경계를 분리한다.
- 확인된 사실, 추론, 가정을 데이터 모델과 UI에서 구분한다.
- 외부 도구와 AI가 없어도 핵심 정적 분석은 동작한다.
- 각 Phase는 테스트와 명시적인 완료 조건을 통과한 뒤 다음 Phase로 진행한다.

## 2. 기존 코드 분석

### 2.1 현재 구조

현재 저장소는 다음 기능이 이미 동작하는 모노레포다.

- FastAPI 기반 HTTP API
- SQLAlchemy 2와 SQLite 기반 바이너리 메타데이터/문제 제출 저장
- SHA-256 콘텐츠 주소 방식 바이너리 저장 및 중복 제거
- pyelftools 기반 ELF32/ELF64 정규화 파서
- Capstone 기반 x86/x86-64 디스어셈블과 evidence-based ROP gadget metadata
- checksec, 문자열, GOT/PLT, 위험 심볼 휴리스틱
- cyclic, packing, overflow payload 도구
- 결정론적으로 생성되는 교육용 ELF 문제 6종
- React/Vite 기반 다크 테마 분석 UI
- Docker 이미지와 단일 Docker Compose 구성
- 백엔드 57개 테스트와 90% 커버리지 게이트

기준선 검증 결과:

- `pytest --cov=pwnable_lab`: 57 passed, 97.32%
- `npm run build`: 성공
- `npm audit --audit-level=high`: 취약점 0건
- `docker compose config`: 성공

### 2.2 재사용할 부분

| 기존 영역 | 재사용 방침 |
|---|---|
| `elf/parser.py`의 정규화 데이터 클래스 | 분석기 간 공통 ELF 표현으로 유지하고 필드를 점진 확장 |
| `analyzer/*` | Phase 2/3 어댑터의 초기 구현으로 이동 또는 호환 래퍼 유지 |
| `database/repository.py` | 서비스/저장소 분리의 출발점으로 유지, 원자적 저장과 소유권 필드 추가 |
| `api/routes/*` | `/api/v1` 계약으로 확장하고 기존 `/api`는 한시적 호환 경로로 유지 |
| `challenge/*`와 `elf/builder.py` | 교육용 fixture 및 회귀 테스트 데이터로 유지 |
| `payload/*` | Phase 1 도구 API와 Phase 4 크래시 분석에서 재사용 |
| React UI와 CSS | 시각 체계와 분석 컴포넌트를 보존하고 TypeScript/Router/Query로 점진 이행 |
| 기존 테스트 | 회귀 테스트로 유지하고 Phase별 계약/보안 테스트를 추가 |

### 2.3 현재 격차

- 기본 API prefix가 `/api`이며 요구 계약인 `/api/v1`이 없다.
- 업로드 상한이 16MiB이고 업로드가 단일 `read()` 호출로 처리된다.
- 임시 파일 fsync 및 원자적 채택을 사용하는 저장 경로가 없다.
- 바이너리 상세/삭제/분석 시작/분석 작업 상태 API가 없다.
- Alembic 마이그레이션과 PostgreSQL 드라이버가 없다.
- 개발용 작업 큐 추상화와 분석 작업 모델이 없다.
- 프런트엔드 진입점과 API 계층이 JavaScript이며 Router/Query 기반이 아니다.
- 운영 인증, 사용자별 격리, rate limit, 감사 로그, 비동기 worker는 아직 없다.
- 샌드박스 및 동적 분석 코드는 없으며 현재 정적 분석 전용이다.

## 3. 범위 구분

### 3.1 MVP: Phase 1~2

MVP는 업로드한 ELF, PE/EXE, raw binary를 안전하게 보관하고, 포맷별 핵심 정적 분석
결과를 웹에서 확인하는 범위다.

- 모노레포와 실행 가능한 FastAPI/React 애플리케이션
- `/api/v1` API와 OpenAPI 문서
- 32MiB 기본 상한의 청크 기반 업로드
- SHA-256 저장, 파일명 무시, ELF/PE 구조 검사, raw intake 정책, 중복 제거
- 원자적 파일 채택과 삭제
- SQLite 개발 모드, PostgreSQL 배포 모드, Alembic 마이그레이션
- 인라인 작업 큐와 분석 상태 API
- ELF metadata/GOT/PLT, PE metadata/import/export/relocation, raw strings/hex/entropy
- 근거/영향/신뢰도를 포함한 checksec
- 위험 함수 후보와 오탐 가능성 표시
- 기본 Dashboard/Binary Workspace/Hex View
- malformed/truncated/oversized/path traversal 회귀 테스트

MVP에서는 업로드 바이너리를 실행하지 않으며, 익스플로잇 성공을 검증했다고 표시하지 않는다.

### 3.2 후속 범위

- Phase 3: 함수/기본 블록/CFG/xref/고급 가젯과 ROP Studio
- Phase 4: core/GDB 로그/메모리/스택/포인터/크래시 분석
- Phase 5: 전략 랭킹과 근거 기반 pwntools 초안
- Phase 6A: 비대화형 격리 실행과 crash/strace 수집
- Phase 6B: GDB/MI, WebSocket, interactive debugger
- Phase 6C: packing/entropy/UPX/obfuscation/runtime strings
- Phase 6D: QEMU worker, rr, 동적 OEP와 재구성 지원
- Phase 7: LLM provider 추상화와 개인정보 제어
- 인증/권한, 사용자별 quota, 운영 rate limit, 장기 감사 보존

## 4. 목표 디렉터리 구조

현재 import 경로인 `pwnable_lab`은 호환성을 위해 유지하되, 내부를 아래 구조로 확장한다.

```text
Pwnable_Lab/
├── backend/
│   ├── alembic.ini
│   ├── migrations/
│   ├── pwnable_lab/
│   │   ├── api/
│   │   │   ├── routes/
│   │   │   ├── dependencies.py
│   │   │   └── errors.py
│   │   ├── analyzers/
│   │   │   ├── elf/
│   │   │   ├── checksec/
│   │   │   ├── disassembly/
│   │   │   ├── cfg/
│   │   │   ├── gadgets/
│   │   │   ├── vulnerability/
│   │   │   ├── memory/
│   │   │   ├── core_dump/
│   │   │   ├── libc/
│   │   │   ├── packing/
│   │   │   └── obfuscation/
│   │   ├── artifacts/
│   │   ├── database/
│   │   ├── exploit/
│   │   ├── jobs/
│   │   ├── llm/
│   │   ├── sandbox/
│   │   ├── services/
│   │   ├── workers/
│   │   ├── config.py
│   │   └── main.py
│   └── tests/
│       ├── fixtures/
│       ├── integration/
│       ├── security/
│       └── unit/
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── features/
│   │   │   ├── dashboard/
│   │   │   ├── binary-workspace/
│   │   │   ├── crash-analyzer/
│   │   │   ├── dynamic-analysis/
│   │   │   ├── rop-studio/
│   │   │   ├── exploit-studio/
│   │   │   └── technique-intelligence/
│   │   ├── routes/
│   │   └── types/
│   └── package.json
├── sandbox-runner/
│   ├── images/
│   ├── profiles/
│   ├── seccomp/
│   └── tests/
├── docs/
├── docker-compose.yml
├── docker-compose.dev.yml
└── docker-compose.prod.yml
```

기존 `analyzer/`, `challenge/`, `elf/`, `payload/` 디렉터리는 한 번에 이동하지 않는다.
기능을 확장할 때 새 어댑터와 호환 테스트를 추가한 뒤 점진적으로 재배치한다.

## 5. 단계별 구현 계획

프런트엔드의 정보 구조와 시각 규약은 다음 문서를 source of truth로 사용한다.

- `docs/INFORMATION_ARCHITECTURE.md`
- `docs/USER_FLOWS.md`
- `docs/DESIGN_SYSTEM.md`
- `docs/DASHBOARD_SPEC.md`

### Phase 1 — 프로젝트 기반

구현:

- `/api/v1`을 기본 계약으로 추가하고 기존 `/api` 경로를 호환 유지
- health check, 바이너리 업로드/목록/상세/삭제
- 분석 시작과 최신 작업 상태 조회
- 청크 스트리밍, 32MiB 상한, SHA-256, 안전한 이름, 원자적 저장
- `BinaryArtifact`, `BinaryAnalysisJob`, `AuditLog`의 Phase 1 최소 모델
- Alembic 초기 migration
- SQLite 및 PostgreSQL 설정
- 개발용 인라인 큐 인터페이스
- React TypeScript 진입점, Query/Router provider, 업로드와 작업 상태 UI
- 실제 데이터 기반 AppShell, Dashboard, Binary Context Header
- URL에 선택된 바이너리와 Workspace 탭 상태 반영
- 의미 기반 색상과 verified/inferred/unknown 표현을 위한 디자인 토큰
- Docker Compose 개발 실행과 문서

완료 조건:

- 유효한 ELF 업로드 및 목록/상세 표시
- 동일 파일 중복 제거
- 분석 작업이 `queued/running/completed/failed` 상태 중 하나로 조회
- 잘못된 ELF, 제한 초과 업로드, 경로 조작 파일명이 안전하게 처리
- 백엔드 테스트, 타입 검사, 프런트엔드 빌드, Compose 설정 검증 통과

### Phase 2 — 정적 ELF 분석

- interpreter, linked libc, needed libraries, relocation, 정확한 GOT/PLT
- import/export/dynamic symbol 구분
- checksec 결과를 상태/근거/영향/전략/신뢰도 객체로 변경
- CET/IBT/Shadow Stack, executable stack, W+X, static/dynamic 판정
- 호출 위치와 calling convention 기반 위험 함수 인자 추론
- 분석 결과 캐시 및 pagination
- fixture를 실제 C 컴파일 산출물로 보강

구현 상태(2026-08-02):

- 완료: interpreter/DT_NEEDED/libc/Build ID/RPATH/RUNPATH/linking 정규화
- 완료: static/dynamic/import/export/function symbol과 relocation pagination API
- 완료: relocation 기반 verified GOT와 section layout 기반 inferred PLT
- 완료: 근거/영향/전략/confidence 기반 14개 checksec 항목
- 완료: x86/x86-64 direct call과 제한적 calling-convention 인자 추정
- 완료: GCC 생성 protected dynamic/static fixture와 API 회귀 테스트
- 진행 예정: indirect call과 interprocedural data flow 정밀화, 대형 결과 DB cache 분리

포맷 확장 상태(2026-08-02):

- 완료: ELF/PE/raw signature detection과 archive/text 거부 정책
- 완료: PE32/PE32+ header, section, import/export, base relocation parser
- 완료: PE ASLR/DEP/CFG 등 근거 기반 보호 기법 판정
- 완료: raw entropy/strings/hex와 명시적 x86/x86-64/base-address disassembly
- 완료: format DB migration, format-aware analysis job v3, UI capability tabs
- 진행 예정: PE delay import/load-config 심화, ARM/AArch64/raw architecture adapter

### Phase 3 — 디스어셈블리와 ROP

- 아키텍처 어댑터와 함수 경계 탐지
- 기본 블록, CFG, xref, 주소/opcode/문자열 참조 검색
- Capstone detail 기반 register read/write, stack delta, side effect
- 가젯 필터, PIE offset, bad byte, 품질 점수
- React Flow 또는 Cytoscape 기반 CFG/ROP Studio

1차 구현 상태(2026-08-02):

- 완료: ELF/PE x86·x86-64 executable region 공통 adapter
- 완료: symbol/export/entry의 verified start와 direct-call inferred start 분리
- 완료: symbol size 기반 verified boundary와 neighbour/region 기반 inferred boundary
- 완료: 함수 detail, basic block CFG, predecessor/successor, direct edge, call target API
- 완료: direct call/jump 및 RIP-relative memory xref API와 pagination
- 완료: Functions/CFG/Disassembly 사이 URL address 상태와 Inspector UI
- 완료: ret/ret-imm/syscall/int80 exact gadget scan과 Capstone access metadata
- 완료: stack delta, register/memory side effect, PIE offset, inferred quality score
- 완료: safe regex/register/category/stack/bad-byte filter와 server pagination
- 완료: 3-panel ROP Studio, drag/reorder chain, inferred state, `flat` draft
- 진행 예정: indirect branch/jump table, dominator, string/symbol xref, 대형 graph 가상화
- 진행 예정: standalone indirect call/jump terminal, deeper data-flow, chain goal builder

### Phase 4 — 크래시와 메모리

- ELF core note, GDB/pwndbg/gef 텍스트 파서
- register/stack/maps/backtrace/fault 정보 정규화
- cyclic offset과 포인터 영역 분류
- 다중 근거 stack canary 후보
- 메모리 hex/pointer/string/snapshot diff

2차 구현 상태(2026-08-12):

- 완료: UTF-8 GDB/pwndbg/GEF/generic text log intake와 2MiB bounded read
- 완료: ANSI/control 정규화, line/stack-entry 상한, archive/임의 binary 거부
- 완료: signal, fault address, x86/x86-64 register와 current instruction 파싱
- 완료: GDB `x/` stack, `info proc mappings`, `/proc/maps` 정규화
- 완료: runtime mapping 기반 pointer class와 return-address/canary candidate
- 완료: RIP/EIP/stack De Bruijn match, cyclic offset, probable cause 분리
- 완료: crash artifact/analysis/audit model, migration, list/detail/reanalysis API
- 완료: 실제 API 기반 Crash Analyzer UI와 Playwright flow/screenshot
- 보안 수정: `n=8` cyclic 생성이 전체 주기를 선구성하던 경로를 streaming으로 변경
- 완료: Linux x86/x86-64 ELF core header/program-header/file-range bounded validation
- 완료: `NT_PRSTATUS`, `NT_SIGINFO`, `NT_PRPSINFO`, `NT_FILE`, 다중 thread 정규화
- 완료: PT_LOAD stack/mapping, current instruction, cyclic match와 frame-pointer backtrace
- 완료: content-addressed core persistence, migration, 재분석과 backtrace API/UI
- 진행 예정: pwndbg/GEF stack format 확대, 다중 근거 canary, snapshot diff

이 구현은 업로드한 바이너리/core를 실행하거나 host GDB를 호출하지 않는다. 로그/core에
직접 기록된 값은 `verified`, pointer/frame/root-cause/canary 해석은 `inferred` 또는
`unknown`으로 보존한다.

### Phase 5 — 익스플로잇 어시스턴트

- primitive와 mitigation 기반 전략 랭킹
- ret2win 검증 fixture부터 pwntools 초안 생성
- ret2libc/format string/canary/stack pivot/SROP scaffold
- 미확인 주소는 `0`과 TODO로만 표현
- AST/정적 검증과 sandbox validation 준비
- Monaco 기반 Exploit Studio

### Phase 6A — 비대화형 동적 분석

- backend와 분리된 sandbox orchestrator/runner
- 네트워크 없음, read-only root, non-root, cap drop, seccomp
- PID/CPU/메모리/파일/시간/출력 제한
- stdin fixture, stdout/stderr, strace, core, maps, crash timeline
- 세션 종료/취소/cleanup/audit

### Phase 6B — 대화형 디버거

- GDB/MI 어댑터와 정규화 이벤트
- 세션별 단일 실행 명령 lock, timeout, cancellation
- WebSocket 재연결과 grace period
- breakpoint/watchpoint/register/stack/memory/disassembly
- 사용자/세션 격리

### Phase 6C — 패킹과 난독화

- 전역/section/segment entropy와 다중 근거 packing 판정
- UPX signature/test와 공식 decompression
- 원본-파생 artifact 관계와 검증 결과
- obfuscation/anti-debug heuristic와 오탐 요인
- runtime string recovery와 민감정보 제외
- Technique Intelligence/Attack Chain UI

### Phase 6D — 고급 실행 추적

- 아키텍처별 worker와 QEMU user-mode
- native/emulated 결과 구분
- rr/reverse debug 후보
- OEP 후보, memory dump, ELF reconstruction assistance
- syscall/function/timeline correlation

### Phase 7 — AI 설명

- `AnalysisLLMProvider` Protocol
- Mock/OpenAI-compatible/Ollama-compatible provider
- 서버 환경변수 기반 key 관리
- 선택된 정규화 데이터만 외부 provider에 전달
- observation/inference/assumption/recommendation/confidence 강제
- AI 실패가 핵심 분석 작업에 전파되지 않는 회귀 테스트

## 6. 기술적 위험

| 위험 | 영향 | 대응 |
|---|---|---|
| 악성/손상 ELF/PE에 의한 parser DoS | worker 메모리/CPU 고갈 | 업로드/분석 크기 상한, bounded table, 별도 worker, malformed corpus |
| pyelftools/LIEF/Capstone 결과 불일치 | 잘못된 판정 | 정규화 계층, analyzer/version/evidence 저장, fixture 교차 검증 |
| stripped/최적화 바이너리의 함수 경계 오류 | CFG와 호출 추론 오탐 | inferred 상태, confidence, r2/Rizin 선택 어댑터로 교차 확인 |
| 대형 분석 JSON | DB/네트워크/브라우저 부담 | 요약/상세 분리, pagination, blob/object storage, TTL cache |
| SQLite와 PostgreSQL 동작 차이 | 운영 migration 실패 | CI PostgreSQL 통합 테스트, Alembic 단일 source of truth |
| 인라인 큐의 프로세스 장애 | 작업 상태 유실/고착 | Phase 1은 개발 전용 표기, 운영은 Redis worker와 heartbeat/reaper |
| GDB/MI 비동기 이벤트 순서 | UI 상태 불일치 | command ID, monotonic sequence, session lock, idempotent reducer |
| QEMU와 native 동작 차이 | 잘못된 동적 결론 | execution mode/limitations를 결과에 필수 저장 |
| 동적 unpack reconstruction 불완전 | 원본으로 오인 | `reconstructed` artifact, 검증 항목과 unknown 영역 표시 |
| LLM 환각 | 가짜 주소/전략 생성 | verified 데이터 allowlist, 구조화 schema, address provenance validator |

## 7. 보안 위협과 통제

### 업로드/저장

- 경로 조작: 원본 이름을 저장 경로에 사용하지 않고 basename만 표시한다.
- oversized upload: Content-Length를 신뢰하지 않고 청크 누적 크기로 제한한다.
- archive/decompression bomb: ELF/PE/raw만 허용하고 known archive signature를 거부한다.
- 중복/경합: content hash와 원자적 파일 생성으로 기존 파일을 덮어쓰지 않는다.
- parser exploit: 구조 오류를 4xx로 정규화하고 향후 정적 분석 worker로 분리한다.
- cross-tenant 접근: 인증 도입 전 단일 사용자 개발 모드로 명시하고 운영 노출을 금지한다.

### API/제어 평면

- IDOR/job ownership: Phase 1 모델에 소유자 확장 지점을 두고 인증 Phase에서 강제한다.
- rate abuse: 업로드/고비용 분석별 제한과 사용자 quota를 적용한다.
- log injection: 사용자 파일명을 구조화 필드로 저장하고 제어 문자를 제거한다.
- SSRF: 외부 대상 URL 입력 기능을 기본 비활성화하고 등록된 CTF target만 허용한다.
- command injection: shell 문자열 조립을 금지하고 argv allowlist를 사용한다.

### 샌드박스

- container breakout: runner를 별도 보안 경계에 두고 backend에 Docker socket을 주지 않는다.
- network abuse: `network_mode=none`과 네트워크 syscall seccomp를 함께 적용한다.
- fork bomb/resource exhaustion: pids/cgroup/rlimit/timeout/output 제한을 중첩 적용한다.
- host disclosure: 호스트 디렉터리/절대 경로/socket/secret를 마운트하지 않는다.
- persistence: 일회성 worker와 종료 후 강제 삭제, 허용된 artifact만 별도 저장한다.
- debugger privilege: ptrace는 격리된 worker 내부 target에만 최소 범위로 허용한다.

## 8. 정확성 및 데이터 규약

- finding/technique 상태: `possible`, `likely`, `confirmed`, `disproven`
- 값 검증 상태: `verified`, `inferred`, `unknown`
- 모든 분석 결과: analyzer name/version, status, error, evidence, confidence, timestamp
- technique의 `used`와 `available`을 별도 객체로 저장
- static import만으로 취약점/anti-debug/packing/ROP 사용을 확정하지 않음
- entropy, stripped, indirect jump 등 단일 휴리스틱으로 결론을 확정하지 않음
- 실행하지 않은 exploit을 성공으로 표시하지 않음

## 9. Phase 1 이후 바로 할 일

1. 실제 컴파일된 보호 기법별 ELF fixture를 추가한다.
2. 분석 결과 schema를 evidence/confidence 중심으로 버전 관리한다.
3. interpreter/DT_NEEDED/relocation/GOT/PLT 분석을 보강한다.
4. 정적 분석을 프로세스 격리 worker로 이동하고 시간/메모리 제한을 건다.
5. 사용자 인증과 artifact/job 소유권을 도입하기 전에는 외부 운영 노출을 금지한다.
