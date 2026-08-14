# PHASE 1 — 인벤토리

대상: 저장소 전체 (읽기 전용 감사). 기준선: pwntools / pwndbg / ROPgadget / one_gadget / checksec / angr.
모든 항목에 `경로:라인` 근거 첨부. 확인 못 한 것은 UNVERIFIED로 분류. 이 문서는 인벤토리 단계이며, 정확성 검증(계산식 라인 검증)은 Phase 2에서 수행한다.

---

## 0. 한 줄 요약

이 도구는 **업로드 바이너리를 실행하지 않는 순수 정적 분석 + 오프라인 페이로드 계산기 + 사후(post-mortem) 크래시/코어 파서**다.
동적 분석(디버거/ptrace/실행)은 **존재하지 않는다**. 근거: `backend/pwnable_lab/` 전체에 `subprocess`/`os.system`/`os.popen`/`eval(`/`exec(` 호출 **0건** (grep 결과 0). 문서도 동적 실행은 미구현(Phase 6A)이라 명시한다: `docs/AUTO_EXPLOIT_SANDBOX.md:3`.

---

## 1. 의존성 지도 — 직접 구현 vs 래핑

### 선언된 런타임 의존성 (`backend/pyproject.toml:13-23`)
- `capstone>=5.0,<6` — 디스어셈블리 엔진 (래핑)
- `pyelftools>=0.31,<1` — ELF 파싱 (래핑)
- `fastapi`, `uvicorn`, `pydantic`, `SQLAlchemy`, `psycopg`, `alembic`, `python-multipart` — 웹/DB 인프라

### 기준선 도구 중 **부재**한 것 (전부 미사용)
- **pwntools**: 미설치. `from pwn import *`는 생성 스켈레톤 **문자열 안**에만 존재(`backend/pwnable_lab/analyzer/strategy.py:672`)이며 런타임 import 아님.
- **ROPgadget / ropper**: 미설치. 문자열 언급만: `backend/pwnable_lab/errors.py:39`. 대조 검증 로직 **없음** → UNVERIFIED(Phase 2 A에서 자체 가젯 검색을 ROPgadget과 수동 대조 필요).
- **one_gadget**: 미설치. 언급만: `strategy.py:624`, `errors.py:39`. one_gadget constraint 검증 기능 **없음**.
- **angr**: 미사용 (심볼릭 실행 없음).
- **gdb / ptrace**: 미사용. 크래시 분석은 **live 프로세스가 아니라** 업로드된 텍스트 로그/ELF 코어 파일을 파싱한다 (§4-B).
- **libc-database**: 미사용. libc 버전 식별/leak→offset 조회 기능 **없음** (grep: `libc.database|one_gadget` 코드 히트 0건, 문자열/문서 언급만).

### 자체 구현(직접 작성) 핵심 로직
- De Bruijn cyclic 생성/탐색: `backend/pwnable_lab/payload/cyclic.py` (pwntools `cyclic` 알고리즘 재구현, `n=4` 기본)
- checksec류 보호기법 판정: `backend/pwnable_lab/analyzer/checksec.py` (ELF 헤더/세그먼트/동적 태그 파싱)
- ROP 가젯 검색/시뮬레이션: `backend/pwnable_lab/analyzer/gadgets.py` (capstone 디코드 + 자체 스캐너)
- GOT/PLT 매핑: `backend/pwnable_lab/analyzer/got_plt.py`
- CFG/함수 경계: `backend/pwnable_lab/analyzer/control_flow.py`
- 취약 API 스캔: `backend/pwnable_lab/analyzer/vuln_scan.py`
- 익스 전략 추천: `backend/pwnable_lab/analyzer/strategy.py`
- 의사-C(pseudo-C): `backend/pwnable_lab/analyzer/decompile.py` (**실제 디컴파일러 아님**, 룰 기반 — 자체 주석 명시)
- 코어덤프 파서: `backend/pwnable_lab/analyzer/core_dump.py` (NT_PRSTATUS 등 note 직접 파싱)
- 크래시 로그 파서: `backend/pwnable_lab/analyzer/crash_log.py`
- PE 파서/분석: `backend/pwnable_lab/pe/parser.py`, `backend/pwnable_lab/pe/analyzer.py` (pefile 미사용, 자체 파싱)
- 패킹(p32/p64/u32/u64): `backend/pwnable_lab/payload/pack.py`

**정확성 함의**: 가젯 검색·checksec·cyclic·PE 파싱 모두 표준 도구 래핑이 아니라 **자체 재구현**이다. 따라서 각 계산이 ROPgadget/checksec/pefile과 일치하는지 대조 검증이 없으면 정확성은 UNVERIFIED. capstone/pyelftools에 위임하는 부분(순수 디스어셈블·ELF 섹션 파싱)만 상대적으로 신뢰 가능.

---

## 2. 기능 목록 및 분류

분류: (a) 정적 분석 · (b) 동적 분석 · (c) 익스 생성/보조 · (d) 단순 표시

### 바이너리 워크스페이스 (`backend/pwnable_lab/api/routes/binaries.py`)

| 엔드포인트 | 분류 | 구현 모듈 | 근거 |
|---|---|---|---|
| `POST /binaries` (업로드) | d | 저장/해시 | `binaries.py:35` |
| `GET /binaries/{sha}/info` | a | 포맷 감지 | `binaries.py:162` |
| `GET .../elf` | a | ELF 파서 | `binaries.py:171`, `elf/parser.py:159` |
| `GET .../pe` | a | PE 파서 | `binaries.py:181`, `pe/parser.py:144` |
| `GET .../checksec` | a | 보호기법 판정 | `binaries.py:192`, `checksec.py:70` |
| `GET .../vulns` | a | 위험 API 스캔 | `binaries.py:201`, `vuln_scan.py:141` |
| `GET .../strategy` | **c** | 익스 전략+pwntools 스켈레톤 | `binaries.py:210`, `strategy.py:98` |
| `GET .../functions/{addr}/pseudocode` | a | 룰기반 의사-C | `binaries.py:220`, `decompile.py` |
| `GET .../gadgets` | a→c | ROP 가젯 검색/필터 | `binaries.py:231`, `gadgets.py:109` |
| `POST .../rop/simulate` | **c** | inferred 체인 레이아웃 | `binaries.py:276`, `gadgets.py:235` |
| `GET .../symbols /imports /exports` | a | 심볼 페이지 | `binaries.py:290,306,319` |
| `GET .../functions[/{addr}][/cfg]` | a | 함수 인덱스/CFG | `binaries.py:332,346,358`, `control_flow.py` |
| `GET .../xrefs` | a | 상호참조 | `binaries.py:368` |
| `GET .../relocations /libraries /got /plt` | a | 재배치/GOT/PLT | `binaries.py:389,400,409,420`, `got_plt.py:71` |
| `GET .../strings` | a | 문자열 추출 | `binaries.py:431`, `strings.py` |
| `GET .../entropy` | a | Shannon 엔트로피 | `binaries.py:441`, `entropy.py` |
| `GET .../disassembly` | a | capstone 디스어셈블 | `binaries.py:450`, `disasm.py:59` |
| `GET .../hex` | d | 헥스 뷰 | `binaries.py:469` |

### 페이로드 스튜디오 (`backend/pwnable_lab/api/routes/payload.py`) — 전부 오프라인 계산기
| 엔드포인트 | 분류 | 근거 |
|---|---|---|
| `POST /payload/cyclic` | **c** | `payload.py:33`, `cyclic.py:35` |
| `POST /payload/cyclic/find` | **c** | `payload.py:48`, `cyclic.py:47` |
| `POST /payload/pack` | c | `payload.py:61`, `pack.py:10` |
| `POST /payload/overflow` | c | `payload.py:68`, `pack.py:38` |
| `GET /payload/shellcode[/{slug}]` | d | `payload.py:84,89`, `shellcode.py:67` |

### 크래시/코어 분석 (`backend/pwnable_lab/api/routes/crashes.py`) — **사후 파싱**, 동적 아님
| 엔드포인트 | 분류 | 근거 |
|---|---|---|
| `POST /crashes` (텍스트 로그 or ELF 코어 업로드) | b* | `crashes.py:32` |
| `POST /crashes/{id}/analyze` | b* | `crashes.py:109` |
| `GET .../registers /stack /mappings /backtrace` | b*/d | `crashes.py:125,134,145,156` |

\* **동적 분석으로 오해 금지**: live 디버깅이 아니라 사용자가 올린 정적 로그/코어 파일 파싱이다. `POST /crashes`는 최대 2MiB 텍스트 또는 최대 64MiB Linux x86/x86-64 ELF 코어만 받는다(`docs/API.md:121`). 실제 크래시를 **유발**하는 코드는 없음.

### 챌린지 (`backend/pwnable_lab/api/routes/challenges.py`) — 교육용 생성기
- 목록/상세/아티팩트/제출: `challenges.py:15,25,37,47`
- 생성기 6종: `backend/pwnable_lab/challenge/generators/` — `ret2win.py`, `rop_chain.py`, `offset_hunt.py`, `gadget_hunt.py`, `format_flag.py`, `checksec_audit.py` (분류 d, 학습 콘텐츠 생성)

### 프론트엔드 (`frontend/src/components/`)
- `Analysis.jsx`, `PayloadStudio.jsx`, `CrashAnalyzer.jsx`, `Challenges.jsx`, `Common.jsx` — 모두 위 API 결과 **표시(d)**. 계산은 백엔드에서 수행.

---

## 3. 아키텍처 커버리지

**결론: x86 / x86-64 ELF 전용. ARM / AArch64 / MIPS 전부 미지원.**

- 디스어셈블 gate: `disasm.py:38` — `image.machine not in {"EM_386","EM_X86_64"}`이면 거부
- 가젯 검색 gate: `gadgets.py:99-102` — "supports x86/x86-64 ELF only"
- 취약 스캔 gate: `vuln_scan.py:201` — 동일 machine 집합
- CFG gate: `control_flow.py:32` — `_SUPPORTED_ELF_MACHINES = {"EM_386","EM_X86_64"}`
- capstone은 전부 `CS_ARCH_X86`로만 초기화 (예: `gadgets.py:104`, `control_flow.py:492`, `vuln_scan.py:216`, `disasm.py:59`). `CS_ARCH_ARM/ARM64/MIPS` 사용처 0건.
- 셸코드 카탈로그: `amd64`/`i386` 2종 arch만 (`shellcode.py:17` 주석 `"amd64" | "i386"`, 항목들 `shellcode.py:42-58`).
- ELF **파서 자체**(`elf/parser.py:179`)는 `e_machine`을 문자열로 그대로 저장하므로 ARM/MIPS ELF도 파싱은 되지만(섹션/심볼), 이후 모든 분석기가 machine으로 거부한다. → ARM/MIPS 바이너리는 "메타데이터는 보이지만 가젯/가상/전략 전부 불가".

**전제/함의**: 32/64비트 분기는 `image.bits`(`elf/parser.py:177`)로만 결정. bits 오판 시 전 분석기 폴백 정확성은 Phase 2 D(silent failure)에서 검증 필요 — UNVERIFIED.

---

## 4. 포맷 감지

`backend/pwnable_lab/formats/detection.py:44-70`:
- `\x7fELF` → ELF (`:53`)
- `MZ` → PE (`:55`)
- 그 외 휴리스틱 통과 시 raw 기계어 (`:67`)
- 아카이브/컨테이너 시그니처는 거부 (`:47` 주석)

---

## 5. 문서 O / 구현 X (documented-but-unimplemented)

- **Auto-Exploit Sandbox (동적 오프셋 확정, cyclic 자동 주입→크래시→오프셋)**: 문서 `docs/AUTO_EXPLOIT_SANDBOX.md` 전체가 "계획됨(미구현)"으로 명시(`:3`). 코드 없음.
- **Worker / 비동기 잡 큐 (Redis)**: `docs/ARCHITECTURE.md:102` — "Redis는 후속 worker를 위한 foundation이며 Phase 1 inline queue가 사용하지 않는다" → 현재 인라인 처리만.
- **Dashboard 동적 session / technique distribution**: `docs/DASHBOARD_SPEC.md:35` — "실제 API가 생기는 Phase에 추가" (미구현).
- **Job history / 단계별 progress / cancellation**: `docs/USER_FLOWS.md:47-48` — 미구현 명시.

## 6. 구현 O / 문서 부실 (implemented-but-underdocumented)

- **`GET /binaries/{sha}/strategy` (익스 전략 + pwntools 스켈레톤)**: 구현됨(`strategy.py:98`, 라우트 `binaries.py:210`)이나 `docs/API.md`의 static analysis 표에 미등재 (표는 `:44-59`에서 끝, strategy 없음). → UNVERIFIED: strategy 엔드포인트의 계약 문서 위치 재확인 필요.
- **`GET .../functions/{addr}/pseudocode` (의사-C)**: 구현됨(`binaries.py:220`)이나 실제 디컴파일러가 아님에도 API 표 미등재로 보임 → Phase 2에서 사용자 오해 리스크 평가.

---

## 7. 초기 정확성 리스크 플래그 (Phase 2 심층 대상, 여기선 제기만)

1. **가젯 검색 자체 구현 + ROPgadget 대조 없음** (`gadgets.py`) → unaligned/중첩 가젯 누락 여부 미검증. **UNVERIFIED**.
2. **checksec 자체 구현** (`checksec.py`) → Canary/FORTIFY는 심볼 기반 `inferred`(`checksec.py:158,194`), 실제 checksec와 판정 일치 여부 미검증. **UNVERIFIED**.
3. **cyclic n=8 미지원** (`cyclic.py:66` 주석) → 64비트 RSP 8바이트 매칭 시 4바이트 needle로만 검색. 오프셋 산출 정확성 Phase 2 B에서 라인 검증 필요.
4. **strategy 오프셋은 `inferred`** (`strategy.py:242 _infer_offset`, `:667` "offset = 0 # TODO") → 스켈레톤에 플레이스홀더/TODO 잔존. 실행 가능성 Phase 2 C에서 검증.
5. **PE 파싱 자체 구현** (`pe/parser.py`) → pefile 대조 없음. **UNVERIFIED**.
6. **비-ASCII 인코딩 손상** 흔적: `strategy.py:624` 문자열에 `静的`(중국어 글자, 정상은 "정적") — 표시 데이터 무결성 신호, Phase 2 D에서 추적.

---

## 8. 테스트 자산 (Phase 2 F 입력)

- `backend/tests/` 16개 `test_*.py` (`test_analyzer.py`, `test_control_flow.py`, `test_core_dump.py`, `test_strategy.py`, `test_api.py`, `test_challenges.py`, `test_artifact_storage.py` 등). 커버리지 `fail_under=90` 설정(`pyproject.toml`).
- **정답 아는 실제 CTF 바이너리로의 회귀 대조**(오프셋/가젯 골든값) 존재 여부: **UNVERIFIED** — Phase 2 F에서 fixtures 내용 확인 필요.

---

## 9. Phase 1 UNVERIFIED 목록 (다음 단계로 이월)

- U1. 자체 가젯 검색 ↔ ROPgadget 결과 일치 (unaligned/overlap 포함)
- U2. 자체 checksec ↔ 표준 checksec 판정 일치 (특히 RELRO/Canary/FORTIFY)
- U3. cyclic 오프셋 산출식의 엔디안/워드크기(32↔64) 정확성
- U4. strategy 생성 pwntools 코드의 실제 실행 가능성 (플레이스홀더 비율)
- U5. PE 파서 ↔ pefile 일치 (imports/exports/relocations)
- U6. bits/machine 자동 감지 실패 시 silent-0/빈배열 폴백 존재 여부
- U7. 크래시/코어 파서의 레지스터 엔디안·64/32 처리 정확성
- U8. CTF 골든값 회귀 테스트 유무

---

**Phase 1 종료. 지시대로 여기서 멈춘다.** Phase 2 진행 승인 시 축 A(정적 분석 정확성)부터 착수한다.
