# Static Analyzers

## 포맷 탐지

입력은 파일명이나 MIME가 아닌 실제 byte signature와 구조로 판정한다.

- ELF: magic 후 pyelftools 전체 구조 검증
- PE: MZ, `e_lfanew`, PE signature, optional header, section raw range 검증
- raw: 아카이브/일반 텍스트를 제외한 binary-like bytes
- ZIP, TAR, gzip, bzip2, XZ, 7-Zip, RAR, Zstandard: 기본 거부

`MZ`로 시작하는 손상 PE를 raw로 강등하지 않고 parser error로 격리한다.

## 정규화 계층

`pwnable_lab.elf.parser`는 pyelftools 결과를 framework-independent dataclass로 변환한다.
핵심 정적 분석은 LIEF, readelf, objdump가 설치되지 않아도 동작한다.

정규화 항목:

- ELF class, endian, machine, type, entry
- section과 program segment permission
- static/dynamic symbol, import, export, function symbol
- interpreter, `DT_NEEDED`, SONAME, RPATH, RUNPATH
- GNU Build ID와 x86 GNU property
- REL/RELA relocation과 symbol target
- static/dynamic linking classification

업로드 바이너리를 파싱 과정에서 실행하지 않는다.

## PE32/PE32+

외부 명령어 없이 bounded parser로 다음을 읽는다.

- COFF/optional header, image base, entry RVA, subsystem, DLL characteristics
- section RVA/raw range/permission/entropy
- import DLL, import name/ordinal, IAT address
- named export, ordinal, address
- base relocation block
- ASLR, DEP/NX Compat, High Entropy VA, CFG, Force Integrity, AppContainer,
  NO_SEH, Authenticode certificate-table presence, RWX section

`DYNAMIC_BASE`가 있어도 base relocation이 없으면 ASLR을 효과적으로 활성화된
상태로 표시하지 않는다. CFG는 compatibility declaration으로 표시하고 runtime
enforcement를 확정하지 않는다. Authenticode는 certificate table 존재만 탐지하며
서명 유효성이나 trust chain을 검증했다고 표시하지 않는다.

## Raw binary

SHA-256, 크기, entropy, ASCII/UTF-16LE strings, hex는 format-neutral로 제공한다.
architecture, bitness, endian, entry, base address, memory permissions, loader mitigation은
`unknown`으로 유지한다. x86/x86-64 디스어셈블리는 사용자가 architecture와
base address를 제공한 경우에만 수행한다.

## Entropy

전체 파일과 ELF/PE section 또는 bounded raw window의 Shannon entropy를 계산한다.
높은 entropy 하나만으로 packing/encryption/obfuscation을 확정하지 않는다.

## GOT와 PLT

GOT entry 주소는 relocation의 `r_offset`에서 읽으므로 `verified`다. PLT stub 주소는
`.plt` 또는 `.plt.sec`의 `sh_entsize`와 PLT relocation 순서에서 계산하므로 `inferred`다.
entry size가 없으면 주소를 만들지 않고 `unknown`을 반환한다.

## Function recovery, xref, CFG

ELF와 PE의 file-backed executable section을 공통 code-region으로 정규화한다.

- ELF `STT_FUNC`, PE export, loader entry point: start address `verified`
- executable region을 향한 direct call: start address `inferred`
- 유효한 non-zero symbol size: boundary `verified`
- 다음 함수 또는 executable region 끝에서 계산한 boundary: `inferred`

CFG leader는 함수 시작, direct jump target, 조건 분기 fallthrough, terminator 다음
명령에서 만든다. Edge는 정적으로 확인된 direct target에만 생성한다. indirect jump,
jump table, exception flow, tail-call 여부는 데이터 흐름 또는 실행 근거가 없으면 만들지
않는다. xref는 direct call/jump와 x86 RIP-relative memory operand만 반환한다.

Raw bytes에는 loader map과 검증된 entry point가 없으므로 함수/CFG를 추측하지 않는다.

## ROP gadget semantics

ELF x86/x86-64의 file-backed executable section에서 terminal byte를 찾고, 가능한 시작
offset부터 terminal까지 Capstone으로 정확히 소비되는 sequence만 반환한다.

- 현재 terminal: `ret`, `ret imm16`, `syscall`, `int 0x80`
- verified: address, bytes, instructions, register access, memory access
- inferred: quality score, candidate category, chain state
- stack delta: pop/push/ret 및 immediate RSP add/sub만 계산
- `leave`, call, RSP move/xchg처럼 데이터 의존적인 변화는 `unknown`
- PIE는 가장 낮은 `PT_LOAD` 기준 offset을 별도로 반환

가젯이 존재한다는 사실은 ROP이 실제 사용되었거나 exploit이 성공한다는 근거가 아니다.
체인 모델은 명령을 실행하지 않으며 memory content, branch condition, called code, syscall,
runtime mapping을 재현하지 않는다.

## Checksec

각 보호 항목은 다음을 제공한다.

- `state`, `enabled`
- `verification`
- `evidence`
- `impact`
- `possible_strategies`
- `confidence`

분석 항목은 NX, executable stack, RELRO, stack canary, PIE, Fortify, CET, IBT,
Shadow Stack, RPATH, RUNPATH, RWX segment, symbol stripping, static linking이다.

정확성 제한:

- canary symbol 미탐지는 모든 함수에 canary가 없다는 증명이 아니다.
- Fortify symbol 미탐지는 안전 또는 compiler option 부재를 확정하지 않는다.
- CET GNU property는 binary declaration을 검증하지만 CPU/kernel/loader enforcement는
  정적으로 확정하지 않는다.
- PT_GNU_STACK 부재 시 effective permission은 `unknown`이다.

## Attack surface

x86/x86-64에서는 PLT/direct target을 향한 `call`을 탐지한다. x86-64는 call 전 최근
register write에서 SysV argument 후보를, x86은 최근 `push`에서 stack argument 후보를
추정한다.

이는 제한적인 local heuristic이다. alias, indirect call, interprocedural data flow,
compiler optimization을 완전히 복원하지 않는다. 따라서 결과는 `possible/inferred`이며
오탐 요인과 주변 disassembly를 함께 반환한다.

## Text crash-log analyzer

`text_crash_log` analyzer는 사용자가 제공한 UTF-8 GDB/pwndbg/GEF/generic 로그만 읽는다.
GDB를 호출하거나 연관 바이너리를 실행하지 않는다.

정규화 범위:

- signal, explicit fault address, crash instruction
- x86/x86-64 general register와 IP/SP/BP
- GDB `x/` pointer-sized stack value
- GDB `info proc mappings`와 Linux `/proc/{pid}/maps` 형식
- executable, stack, heap, libc, loader, mapped file, anonymous mapping
- register/stack byte의 bounded De Bruijn match와 cyclic offset
- executable pointer 기반 return-address candidate
- 64-bit low-NUL/location/mapping 휴리스틱 기반 canary candidate

로그에서 직접 읽은 토큰은 `verified`다. architecture는 register 이름에서,
pointer classification은 로그의 mapping 범위에서 파생하므로 `inferred`다. canary 후보는
low byte가 0이라는 단일 조건으로 확정하지 않으며 confidence를 낮게 유지한다. cyclic
offset이 RIP/EIP에서 일치하면 instruction-pointer overwrite를 `likely/inferred`로 제안하지만
실행 재현 없이 `confirmed`로 올리지 않는다.

기본 자원 상한은 2MiB, 100,000줄, 줄당 16,384자, 4,096 stack entry다. ANSI escape를
제거하고 과도한 control character, NUL, archive signature를 거부한다.

## Linux ELF core analyzer

`linux_elf_core` analyzer는 최대 64MiB의 Linux x86/x86-64 `ET_CORE` 파일을 실행하지 않고
직접 읽는다. ELF class/machine, program-header file range, note alignment/크기, PT_LOAD
file range를 먼저 검증하고 다음 근거를 정규화한다.

- `NT_PRSTATUS`: thread ID와 x86/x86-64 general registers
- `NT_SIGINFO`: signal/code와 fault address
- `NT_PRPSINFO`: bounded process name/arguments
- `NT_FILE`: mapped path와 file offset
- `PT_LOAD`: 실제 캡처된 memory bytes와 permissions
- IP의 Capstone instruction decode, SP 기준 pointer-sized stack 값
- monotonic/aligned frame-pointer chain의 inferred backtrace
- register/stack byte의 bounded n=4/n=8 De Bruijn match

note/register/memory에 직접 기록된 값과 instruction bytes는 `verified`다. pointer region,
return-address/canary 후보, frame-pointer backtrace, probable root cause는 캡처 근거에서
파생되므로 `inferred` 또는 `unknown`을 유지한다. 별도 module/symbol 분석 없이 함수명을
추측하지 않으며 optimized/corrupted frame의 backtrace 완전성을 보장하지 않는다.

기본 상한은 core 64MiB, program header/note 각 4,096개, note description별 8MiB,
NT_FILE mapping 8,192개, stack entry 4,096개, backtrace 64 frame이다. extended program-header
count, non-x86 machine, big-endian x86 조합은 현재 지원하지 않는다.

## Fixture policy

테스트는 저장소 내부 C source를 임시 디렉터리에서 컴파일하지만 생성한 ELF를 실행하지
않는다. compiler가 없는 환경에서는 compiler-specific fixture만 skip하며 합성 ELF 기반
핵심 parser 테스트는 계속 동작한다.
