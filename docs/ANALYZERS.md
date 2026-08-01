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

## Fixture policy

테스트는 저장소 내부 C source를 임시 디렉터리에서 컴파일하지만 생성한 ELF를 실행하지
않는다. compiler가 없는 환경에서는 compiler-specific fixture만 skip하며 합성 ELF 기반
핵심 parser 테스트는 계속 동작한다.
