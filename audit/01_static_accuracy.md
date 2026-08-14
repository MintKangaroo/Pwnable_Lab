# 축 A — 정적 분석 정확성 (최우선)

방법: 실제 gcc 컴파일 바이너리 6종 + static 바이너리로 도구 출력을 checksec/ROPgadget/objdump와 실측 대조. 확인 못 한 항목만 UNVERIFIED.

---

## A-1. checksec류 보호기법 — 실제 ELF 파싱이다 (문자열 매칭 아님). 판정 정확.

`run_checksec`(`backend/pwnable_lab/analyzer/checksec.py:70`)는 `ElfImage` 의 세그먼트/동적태그/심볼/gnu_property 를 읽는다. 문자열 grep 아님.

실측 결과 (컴파일 바이너리):

| 바이너리 | 도구 판정 | 정답 | 일치 |
|---|---|---|---|
| `-fcf-protection=full` | cet=True ibt=True shstk=True | IBT+SHSTK | ✅ |
| `-fstack-protector-all` | canary=True | canary | ✅ |
| `-z execstack -no-pie` | nx=False execstack=True pie=No PIE | 실행가능스택 | ✅ |
| `-static` | static=True | static | ✅ |
| `-z relro -z now` | relro=Full | Full RELRO | ✅ |

- NX 판정 `_analyze_nx`(`checksec.py:342`) = `not PT_GNU_STACK.executable`. 정확.
- PIE 판정 `_analyze_pie`(`checksec.py:370`): ET_DYN + PT_INTERP → PIE `verified`; ET_DYN + no INTERP + entry==0 → DSO; ET_DYN + no INTERP + entry!=0 → PIE `inferred`. naive checksec 보다 정밀. 정확.
- RELRO: `PT_GNU_RELRO` 존재 + `_has_bind_now`(`checksec.py:535`, `DT_BIND_NOW` 또는 `DF_BIND_NOW=0x8` 또는 `DF_1_NOW=0x1`) → Full/Partial. 플래그 상수 정확.
- CET/IBT/SHSTK: `GNU_PROPERTY_X86_FEATURE_1_AND` 비트 1/2(`checksec.py:66-67, 212-214`). **실측 재현됨** — pyelftools 0.31+ 가 `pr_type` 를 문자열로, `pr_data` 를 int 로 매핑하므로(`elf/parser.py:246-249`) `gnu_properties={'GNU_PROPERTY_X86_FEATURE_1_AND':3}` 정상 산출. 초기 의심했던 silent false-negative 는 **재현되지 않음 → 결함 아님**.

**결함(경미) A-1a — legacy `nx` bool 과 상세 state 불일치.** PT_GNU_STACK 세그먼트가 없으면 `_analyze_nx`(`checksec.py:327-341`)는 `(False, None, state="unknown")` 를 반환한다. 즉 요약 필드 `checksec.nx = False`(NX 없음처럼 표시) 이지만 상세 verification 은 `unknown`. 요약값만 읽는 소비자는 "NX 미적용"으로 오인한다. 근거: `checksec.py:328`(nx=False 반환) vs `checksec.py:91`(verification unknown). 실무 영향은 낮음(현대 바이너리는 대부분 PT_GNU_STACK 보유).

**UNVERIFIED A-1b.** `_has_bind_now`(`checksec.py:540`)의 `any(symbol.name == "__relro_full")` 분기는 실재하지 않는 심볼명이다. 죽은 코드로 보이나 오판을 만들지는 않음(다른 조건으로 이미 판정).

## A-2. 심볼/문자열/스트립 처리 — 정확.

- `symbols_stripped = len(image.symbols) == 0`(`checksec.py:248`). `image.symbols` 는 `.symtab` 만(`.dynsym` 제외, `elf/parser.py:252-253`). "stripped" 정의 정확.
- FORTIFY/Canary 심볼 스캔은 `symbols + dynamic_symbols` 합집합(`checksec.py:72`) → 스트립돼도 `.dynsym` 의 `__printf_chk`/`__stack_chk_fail` 는 탐지. 정확.
- 스트립 바이너리에서 정적 심볼 기반 win-function 탐색은 빈 목록 반환 → 이후 CFG/xref 로 폴백(문서화됨). 빈 결과를 "없음"으로 오판하지 않도록 `inferred` 라벨 유지.

## A-3. GOT/PLT·재배치 — 정확.

`analyze_got_plt`(`got_plt.py:71`)와 재배치 파싱(`elf/parser.py:299-337`)은 `RelocationSection` 을 순회하고 `r_info_sym`/`r_info_type`/`r_addend`(RELA 만) 를 읽는다. GOT 여부는 `.got`/`.got.plt` 주소 범위로 판정(`elf/parser.py:294-298, 317`). purpose(plt/got/dynamic) 분류 근거 명확. **UNVERIFIED**: 대규모 실 libc 의 GOT 타깃을 `objdump -R` 와 전수 대조하지는 않음.

## A-4. ROP 가젯 검색 — ret/syscall 은 완전·정확, **jmp/call(JOP/COP)은 100% 누락**. (핵심 결함)

**실측 (static 바이너리, ROPgadget 5.x 대조):**
- `pop rdi ; ret`: ROPgadget `--all` **179개**, 도구 **179개**, 주소 완전 일치. 표본 주소(0x401dff/0x402547/0x402759/0x40421e) 모두 실제 바이트 `5f c3` 로 검증. → **ret 가젯 주소 계산은 바이트 정확.**
- 도구 종단자 분포: `{ret:28067, syscall:1270, int:2, ...}` — **jmp/call 0개.** ROPgadget 은 `call rax`, `call rbp`, `jmp reg` 등 다수 반환.

**결함 A-4a (MEDIUM) — JOP/COP 가젯 구조적 누락.** `_terminal_ranges`(`gadgets.py:480-489`)는 `0xC3`(ret), `0xC2`(ret imm16), `0x0F 05`(syscall), `0xCD 80`(int 0x80) 4종 바이트만 종단으로 yield 한다. `_is_terminal`(`gadgets.py:694-701`)도 RET-group/syscall/int0x80 만 허용, JMP/CALL group 불허. 따라서 `jmp rax`/`call rax`/`jmp [reg]` 로 끝나는 가젯은 **스캔 대상에서 구조적으로 배제**된다. CET(IBT) 우회나 ret 가젯 고갈 문제에서 필요한 JOP 체인을 이 도구로는 찾을 수 없다.

**결함 A-4b (LOW) — 가젯 최대 길이 5명령.** `max_depth` 기본 5(`gadgets.py:110`, `config.py`). ROPgadget 기본 depth 10. 6~10 명령 가젯 누락. 대부분의 실전 가젯은 ≤5 명령이라 영향 제한적.

**결함 A-4c (MEDIUM) — 2000개 상한 절단.** `max_gadgets=2000`(`config.py:33`)에서 스캔 중단. static 바이너리는 29,343개 중 하위주소 2000개만 수집 후 필터. 고주소의 특정 가젯을 검색하면 존재해도 빈 결과가 나올 수 있다. **단, 응답에 `status:"partially_completed"` 와 `scanned_gadgets` 를 노출**하므로 완전한 무음은 아님(`services.py:302, 308`). 소형 CTF 바이너리(<2000)는 무영향.

## A-5. 하드코딩된 오프셋/주소 — 범용성 훼손 값은 없음.

가젯/주소는 전부 `section.addr + start`(`gadgets.py:524`) 또는 심볼값에서 동적 산출. 특정 문제 전용 상수 없음. 단 strategy 스켈레톤의 `offset = 0` 은 하드코딩 placeholder(축 C 참조).

---

### 축 A UNVERIFIED
- A-U1: 실 libc GOT/PLT 를 `objdump -R` 전수 대조.
- A-U2: PE 정적 판정(축 F 별도) 및 raw 디스어셈블 base 처리.
- A-U3: A-4c 절단이 실제 사용자 검색에서 특정 가젯을 누락시키는 end-to-end 재현.
