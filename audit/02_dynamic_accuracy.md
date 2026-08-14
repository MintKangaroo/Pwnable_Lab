# 축 B — 동적 분석 정확성

**전제 정정: 이 도구에는 동적 분석(live 디버깅/실행)이 없다.** `backend/pwnable_lab/` 전체에 `subprocess`/`os.system`/`ptrace`/`gdb` 호출 0건. 여기서 "동적"으로 분류 가능한 것은 **사용자가 업로드한 크래시 로그/ELF 코어의 사후(post-mortem) 파싱**뿐이다(`crash_log.py`, `core_dump.py`). ptrace 로 실제 프로세스 상태를 읽는 코드는 존재하지 않는다.

---

## B-1. 오프셋 산출(De Bruijn) — pwntools 와 바이트 단위 일치. 정확.

`cyclic`/`cyclic_find`(`payload/cyclic.py:35, 47`) 실측:
- `cyclic(20)` = `b'aaaabaaacaaadaaaeaaa'` — pwntools 와 일치.
- `pip install pwntools` 후 대조: `pwn.cyclic(30) == tool.cyclic(30)` → **True**.
- `cyclic_find(needle@offset64)` → 64, `cyclic_find(int)` → 64 (리틀엔디언 `struct.pack("<I")`, `cyclic.py:59-60`). 정확.
- 64비트 값 하위 4바이트 매칭: 오프셋 100 지점 8바이트를 `& 0xffffffff` 후 `cyclic_find` → **100 정확**.

알고리즘: `de_bruijn`(`cyclic.py:15-32`)은 표준 B(k,n) 재귀. `n=4` 기본은 pwntools 기본과 동일. **64비트에서도 n=4 가 표준이므로 인벤토리에서 우려한 "n=8 미지원" 은 실제 결함이 아님** — 4바이트 subseq 는 26^4=456,976 바이트 내 유일.

`cyclic_find`의 CPU 방어: n=8 요청 시 `min(26^8, max_length=65536)` 로 제한(`cyclic.py:64-66`). 합리적.

## B-2. 크래시 IP 오프셋 매칭 — 근거 기반, 무음 오답 없음. 정확.

`_find_probable_cyclic`(`crash_log.py:402-446`):
- width = `4 if bits==32 else 8`(`crash_log.py:412`). 값은 `masked.to_bytes(width,"little")`(`crash_log.py:416-417`). 엔디안·워드크기 처리 정확.
- n=8 패턴 우선, 실패 시 n=4 패턴(`crash_log.py:413-414, 418-419`). n=4 로 생성된 입력(도구/pwntools 기본)도 n=4 폴백으로 정확히 매칭.
- IP-overwrite 결론은 `source in {rip,eip,pc}` 일 때만 확정(`crash_log.py:454-458`). 스택 슬롯의 우연한 매칭을 IP 덮어쓰기로 오판하지 않음. 근거 gating 양호.

**주의(경미) B-2a.** 사용자가 `n∈{5,6,7}` 같은 비표준 subseq 로 패턴을 만들면 매칭 패턴이 n=8/n=4 뿐이라 오프셋을 `status:"unknown"` 으로 놓친다. 이는 **틀린 값이 아니라 정직한 미검출**이므로 pwn 도구 최악 시나리오(무음 오답)에 해당하지 않음.

## B-3. 레지스터/코어 엔디안·비트 처리.

- 로그 레지스터 파싱 `_parse_registers`(`crash_log.py:216-226`): `int(hex,16)` 로 전체 폭 파싱 후 매칭 단계에서 width 마스킹. 정확.
- 아키텍처 추론 `_infer_architecture`(`crash_log.py:229-234`): `rip/rsp/r15` → 64비트, `eip/esp` → 32비트. 휴리스틱이나 합리적.
- 코어덤프: `_parse_prstatus`(`core_dump.py:420-446`)가 NT_PRSTATUS note 에서 레지스터를 뽑고 ip/sp/bp 를 bits 별 이름으로 선택(`core_dump.py:150-154`). **UNVERIFIED**: 실제 x86-64 코어 파일로 `rip` 값이 pwndbg/gdb 와 일치하는지 end-to-end 실행 대조는 하지 않음(코드상 구조는 타당).

## B-4. ASLR leak → base 계산.

**해당 기능 없음.** libc/PIE base 를 leak 값에서 역산하는 로직은 코드에 없다(grep: `base =`/`leak` 관련 계산 부재). strategy 스켈레톤은 "libc leak 후 one_gadget/system"을 **주석/단계 설명**으로만 안내하며 실제 base 산식을 제공하지 않는다(`strategy.py:624`). 부호/오프셋 오류를 논할 대상 자체가 없음 → 축 C 의 "기능 부재"로 분류.

---

### 축 B UNVERIFIED
- B-U1: 실 x86-64 코어 파일로 `_parse_prstatus` 레지스터값을 gdb 와 대조.
- B-U2: 32비트 코어/로그 경로.
