# 축 D — 신뢰성 / 침묵의 오류(silent failure)

pwn 도구 최악 시나리오 = "정상처럼 보이는 오답". 이 관점으로 점검.

## D-1. (HIGH) `offset = 0` placeholder — 준(準)침묵 오답.

축 C-4 참조. `_infer_offset` 이 실패하면 strategy 스켈레톤은 `offset = 0  # TODO...` 를 낸다(`strategy.py:664-667`). `# TODO` 주석이 붙어 완전한 무음은 아니지만, **나머지 값(win/ret)은 정확히 채워져 "완성된 스크립트"처럼 보이는 맥락**에서 offset 0 은 초보자가 그대로 실행하기 쉬운 오답이다. 근거: `strategy.py:667`.

## D-2. (LOW, 표면화됨) 가젯 2000개 절단 → 특정 가젯 검색 시 존재해도 빈 결과.

축 A-4c 참조. `max_gadgets=2000`(`config.py:33`) 초과 시 하위주소 2000개만 스캔 후 필터. 고주소 가젯 검색은 빈 결과가 될 수 있다. **완화 확인**: 백엔드가 `status:"partially_completed"`, `scanned_gadgets`(`services.py:302,308`)를 내고, **프론트엔드도 실제 표시**한다 — `Analysis.jsx:1032` 가 status≠completed 시 warn 배지, `:1035` 가 "N scanned" 를 렌더. 따라서 완전한 무음은 아님. 다만 배지가 "이 특정 검색어의 가젯이 절단 구간에 있을 수 있음"을 명시하진 않아, 사용자가 배지를 놓치면 빈 결과를 "가젯 없음"으로 오해할 여지는 남는다.

## D-3. 파싱 실패 경로 — 대체로 정직(예외 전파). 무음 0-반환 없음.

- ELF 파싱 실패는 `ParseError` 로 전파(`elf/parser.py:173-174, 338-339`). 조용히 빈 ElfImage 를 만들지 않음.
- 좁은 `except ValueError`만 존재하며 합리적 처리:
  - `crash_log.py:223-224`: 레지스터 hex 파싱 실패 → 해당 항목 skip(continue). 타당.
  - `vuln_scan.py:278-279`: 직접 호출 대상 파싱 실패 → None. 타당.
  - `gadgets.py:736-737`: 사용자 immediate 파싱 실패 → None. 타당.
  - `decompile.py:103-105`: 의사-C immediate 파싱 실패 → 0. 의사-C 는 이미 비권위(rule-based, 실제 디컴파일 아님)로 라벨됨. 영향 낮음.
- **광범위 `except Exception: return []/0/None` 패턴 없음.** 분석기가 오류를 삼켜 빈 결과를 정상처럼 반환하는 지점은 발견되지 않음.

## D-4. 아키텍처/비트 자동 감지 실패 시 폴백.

- 비 x86 ELF: 파서는 `e_machine` 을 보존(`elf/parser.py:179`)하지만 디스어셈블/가젯/vuln/CFG 는 `machine not in {EM_386,EM_X86_64}` 로 **명시적 거부(예외)**(`disasm.py:38`, `gadgets.py:99`, `vuln_scan.py:201`, `control_flow.py:32`). ARM/MIPS 를 x86 로 오해석해 쓰레기 값을 내지 않음 → **양호(무음 오답 없음)**.
- 32/64 분기는 `image.bits`(`elf/parser.py:177`, `elfclass` 기반). ELF 헤더 e_ident[EI_CLASS] 에서 직접 오므로 오판 여지 낮음.
- 크래시 로그 아키텍처 추론(`crash_log.py:229-234`)은 레지스터명 휴리스틱. 레지스터가 전혀 없으면 `("unknown", None)` → 오프셋 매칭이 `unknown` 반환. 무음 오답 아님.

## D-5. 표시값 vs 계산값 불일치.

- checksec 요약 `nx` bool vs 상세 `state` 불일치(축 A-1a, `checksec.py:328` vs `:91`) — PT_GNU_STACK 부재 시 요약은 `nx=False`, 상세는 `unknown`. 두 값을 서로 다른 UI 위치가 읽으면 어긋난다.
- 캐싱: 분석 결과 저장/재분석 경로(`POST /crashes/{id}/analyze`)는 저장 원본을 현재 analyzer 로 재실행 → 스테일 캐시로 인한 불일치 위험 낮음. **UNVERIFIED**(DB 캐시 무효화 정책 미검토).

## D-6. 인코딩 손상(표시 데이터 무결성).

`strategy.py:624` 문자열에 `静的`(중국어 글리프) — 정상은 "정적". 사용자에게 노출되는 설명 텍스트의 문자 깨짐. 계산엔 무영향이나 신뢰도 신호. 근거: `strategy.py:624`.

---

### 축 D UNVERIFIED
- D-U1: 분석 결과 DB 캐시 무효화 정책(재분석 시 스테일 표시 가능성).
