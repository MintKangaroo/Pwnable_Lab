# PHASE 3 — 통합 리포트

대상: 저장소 전체. 방법: 실제 gcc 컴파일 바이너리 + static 바이너리로 도구 출력을 checksec / ROPgadget 5.x / pwntools cyclic / objdump 와 실측 대조. 확인 못 한 것은 UNVERIFIED.

한 줄 결론: **정적 정찰(checksec/심볼/가젯/재배치)과 오프라인 계산(cyclic/pack)은 표준 도구와 실측 일치할 만큼 정확하다. 그러나 익스를 완성시키는 임계 값(오프셋 자동 산출)이 표준 gcc 바이너리에서 무음에 가깝게 실패하며(`offset=0`), libc/one_gadget/동적 검증은 아예 없다. 즉 "정확한 값"을 파는 도구인데 가장 중요한 값 한 개를 못 준다.**

---

## 1. 오답 유발 결함 (믿고 값을 넣으면 익스가 안 터지는 케이스)

### [F-CRIT-1] strategy 오프셋 미산출 → `offset = 0` (HIGH). CONFIRMED.
- **근거**: `strategy.py:248-258`. `arguments['rdi']='rax'`(간접 레지스터)일 때 `buffer_expr` 가 truthy 라 `else` 분기로 가서 `'rax'` 에 `_RBP_DISP`(`strategy.py:62`)를 돌려 실패 → `continue`. 동작 가능한 surrounding_disassembly 폴백에 도달 못 함.
- **실측**: `gets(buf[64])` ret2win 바이너리(-O0/-O2 모두)에서 정답 오프셋 72(=0x40+8)를 못 내고 스켈레톤에 `offset = 0  # TODO`(`strategy.py:667`). win 주소·ret 가젯은 정확히 채워져 "완성 스크립트"처럼 보임.
- **경계**: 인자가 `[rbp-0x40]` 메모리식으로 직접 담기면 72 정확 산출, 간접형이면 실패(축 C-6 실측표). gcc `-O0` 기본이 간접형.
- **재현**: vuln 업로드 → ret2win 스켈레톤 복붙 → 실행 → 반환주소 못 덮음 → 실패.

### [F-CRIT-2] JOP/COP 가젯 100% 누락 (MEDIUM). CONFIRMED.
- **근거**: `_terminal_ranges`(`gadgets.py:480-489`)가 ret/ret-imm/syscall/int0x80 4종 바이트만 종단으로 취급. `_is_terminal`(`:694-701`) JMP/CALL 불허.
- **실측**: 도구 종단 분포 `{ret,syscall,int}` — jmp/call 0개. ROPgadget 은 `call rax` 등 반환.
- **오답 케이스**: ret 가젯이 부족하거나 IBT 우회로 `jmp/call reg` 가젯이 필요한 문제에서 "가젯 없음"으로 오판.

### [F-CRIT-3] 가젯 2000개 절단 (LOW, 표면화됨).
- **근거**: `config.py:33` `max_gadgets=2000`. 대형/static 바이너리는 고주소 가젯 누락.
- **완화 확인**: 백엔드 `status:"partially_completed"`(`services.py:302`) + 프론트 warn 배지·"N scanned"(`Analysis.jsx:1032,1035`). 완전 무음 아님. 소형 CTF 무영향.

### 오답 아님으로 확인된 것 (초기 의심 → 실측 반증)
- checksec NX/PIE/RELRO/Canary/CET/IBT/SHSTK: 컴파일 바이너리 5종 실측 **전부 정답 일치**.
- CET GNU-property 파싱 silent false-negative 가설: **재현 안 됨**(pyelftools 0.31+ 정상 매핑).
- cyclic/cyclic_find: pwntools 와 **바이트 일치**, 32/64 오프셋 정확.
- ret/syscall 가젯 주소: ROPgadget `--all` 과 **179개 완전 일치, 바이트 검증**.
- 경로 조작·바이너리 실행: **차단/부재**(축 F).

---

## 2. 기존 도구(pwntools/pwndbg) 대비 갭 — 솔직한 평가

- **이점이 실재하는 부분**: 포맷 무관 정적 개요, verification/evidence 라벨이 붙은 checksec·gadget·vuln 뷰, 학습용 챌린지 생성. **초심자 정적 정찰·교육**엔 pwndbg 보다 진입장벽이 낮고, 값 자체는 정확.
- **이점이 없는 부분**: 익스 완성의 임계 경로(오프셋 확정·libc 특정·leak→base·one_gadget). 이 영역에서 도구는 pwndbg `cyclic 3줄` / pwntools `ELF().symbols` 대비 **순이득이 없거나 음(-)** 이다. F-CRIT-1 때문에 오프셋조차 결국 손으로 확정해야 한다.
- **결론**: 현재 릴리스는 "정적 분석 대시보드 + 학습 도구"로서는 가치가 있으나, "익스 보조 도구"로서 pwntools/pwndbg 를 대체·가속하지 못한다. 마케팅상 "정확한 값" 을 표방한다면 F-CRIT-1 수정이 전제.

---

## 3. 우선순위 매트릭스 (정확성 영향 × 수정 비용)

```
              수정 비용 낮음                 수정 비용 높음
정확성    ┌────────────────────────┬────────────────────────┐
영향 큼   │ [F-CRIT-1] offset=0     │ libc-database/one_gadget│
          │  (else 분기 폴백 수정)   │  (신규 서브시스템)       │
          │ [D-6] 인코딩 静的 수정   │ leak→base 반자동화       │
          ├────────────────────────┼────────────────────────┤
정확성    │ [A-1a] nx bool/state    │ [F-CRIT-2] JOP/COP 가젯  │
영향 작음 │  불일치 정합            │  (종단 스캐너 확장)      │
          │ [A-4b] max_depth 상향    │ [F-U1] PE↔pefile 대조    │
          └────────────────────────┴────────────────────────┘
```
- **즉시(고영향·저비용)**: F-CRIT-1. `_infer_offset` 의 `else` 분기에서 `_RBP_DISP` 매칭 실패 시 surrounding_disassembly 폴백으로 넘어가게 조건 수정. 산식 `disp+word` 자체는 정확.
- **다음**: F-CRIT-2(가젯 종단에 `jmp/call reg` 추가), 회귀 하네스(4번).

---

## 4. 검증 하네스 제안 (정답 아는 CTF 바이너리 N개 자동 대조)

목표: 합성 `ElfBuilder` 픽스처의 사각지대(실컴파일러 관용구)를 없애고 값 정확성을 회귀 고정.

1. **골든 코퍼스 생성**: `tests/corpus/` 에 소스+빌드 스크립트. 최소 세트:
   - ret2win: `gets`/`read`/`fgets` × `-O0/-O2` × `-no-pie/-pie` (오프셋 정답을 빌드시 `lea` 변위에서 산출해 `expected.json` 에 고정).
   - ret2libc: dynamic + `system`/`/bin/sh` 유무.
   - 가젯: 알려진 `pop rdi;ret`, `jmp rax`, `syscall;ret` 주소.
2. **오라클 대조**: 같은 바이너리를 ROPgadget(`--all`)·pwntools(`cyclic`/`ELF`)·`readelf`/`checksec.sh` 로 돌려 **참값을 자동 생성**하고 도구 출력과 assert. (본 감사에서 ROPgadget/pwntools 설치가 이 방식으로 즉시 가능함을 확인.)
3. **핵심 단언**: `analyze_strategy(binary).inferred_offset == expected_offset`(현재 완전 부재), `gadgets` 종단 집합에 jmp/call 포함, checksec 각 필드 == checksec.sh.
4. **비 x86 거부 단언**: ARM/MIPS ELF 업로드가 명시적 400/예외인지(무음 오답 방지).
5. CI 에서 코퍼스 빌드는 `gcc` 필요 → 빌드 캐시 또는 체크인된 바이너리 + SHA 고정.

---

## 5. UNVERIFIED 목록

- A-U1: 실 libc GOT/PLT ↔ `objdump -R` 전수 대조.
- A-U3 / D-2: 절단이 실제 사용자 검색에서 특정 가젯을 누락시키는 end-to-end 재현.
- B-U1/B-U2: 실 x86-64·x86 코어 파일로 `_parse_prstatus` 레지스터값 ↔ gdb 대조.
- C-U1: `strcpy`/`sprintf`/`read`/`scanf` 각 심볼 실 바이너리 개별 실측(메커니즘은 C-6 로 확정, 심볼별 재현은 미수행).
- D-U1: 분석 결과 DB 캐시 무효화 정책(재분석 스테일 표시).
- F-U1: PE 파서 ↔ pefile 대조.
- F-U2: DB 계층 raw SQL 유무(SQLAlchemy ORM 이라 낮은 위험).

---

## 부록 — 실측 환경
- x86_64 / Python 3.10.12 / pyelftools 0.31+ / capstone 5 / ROPgadget·pwntools 감사용 임시 설치(도구 런타임 의존 아님).
- 테스트 바이너리는 세션 스크래치패드에서 gcc 로 생성(저장소 미변경). **본 감사는 코드/설정을 일절 수정하지 않았다.**
