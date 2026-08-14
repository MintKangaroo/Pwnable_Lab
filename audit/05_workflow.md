# 축 E — 워크플로 적합성 (CTF 실전 관점)

## E-1. 문제 하나를 푸는 실제 비용 — 현재는 pwntools 직접 작성보다 느리거나 대등, 빠르지 않다.

이유: 이 도구가 절약해줘야 할 **가장 비싼 단계(오프셋 확정)를 자동화하지 못한다**(축 C-4). 표준 흐름:
1. 업로드 → 자동 분석(checksec/심볼/가젯/vuln) — 여기까진 빠르고 정확.
2. strategy 탭에서 경로 추천 + 스켈레톤 — win/ret 는 채워지나 `offset=0`.
3. 사용자는 결국 로컬에서 `cyclic`/`cyclic_find` 로 오프셋을 직접 확정해야 함 → pwntools 를 직접 쓰는 것과 동일한 수작업.

즉 정적 정보 조회(checksec/gadgets)는 GUI 로 빠르지만, **익스 완성의 임계 경로에서 도구가 빠지므로** 순수 시간 이득은 크지 않다. 소형 ret2win 에서 pwndbg `cyclic` 3줄이면 끝나는 오프셋을 이 도구는 못 준다.

## E-2. 원격 서버(로컬 libc ≠ 원격 libc) 처리 — 없음.

libc-database/버전 매칭/leak 기반 base 산출 부재(축 C-1). 원격 전용 문제에서 이 도구가 제공하는 것은 정적 심볼/가젯뿐이며, 원격 libc 를 특정하거나 원격 leak 을 base 로 환산하는 보조가 없다. `remote('HOST',PORT)` 골격만 주석으로 제공.

## E-3. 실패 시도 기록/여러 오프셋 후보 관리 — 없음.

여러 오프셋 후보를 비교·저장하거나 실패한 익스 시도를 히스토리로 남기는 기능은 코드/문서에 없다(`docs/USER_FLOWS.md:47-48` 이 job history/progress 미구현 명시). 크래시 아티팩트는 개별 저장되나 "시도 비교" UX 는 아님.

## E-4. pwntools 스크립트 내보내기 — 있음(복붙 가능), 단 offset 결함.

strategy 는 `p['pwntools']` 로 완결형 스크립트 문자열을 제공(축 C-5). `context.binary`, `process/remote`, win/ret 주소까지 실값. **복붙 가능**은 충족하나 offset 한 줄이 placeholder 라 그대로는 안 터진다(축 C-4). payload 스튜디오의 `cyclic`/`pack`/`overflow` 는 독립적으로 정확.

## E-5. 실전 강점이 실재하는가.

- **강점**: 포맷 무관(ELF/PE/raw) 정적 개요, 근거·verification 라벨이 붙은 checksec/gadget/vuln 뷰, 학습용 챌린지 생성. 초심자 교육·정적 정찰용으로는 pwndbg 보다 진입장벽 낮음.
- **약점**: 익스를 실제로 완성시키는 동적 값(offset/leak/libc)을 주지 못함 → 중급 이상에겐 pwntools+pwndbg 대비 순이득 제한적.

---

### 축 E UNVERIFIED
- E-U1: 실제 클릭/입력 수를 pwntools 워크플로와 정량 측정한 벤치마크(정성 평가만 수행).
