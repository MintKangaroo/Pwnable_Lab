# 축 F — 코드/보안 건전성

## F-1. 분석 대상 바이너리 실행 — 없음. (양호)

`backend/pwnable_lab/` 전체에 `subprocess`/`os.system`/`os.popen`/`eval(`/`exec(`/`Popen`/`check_output` **0건**(grep 확인). 업로드된 신뢰 불가 바이너리를 실행하거나 셸에 넘기는 지점이 없다. "분석기가 감염되는 아이러니" 시나리오는 **현재 코드에 존재하지 않음**. 디스어셈블은 capstone(비실행 디코드), 파싱은 pyelftools/자체 파서로만 수행.

> 단, Phase 6A(`docs/AUTO_EXPLOIT_SANDBOX.md`)가 구현되면 이 원칙이 바뀐다. 그 문서는 network-disabled 일회용 컨테이너·리소스 상한·backend 에 docker socket 미마운트를 안전 경계로 명시(`:18-24`). 현재는 미구현이라 리스크 없음.

## F-2. 업로드 파일 처리 — 견고. (양호)

- 스트리밍 청크 업로드 + 크기 상한 강제(`storage.py:44-58`, `max_bytes` 초과 시 `PayloadTooLargeError`). 메모리 폭발 방지.
- MIME/파일명 불신, **구조 기반 포맷 검증**(`binaries.py:57-60` 주석 및 `service.inspect`). 확장자 위조로 우회 불가.
- 임시파일 → 검증 → `os.link` 원자적 커밋, 실패 시 unlink(`storage.py:56-58, commit`). content-addressed(SHA-256).

## F-3. 경로 조작(path traversal) — 차단됨. (양호)

`BinaryRepository._path`(`repository.py:45-49`)가 파일 경로 조립 전 **`len(sha256)==64` 및 `[0-9a-f]` 전수 검증**, 위반 시 `NotFoundError`. `load_bytes`(`:117-118`)가 이 `_path` 를 사용하므로 `../../etc/passwd` 류 URL 은 파일 접근 전 거부된다. **실측 코드경로상 traversal 불가.**
- 업로드 파일명도 unquote → 경로구분자/널/비출력 문자 제거 → 255 절단(`repository.py:73-78`). 저장 파일명은 SHA 라 파일명은 메타데이터로만 사용.

## F-4. 핵심 계산 로직 테스트 커버리지 — **오프셋 값 단언 부재. (결함)**

- `tests/test_strategy.py` 에 **offset/inferred_offset 을 특정 값으로 단언하는 테스트 0건**(grep: `offset`/`72`/`lea`/`rbp` 히트 없음). 축 C-4 의 `offset=0` 버그가 테스트를 통과한 직접 원인.
- 픽스처가 **실제 gcc 산출물이 아니라 합성 `ElfBuilder`**(`tests/fixtures.py:8, 12-29`). 실컴파일러 관용구(`lea reg,[rbp-N]; mov rdi,reg`)를 재현하지 않으므로 `_infer_offset` 의 간접-레지스터 실패 경로가 테스트에서 노출되지 않는다.
- 커버리지 게이트 `fail_under=90`(`pyproject.toml`)은 **라인 커버리지**일 뿐 값 정확성을 보장하지 않는다. `_infer_offset` 은 실행되긴 하나(라인 커버) 결과값을 검증하는 단언이 없다.

## F-5. 알려진 정답 CTF 회귀 테스트 — 없음. (결함)

정답 오프셋/가젯 주소가 알려진 실 CTF 바이너리로 도구 출력을 대조하는 골든 테스트가 없다. 모든 ELF 테스트가 `ElfBuilder` 합성 입력 기반. → 이 감사가 gcc 바이너리로 처음으로 end-to-end 대조를 수행했고 즉시 축 C-4 버그가 드러났다.

## F-6. 의존성 표면.

capstone/pyelftools 만 런타임 의존(`pyproject.toml:13-23`). pwntools/angr/ROPgadget 미포함 → 공급망 표면 작음. 자체 재구현이 많아(가젯/checksec/PE) **정확성 책임이 전적으로 이 코드에 있다** — F-4/F-5 의 값 단언 테스트 부재가 특히 위험한 이유.

---

### 축 F UNVERIFIED
- F-U1: PE 파서(`pe/parser.py`)의 imports/exports/relocations 를 pefile 과 대조.
- F-U2: DB 계층 SQL 인젝션(SQLAlchemy ORM 사용으로 낮은 위험이나 raw query 유무 미확인).
