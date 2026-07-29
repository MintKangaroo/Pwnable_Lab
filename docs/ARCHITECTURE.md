# Pwnable Lab 아키텍처

## 설계 목표

Pwnable Lab은 바이너리 익스플로잇을 공부할 때 반복되는 세 가지 작업을 한곳에 모읍니다.

1. ELF의 구조와 완화 기법을 정적으로 확인한다.
2. 공격 표면과 ROP 재료를 찾아 페이로드를 조립한다.
3. 동일한 도구로 결정론적 실습 바이너리를 풀고 서버에서 채점한다.

업로드한 바이너리를 실행하는 기능은 의도적으로 없습니다. 파서가 받는 모든 바이트는
신뢰할 수 없는 입력이며, 업로드 크기와 모든 고비용 분석에 상한을 둡니다.

## 구성

```text
Browser / React
       │
       │ /api
       ▼
FastAPI routes ────── payload tools
       │              (cyclic, pack, overflow, shellcode catalog)
       │
       ├── AnalysisService
       │      ├── ELF parser (pyelftools → normalized dataclasses)
       │      ├── checksec / dangerous-symbol scan
       │      ├── Capstone disassembly / ROP gadget scan
       │      └── strings / GOT·PLT / hex view
       │
       ├── Challenge registry
       │      └── six seeded ELF generators + constant-time verifier
       │
       └── BinaryRepository
              ├── SQLite metadata and submission counters
              └── SHA-256-addressed binary storage
```

의존 방향은 HTTP 계층에서 도메인 코어 쪽으로만 흐릅니다. 분석기, ELF 빌더, 문제 생성기,
페이로드 모듈은 FastAPI나 SQLAlchemy를 import하지 않습니다.

## ELF 처리

`elf/parser.py`는 pyelftools 결과를 `ElfImage`, `SectionInfo`, `SymbolInfo`,
`SegmentInfo`로 정규화합니다. 이후 분석 모듈은 원본 라이브러리 객체 대신 이 값 타입만
사용합니다.

- checksec: 프로그램 헤더, 동적 태그, 심볼을 조합해 RELRO/Canary/NX/PIE 등을 판정
- gadget finder: 실행 섹션의 `ret` 바이트에서 역방향으로 디코딩해 유효한 명령 경계만 수집
- disassembler: `.text` 범위 안의 주소만 허용하며 x86/x86-64를 Capstone으로 디코딩
- dangerous-symbol scan: 정적/동적 심볼의 알려진 위험 함수를 심각도순으로 분류
- GOT/PLT: 링크 섹션과 정의되지 않은 동적 심볼을 정리

## 문제 생성

각 문제 생성기는 슬러그에서 파생한 고정 시드로 최소 ELF64 아티팩트를 만듭니다. 따라서
서버를 재시작하거나 여러 프로세스를 띄워도 아티팩트와 정답이 같습니다. 공개 응답에는
정답과 풀이가 직렬화되지 않으며, 정답 제출 뒤 서버에서 `hmac.compare_digest`로 비교합니다.

합성 ELF는 실제 실행을 목적으로 하지 않습니다. pyelftools와 Capstone이 해석할 수 있는
정적 학습 아티팩트입니다.

## 데이터와 신뢰 경계

- 파일은 원래 이름이 아니라 SHA-256 해시로 저장합니다.
- 업로드 스트림은 `max_upload_bytes + 1`까지만 읽어 전체 메모리 적재를 막습니다.
- 사용자 파일명은 경로 구성에 쓰지 않으며 메타데이터 저장 전에 basename으로 정리합니다.
- 디스어셈블 명령 수, 가젯 수/깊이, 문자열 수, hex 페이지, cyclic 길이에 각각 상한이 있습니다.
- 외부 명령 실행, 셸 호출, 업로드 파일 실행은 없습니다.

## 영속성

SQLite는 업로드 메타데이터와 문제 제출 통계만 보관합니다. 바이너리 바이트는 파일 시스템의
content-addressed storage에 저장합니다. 동일 파일 재업로드는 기존 레코드와 바이트를
재사용합니다.

## 배포

로컬 개발에서는 Vite가 `/api`를 FastAPI로 프록시합니다. Docker Compose에서는 Nginx가
React 정적 빌드와 `/api` 리버스 프록시를 담당하고, 백엔드는 비루트 사용자로 실행됩니다.
SQLite와 업로드 파일은 `pwnable-data` 볼륨에 유지됩니다.
