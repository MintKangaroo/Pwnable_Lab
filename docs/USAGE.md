# PwnPilot 사용 가이드

## Dashboard

Dashboard는 실제 API에서 다음을 표시한다.

- 최근 ELF/PE/raw artifact와 format/architecture/bit/size/SHA
- `Not analyzed`, `Queued`, `Running`, `Completed`, `Failed` 분석 상태
- 대기/실패 작업과 다음 액션
- 최근 artifact의 Critical/High 위험 symbol 후보

위험 symbol은 `Possible · static heuristic`으로 표시한다. import나 symbol 이름만으로
실제 취약점을 확정하지 않는다.

## 바이너리 업로드

좌측 `Upload binary` 또는 Dashboard action에서 ELF, PE/EXE, raw binary를 선택한다.

1. 브라우저가 파일을 `/api/v1/binaries`에 전송한다.
2. 서버가 1MiB 이하 청크로 읽으며 32MiB 누적 제한을 적용한다.
3. ELF/PE 구조 또는 raw-binary 정책을 검증한다.
4. SHA-256으로 중복을 제거해 저장한다.
5. UI가 format-aware 정적 분석 작업을 시작한다.
6. Binary Workspace로 이동한다.

업로드 파일은 control plane에서 실행되지 않는다.

## Binary Workspace

포맷별로 분석 가능한 탭만 표시한다.

- **Overview**: identity, protection matrix, 위험 symbol 후보, memory segment
- **Functions**: 함수 시작·경계의 verification, confidence, evidence
- **Disassembly**: entry부터 제한된 수의 Capstone instruction
- **CFG**: 함수별 basic block, predecessor/successor, direct edge, incoming xref
- **ROP Studio**: verified gadget 효과, semantic filter, chain layout, inferred state model
- **Symbols**: static/dynamic symbol 검색
- **Strings**: ASCII/UTF-16LE string
- **GOT / PLT**: 관련 section과 undefined dynamic imports
- **Hex View**: 512-byte page 기반 file view

PE는 Functions/CFG를 지원하지만 ROP Studio와 GOT/PLT 탭은 표시하지 않고
imports/exports를 Symbols에 표시한다. Raw는 함수 경계를 추측하지 않으므로 Overview,
Disassembly, Strings, Hex View만 표시한다.

Raw Disassembly에서는 architecture (`x86` 또는 `x86-64`)와 base address를
사용자가 직접 지정한다. 플랫폼은 이 값들을 추측하지 않는다.

탭과 선택 주소는 URL의 path와 `address` query에 반영되므로 새로고침, 뒤로 가기,
링크 공유가 가능하다. Functions의 `Open CFG`와 CFG block 주소를 이용해 같은 주소 근거를
유지한 채 화면 사이를 이동할 수 있다.

### ROP Studio

1. instruction substring 또는 제한된 safe regex로 gadget을 검색한다.
2. changed register, category, stack delta, bad byte, quality 조건을 적용한다.
3. `+ ADD`로 verified gadget을 chain에 넣고 literal/symbol 값을 배치한다.
4. drag-and-drop 또는 위/아래 버튼으로 stack layout을 정렬한다.
5. State Simulation에서 소비된 entry, RSP delta, register 값과 실패 이유를 확인한다.

`LAYOUT VALID`는 제한된 정적 모델 안에서 stack layout이 일관된다는 뜻이다. 바이너리를
실행하거나 exploit 성공을 검증했다는 의미가 아니며 결과는 `inferred`로 표시된다.
PIE gadget은 runtime base가 확인되기 전까지 image offset이다.

Context Header에는 파일명, architecture, bit, short SHA, 분석 상태, compact protection
요약이 표시된다. `Re-run static analysis`는 업로드 파일을 실행하지 않고 metadata
분석만 다시 수행한다.

## Payload Studio

### Cyclic Pattern

De Bruijn pattern을 만들고 crash register value 또는 관찰된 byte sequence에서 offset을
검색한다.

### Integer Pack

주소를 32/64-bit, little/big endian byte로 변환한다.

### Overflow Builder

```text
[fill × padding][packed return target][packed ROP values...]
```

정적 payload byte layout만 생성하며 target에 연결하거나 실행하지 않는다.

### Shellcode Catalog

교육용 x86/x86-64 syscall byte를 정적 참고용으로 표시한다. 플랫폼이 실행하지 않는다.

## Challenges

결정론적 최소 ELF artifact를 내려받아 같은 정적 도구로 분석한다. 정답은 client bundle에
포함하지 않고 server에서 상수 시간 비교한다. 이 artifact는 운영체제에서 실행하기 위한
바이너리가 아니라 parser/disassembly 학습 fixture다.

## API

OpenAPI:

- 기본: `http://localhost:8000/api/v1/docs`
- 기존 호환: `http://localhost:8000/api/docs`

예:

```bash
BINARY_ID=$(
  curl -s -F file=@./target http://localhost:8000/api/v1/binaries |
  jq -r .binary_id
)
curl -s -X POST \
  "http://localhost:8000/api/v1/binaries/$BINARY_ID/analyze" | jq
curl -s \
  "http://localhost:8000/api/v1/binaries/$BINARY_ID/checksec" | jq
```

## 오류 해결

| Error | 의미 | 확인 |
|---|---|---|
| `UnsupportedFormatError` | 지원 포맷/raw binary가 아님 | 텍스트/압축/아카이브인지 확인 |
| `PayloadTooLargeError` | 32MiB 기본 제한 초과 | 설정과 원본 크기 확인 |
| `ParseError` | 손상/절단 ELF 또는 PE 구조 | 원본과 header/table 범위 확인 |
| `NotFoundError` | artifact/job이 없음 | SHA/삭제 여부 확인 |
| `AnalysisError` | 분석 범위/지원 architecture 문제 | 요청 count/address와 arch 확인 |

한 analyzer panel이 실패해도 가능한 다른 artifact 정보는 유지하는 방향으로 확장한다.

## 안전 수칙

- 소유하거나 명시적인 권한을 받은 바이너리만 업로드한다.
- 현재는 인증과 사용자별 격리가 없으므로 공개 배포하지 않는다.
- 동적 실행이 필요한 경우 Phase 6 sandbox runner가 완성될 때까지 별도 허가된 로컬
  실습 환경을 사용한다.
- 생성한 payload를 임의 인터넷 host나 권한 없는 시스템에 사용하지 않는다.
