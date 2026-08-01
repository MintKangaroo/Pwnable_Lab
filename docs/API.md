# PwnPilot API

기본 prefix는 `/api/v1`이다. 기존 `/api`는 호환 경로이며 신규 클라이언트는 사용하지 않는다.
`binary_id`는 현재 SHA-256과 동일하다.

## Artifact lifecycle

```text
POST /binaries
  → ELF validation
  → atomic SHA-256 storage
  → not_started

POST /binaries/{binary_id}/analyze
  → queued → running → completed | failed
```

업로드 파일은 API 호스트에서 실행되지 않는다.

## Phase 2 ELF endpoints

| Method | Path | 결과 |
|---|---|---|
| `GET` | `/binaries/{id}/elf` | identity, interpreter, libraries, sections, segments, symbols |
| `GET` | `/binaries/{id}/checksec` | legacy summary와 detailed protection objects |
| `GET` | `/binaries/{id}/symbols` | `kind`, `offset`, `limit` 기반 symbol page |
| `GET` | `/binaries/{id}/imports` | undefined dynamic symbol page |
| `GET` | `/binaries/{id}/exports` | defined global/weak dynamic symbol page |
| `GET` | `/binaries/{id}/functions` | defined `STT_FUNC` symbol page |
| `GET` | `/binaries/{id}/relocations` | normalized relocation page |
| `GET` | `/binaries/{id}/libraries` | linking mode, interpreter, DT_NEEDED, libc, search paths |
| `GET` | `/binaries/{id}/got` | relocation으로 검증된 GOT target |
| `GET` | `/binaries/{id}/plt` | PLT layout에서 파생한 stub candidate |
| `GET` | `/binaries/{id}/vulns` | 위험 API와 direct-call 후보 |

`symbols`의 `kind`는 `all`, `static`, `dynamic`, `imports`, `exports`, `functions` 중 하나다.
`offset` 기본값은 0, `limit` 기본값은 200이며 최대 5000이다.

## Accuracy fields

주소 또는 판정에는 가능한 경우 다음 필드를 포함한다.

```json
{
  "verification": "inferred",
  "confidence": 0.92,
  "evidence": [
    "Address derived from .plt entry size 16 and relocation order"
  ]
}
```

`verification`은 `verified`, `inferred`, `unknown`을 사용한다. 취약점 후보 상태는
`possible`, `likely`, `confirmed`, `disproven`을 사용한다. 정적 위험 API 탐지는 기본적으로
`possible`이며 import나 direct call만으로 취약점을 확정하지 않는다.

## Errors

오류는 구조화된 `error`와 사용자용 `detail`을 반환한다. malformed ELF는 전체 서버를
중단시키지 않고 4xx 응답으로 격리된다. pagination 범위를 벗어난 page는 빈 `items`를
반환한다.
