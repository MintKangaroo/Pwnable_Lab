# PwnPilot API

기본 prefix는 `/api/v1`이다. 기존 `/api`는 호환 경로이며 신규 클라이언트는 사용하지 않는다.
`binary_id`는 현재 SHA-256과 동일하다. 업로드 응답과 binary 목록은
`format` (`ELF`, `PE`, `RAW`)을 포함한다.

## Artifact lifecycle

```text
POST /binaries
  → ELF/PE structure validation or raw-binary policy
  → atomic SHA-256 storage
  → not_started

POST /binaries/{binary_id}/analyze
  → queued → running → completed | failed
```

업로드 파일은 API 호스트에서 실행되지 않는다. MIME과 파일명은 포맷 판정에
사용하지 않는다.

## Format-aware endpoints

| Method | Path | 결과 |
|---|---|---|
| `GET` | `/binaries/{id}/info` | ELF/PE/raw 공통 metadata |
| `GET` | `/binaries/{id}/elf` | ELF 전용 metadata; 다른 포맷은 400 |
| `GET` | `/binaries/{id}/pe` | PE32/PE32+ 전용 metadata; 다른 포맷은 400 |
| `GET` | `/binaries/{id}/entropy` | global/region Shannon entropy |
| `GET` | `/binaries/{id}/disassembly` | ELF/PE x86 또는 opt-in raw x86 디스어셈블리 |

Raw 디스어셈블리는 `architecture=x86|x86_64`를 반드시 전달해야 하며,
`base_address`는 사용자가 알고 있는 매핑 주소를 전달한다. 두 값은 서버가 추측하지
않는다.

```text
GET /api/v1/binaries/{id}/disassembly?architecture=x86_64&base_address=4194304
```

## Static analysis endpoints

| Method | Path | 결과 |
|---|---|---|
| `GET` | `/binaries/{id}/elf` | identity, interpreter, libraries, sections, segments, symbols |
| `GET` | `/binaries/{id}/checksec` | legacy summary와 detailed protection objects |
| `GET` | `/binaries/{id}/symbols` | `kind`, `offset`, `limit` 기반 symbol page |
| `GET` | `/binaries/{id}/imports` | undefined dynamic symbol page |
| `GET` | `/binaries/{id}/exports` | defined global/weak dynamic symbol page |
| `GET` | `/binaries/{id}/functions` | verified/inferred function index; `q`, `offset`, `limit` |
| `GET` | `/binaries/{id}/functions/{address}` | selected function boundary, evidence, instructions |
| `GET` | `/binaries/{id}/functions/{address}/cfg` | basic blocks, internal direct edges, call targets |
| `GET` | `/binaries/{id}/xrefs` | `address`, `direction`, `kind`, pagination 기반 xref |
| `GET` | `/binaries/{id}/relocations` | normalized relocation page |
| `GET` | `/binaries/{id}/libraries` | linking mode, interpreter, DT_NEEDED, libc, search paths |
| `GET` | `/binaries/{id}/got` | relocation으로 검증된 GOT target |
| `GET` | `/binaries/{id}/plt` | PLT layout에서 파생한 stub candidate |
| `GET` | `/binaries/{id}/vulns` | 위험 API와 direct-call 후보 |

PE에서 `imports`, `exports`, `relocations`, `libraries`는 PE 테이블을
정규화해 반환한다. GOT/PLT와 ROP gadget 스캔은 현재 ELF 전용이며 PE/raw
요청은 지원하지 않는 기능으로 명시적으로 거부된다.

`functions`는 ELF symbol/entry 또는 PE export/entry에서 확인한 주소와 executable
direct-call target에서 추론한 주소를 합친다. raw binary에는 loader map과 함수 경계가
없으므로 function/CFG/xref 요청을 400으로 거부한다. `{address}`와 xref `address`는
`0x401000` 또는 10진수 형식을 지원한다.

`xrefs`의 `direction`은 `to|from`, `kind`는
`all|call|jump|conditional_jump`이다. 현재 direct immediate와 x86 RIP-relative
memory operand만 정적으로 해석한다.

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

malformed PE는 422, 일반 텍스트와 ZIP/TAR/gzip/7-Zip/RAR 등 archive는 415로
거부한다.
