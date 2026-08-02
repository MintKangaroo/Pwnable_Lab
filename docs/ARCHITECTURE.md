# PwnPilot 아키텍처

## 현재 정적 분석 구성

```text
Browser
  └── React + TypeScript + TanStack Query + URL Router
        │ /api/v1
        ▼
FastAPI Control Plane
  ├── Artifact intake service
  │   ├── bounded chunk reads
  │   ├── temporary file + SHA-256
  │   ├── ELF structure validation
  │   └── atomic content-addressed commit
  ├── BinaryRepository
  │   ├── BinaryRecord
  │   ├── AnalysisJobRecord
  │   └── AuditLogRecord
  ├── InlineAnalysisJobQueue (development only)
  └── Format-aware static analysis core
      ├── signature/archive policy
      ├── normalized ELF parser
      ├── bounded PE32/PE32+ parser
      ├── raw byte metadata + opt-in disassembly
      ├── interpreter / dynamic tags / relocations
      ├── evidence-based checksec / call-site heuristic
      ├── Capstone disassembly / function recovery / basic-block CFG / xref
      ├── bounded gadget scan
      └── strings / GOT·PLT / hex
        │
        ├── SQLite (local)
        └── PostgreSQL + Alembic (Compose)
```

API는 업로드 바이너리를 실행하지 않는다. 현재 queue의 `running`은
ELF/PE/raw 정적 분석만 의미한다.

## 의존 방향

- HTTP route는 service/job/repository를 호출한다.
- analyzer와 ELF domain은 FastAPI/SQLAlchemy를 import하지 않는다.
- repository는 DB record와 content-addressed file lifecycle을 담당한다.
- upload stream 처리는 artifact storage abstraction이 담당한다.
- 프런트엔드는 `/api/v1` typed client를 통해서만 backend data를 읽는다.

기존 `analyzer/`, `elf/`, `payload/`, `challenge/` 모듈은 검증된 정적 분석 코어로
재사용한다. 목표 구조로의 이동은 기능별 adapter와 회귀 테스트를 추가한 뒤 수행한다.

## Artifact intake

```text
UploadFile
  → read 1 MiB chunk
  → cumulative 32 MiB limit
  → write mode 0600 temporary file
  → incremental SHA-256
  → fsync
  → detect ELF/PE/raw and validate bounded structure/policy
  → atomic hard-link to storage/{sha256}
  → remove temporary name
  → insert/reuse DB metadata
```

- Content-Length와 MIME을 신뢰하지 않는다.
- 사용자 파일명은 저장 경로에 사용하지 않는다.
- path separator, NUL/control characters를 제거한 basename만 표시한다.
- 같은 SHA의 기존 파일은 덮어쓰지 않는다.
- parser/size 실패 시 임시 파일을 제거한다.

## API versioning

`/api/v1`이 기본 계약이다. 기존 `/api`는 Phase 1 호환 경로로 같은 router를 mount한다.
새 프런트엔드는 `/api/v1`만 사용한다.

주요 lifecycle:

```text
POST /binaries
  → not_started
POST /binaries/:id/analyze
  → queued → running → completed | failed
GET /binaries/:id/analysis
  → latest job + verified result provenance
DELETE /binaries/:id
  → jobs/record delete → stored bytes delete → audit retained
```

inline queue는 요청 안에서 완료되므로 API 응답 시점에는 보통 terminal state다.
후속 Redis worker는 같은 상태 계약을 비동기적으로 갱신한다.

## DB와 migration

- 개발 기본: SQLite, `PLAB_AUTO_CREATE_SCHEMA=true`
- migration/Compose: Alembic, `PLAB_AUTO_CREATE_SCHEMA=false`
- Compose 기본: PostgreSQL 17
- Redis는 후속 worker를 위한 service foundation이며 Phase 1 inline queue가 사용하지 않는다.

첫 migration은 새 DB schema를 만들고 migration 이전 `binaries/submissions` SQLite도
새 column/table로 업그레이드한다.

## 프런트엔드

현재 우선 화면:

- Dashboard: recent workspaces, analysis queue, 실제 symbol finding 후보
- Binary Workspace: URL tab, binary identity, analysis status, protection context
- Functions/CFG/Disassembly와 URL address 기반 근거 이동
- verified gadget search, chain layout, inferred state를 분리한 3-panel ROP Studio
- Phase 2 evidence/confidence protection matrix와 linking identity
- Payload Studio와 교육용 Challenges

정보 구조와 디자인 규약은
[`INFORMATION_ARCHITECTURE.md`](INFORMATION_ARCHITECTURE.md),
[`DESIGN_SYSTEM.md`](DESIGN_SYSTEM.md),
[`DASHBOARD_SPEC.md`](DASHBOARD_SPEC.md)에 정의한다.

## 신뢰 경계

### 현재

- Browser ↔ FastAPI: 신뢰하지 않는 입력
- FastAPI ↔ parser: 신뢰하지 않는 ELF/PE/raw bytes
- FastAPI ↔ storage: application-owned content-addressed directory
- FastAPI ↔ DB: parameterized SQLAlchemy operations

### 후속 동적 분석

```text
FastAPI Control Plane
  → queue/session manager
  → separate sandbox orchestrator
  → disposable non-networked worker
```

운영에서 backend에 Docker socket을 제공하지 않는다. sandbox worker는 read-only root,
non-root, cap drop, seccomp, no-new-privileges, PID/CPU/memory/file/time/output limits를
중첩 적용한다.

## 현재 한계

- 사용자 인증/tenant ownership/rate limit이 없다.
- inline queue는 프로세스 장애 복구/취소/heartbeat를 제공하지 않는다.
- 분석 parser는 아직 별도 static worker process로 격리되지 않았다.
- 동적 분석과 exploit 실행은 구현되지 않았다.
- ELF 위험 함수는 symbol/direct-call, PE는 import heuristic이며 취약점 확정이 아니다.
- PLT 주소는 ABI section layout에서 파생한 inferred 값이며 relocation target과 구분된다.
- CFG는 statically resolved direct edge만 포함하며 indirect jump table을 복원했다고 표시하지
  않는다.

따라서 현재 버전을 공개 인터넷 운영 서비스로 노출하지 않는다.
