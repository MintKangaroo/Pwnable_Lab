# Ghidra 디컴파일 백엔드

기존 pseudo-C(`analyzer/decompile.py`)는 규칙 기반 경량 생성기다. 이 백엔드는 **진짜
디컴파일러(Ghidra headless)** 가 설치돼 있을 때 훨씬 정확한 C 를 제공한다. 설치가
없거나 비활성이면 API 는 `{"available": false}` 를 반환해 UI 가 pseudo-C 로 폴백한다.

> **성격**: Ghidra 는 바이너리를 **실행하지 않고** 정적 분석만 한다(자동 익스 샌드박스
> 러너와 다르다). 그래도 무겁고 느리므로(임포트+분석 수십 초) **기본 비활성·온디맨드**다.

## 엔드포인트

```
POST /api/binaries/{sha256}/decompile-ghidra
```

응답: `{"available", "succeeded", "backend": "ghidra", "program", "language",
"image_base", "function_count", "functions": [{"name","entry","signature","c"}, ...]}`.
비활성/미설치면 `{"available": false, "reason": "ghidra-disabled|ghidra-not-installed"}`,
실행 실패면 `{"available": true, "succeeded": false, "error": ...}`.

## 설정 (`PLAB_` 접두사)

| 환경변수 | 기본 | 설명 |
|---|---|---|
| `PLAB_GHIDRA_ENABLED` | `false` | 백엔드 활성화(마스터 스위치) |
| `PLAB_GHIDRA_HOME` | 자동 | ghidra 설치 경로(비면 `~/.local/ghidra_*` 자동 탐지) |
| `PLAB_JAVA_HOME` | 자동 | JDK 경로(비면 `JAVA_HOME`/`~/.local/jdk/jdk-*`/`PATH`의 java) |
| `PLAB_GHIDRA_TIMEOUT_SECONDS` | `180` | headless 실행 타임아웃 |
| `PLAB_GHIDRA_MAX_FUNCTIONS` | `200` | 디컴파일할 최대 함수 수 |

## 설치 (sudo/멀티리브 불필요 — 포터블)

Ghidra 12.x 는 **JDK 21+** 이 필요하다. 둘 다 tarball/zip 이라 root 없이 홈에 풀면 된다.

```bash
# JDK 21 (Temurin)
curl -L -o /tmp/jdk21.tar.gz \
  "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse"
mkdir -p ~/.local/jdk && tar -C ~/.local/jdk -xzf /tmp/jdk21.tar.gz

# Ghidra (NSA release)
curl -L -o /tmp/ghidra.zip \
  "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip"
unzip -q /tmp/ghidra.zip -d ~/.local/
```

> **함정 — 실행권한**: `unzip`(또는 Python `zipfile`)로 풀면 네이티브 디컴파일러
> 바이너리의 exec 비트가 사라질 수 있다. 그러면 headless 가
> `Cannot run program ".../decompile": Exec failed, error: 13 (Permission denied)` 로
> 실패한다. `find ~/.local/ghidra_*/ -path '*/os/*' -type f -exec chmod +x {} +`
> 로 복구한다.

활성화:

```bash
export PLAB_GHIDRA_ENABLED=1
# 자동 탐지가 안 되면 명시:
# export PLAB_GHIDRA_HOME=~/.local/ghidra_12.1.3_PUBLIC
# export PLAB_JAVA_HOME=~/.local/jdk/jdk-21.0.12.1+1
```

## 구현

- `analyzer/ghidra.py`: `locate_ghidra`(경로 자동 탐지) / `ghidra_available` /
  `decompile_with_ghidra`(임시 프로젝트에 임포트·분석 후 번들 스크립트로 JSON 덤프).
- `analyzer/ghidra_scripts/DecompileToJson.java`: headless post-script(Java — Ghidra 12
  는 `.py` 에 PyGhidra 를 요구하므로 Java 스크립트를 쓴다). `DecompInterface` 로 함수별
  C 를 뽑아 JSON 으로 쓴다. `DecompileOptions`+`setSimplificationStyle("decompile")` 설정
  필수(없으면 C 가 비어 나온다).
- 서비스 `AnalysisService.decompile_ghidra` / 라우트 `POST /binaries/{sha}/decompile-ghidra`.
- 테스트 `backend/tests/test_ghidra.py`(설치+컴파일러 있을 때만 실 디컴파일, 없으면 skip).
