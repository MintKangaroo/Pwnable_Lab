# 사용 가이드

## Binary Lab

ELF 파일을 좌측 업로드 영역에 놓으면 SHA-256으로 저장한 뒤 분석 화면이 열립니다.

- **Overview**: ELF 타입, 아키텍처, 진입점, 메모리 세그먼트와 checksec 결과
- **Disassembly**: 진입점부터 최대 500개 명령을 선형 디스어셈블
- **ROP Gadgets**: 실행 섹션의 `ret` 가젯 목록과 부분 문자열 검색
- **Symbols**: 정적·동적 심볼 통합 검색
- **Strings**: ASCII/UTF-16LE 문자열 추출과 최소 길이 필터
- **GOT / PLT**: 링크 섹션 권한과 외부 임포트
- **Hex View**: 512바이트 단위 원본 바이트 탐색

분석은 현재 ELF를 입력으로 받으며, 디스어셈블과 가젯 탐색은 x86/x86-64를 지원합니다.

## Payload Studio

### Cyclic Pattern

패턴 길이와 부분 수열 폭을 지정해 De Bruijn 패턴을 만듭니다. 크래시 후 레지스터 값
(`0x61616162`) 또는 관찰된 바이트(`baaa`)를 넣으면 첫 오프셋을 계산합니다.

### Integer Pack

주소를 32/64비트와 little/big endian에 맞춰 바이트로 변환합니다. 예를 들어
`0x401156`의 64비트 little-endian 결과는 `56 11 40 00 00 00 00 00`입니다.

### Overflow Builder

다음 레이아웃으로 페이로드를 만듭니다.

```text
[fill × padding][packed return target][packed ROP step 1][packed ROP step 2]...
```

결과는 전체 hex와 주소/ASCII를 함께 보는 hexdump로 제공합니다.

### Shellcode Catalog

x86/x86-64 syscall 학습용 바이트를 조회하고 복사합니다. 플랫폼은 이 바이트를 실행하지
않습니다.

## Challenges

문제 보드에서 미션을 고르고 ELF를 다운로드합니다. Binary Lab에 다시 업로드해 분석한 뒤
요구 형식에 맞는 값을 제출합니다.

| 문제 | 난이도 | 핵심 기술 |
|---|---|---|
| Ret2Win | Easy | 심볼과 고정 주소 |
| Stack Offset | Easy | 스택 프레임과 반환 주소 오프셋 |
| Checksec Audit | Easy | 비활성화된 완화 기법 |
| ROP Gadget | Medium | `pop rdi ; ret` 탐색 |
| Format String Leak | Medium | 문자열과 포맷 스트링 |
| ROP Chain Reconstruction | Hard | 가젯, 심볼, XOR 데이터 복원 |

힌트는 한 단계씩 공개됩니다. 정답 제출 전에는 API 응답과 프런트엔드 번들 어디에도 정답이나
풀이 설명이 포함되지 않습니다.

## API 문서

백엔드 실행 후 [http://localhost:8000/api/docs](http://localhost:8000/api/docs)에서
OpenAPI 문서를 볼 수 있습니다. 모든 애플리케이션 엔드포인트는 `/api` 아래에 있습니다.

## 안전 수칙

Pwnable Lab은 교육, CTF, 소유한 시스템 또는 명시적으로 허가받은 보안 테스트를 위한
도구입니다. 타인의 시스템에 허가 없이 페이로드를 사용하지 마세요.
