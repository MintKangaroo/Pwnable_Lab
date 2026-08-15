#!/usr/bin/env bash
# 일회용 샌드박스에서 바이너리 하나의 반환 주소 오프셋을 확정한다.
#
# 사용:
#   sandbox/run.sh <binary> [pattern_length]
#
# 바이너리 바이트는 stdin 으로 주입되므로 호스트 경로를 컨테이너에 마운트하지
# 않는다. 결과(OffsetConfirmation JSON)는 stdout 으로 나온다.
#
# 격리는 전적으로 아래 `docker run` 플래그가 강제한다:
#   --network none        네트워크 완전 차단
#   --read-only           루트FS read-only (+ 필요한 곳만 tmpfs)
#   --cap-drop ALL        모든 리눅스 캐퍼빌리티 제거
#   --security-opt no-new-privileges  권한 상승 차단
#   --pids-limit / --memory / --cpus  자원 상한(러너 rlimit 위 한 겹 더)
#   --rm                  실행 후 컨테이너 폐기(일회용)
# gVisor 를 쓰려면 RUNTIME=runsc 로 실행: 커널 시스템콜 경계까지 격리된다.
set -euo pipefail

IMAGE="${SANDBOX_IMAGE:-pwnpilot-sandbox}"
RUNTIME="${RUNTIME:-}"    # 예: runsc (gVisor)
MEM="${SANDBOX_MEM:-768m}"
CPUS="${SANDBOX_CPUS:-1}"
PIDS="${SANDBOX_PIDS:-128}"

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <binary> [pattern_length]" >&2
    exit 64
fi
binary="$1"
pattern_length="${2:-}"

if [ ! -f "$binary" ]; then
    echo "no such file: $binary" >&2
    exit 66
fi

runtime_args=()
[ -n "$RUNTIME" ] && runtime_args+=(--runtime "$RUNTIME")

cli_args=(--stdin)
[ -n "$pattern_length" ] && cli_args+=(--pattern-length "$pattern_length")

# /tmp 은 실행 대상 임시파일을 담으므로 exec 를 허용해야 한다(noexec 금지).
# /run 은 마커 전용이라 noexec,nosuid 로 잠근다.
exec docker run --rm -i \
    "${runtime_args[@]}" \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,exec,nosuid,size=64m,mode=1777 \
    --tmpfs /run:rw,noexec,nosuid,size=1m,mode=1777 \
    --cap-drop ALL \
    --cap-add SYS_PTRACE \
    --security-opt no-new-privileges \
    --pids-limit "$PIDS" \
    --memory "$MEM" \
    --memory-swap "$MEM" \
    --cpus "$CPUS" \
    "$IMAGE" "${cli_args[@]}" < "$binary"
