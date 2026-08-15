#!/bin/sh
# 일회용 샌드박스 엔트리포인트.
#
# 1) 격리 마커를 생성한다. 이 마커는 "샌드박스 엔트리포인트를 통해 실행됐다"는
#    증거로, 게이트(pwnable_lab.sandbox.gate)가 실행 직전 존재를 요구한다.
#    실 격리(네트워크 차단/read-only/캡 드롭)는 `docker run` 플래그가 강제한다.
# 2) nsjail 이 있고 SANDBOX_USE_NSJAIL=1 이면 한 겹 더 감싼다(선택).
# 3) one-shot CLI 워커를 exec 한다. 넘어온 인자는 그대로 CLI 로 전달된다.
set -eu

: "${PLAB_SANDBOX_ISOLATION_MARKER:=/run/pwnpilot-sandbox}"
: "${TMPDIR:=/tmp}"
export PLAB_SANDBOX_EXECUTION_ENABLED=1
export PLAB_SANDBOX_ISOLATION_MARKER TMPDIR

marker_dir=$(dirname "$PLAB_SANDBOX_ISOLATION_MARKER")
mkdir -p "$marker_dir" 2>/dev/null || true
: > "$PLAB_SANDBOX_ISOLATION_MARKER"

if [ "${SANDBOX_USE_NSJAIL:-0}" = "1" ] && command -v nsjail >/dev/null 2>&1; then
    # 보수적 nsjail 프로파일: 새 네트워크/유저/pid 네임스페이스, rlimit 은
    # 러너가 자체적으로 건다. 실패 시 컨테이너 격리만으로 진행.
    exec nsjail \
        --quiet \
        --disable_clone_newnet \
        --time_limit "${SANDBOX_NSJAIL_TIME:-15}" \
        --rlimit_as "${SANDBOX_NSJAIL_AS_MB:-1024}" \
        -- python -m pwnable_lab.sandbox.cli "$@"
fi

exec python -m pwnable_lab.sandbox.cli "$@"
