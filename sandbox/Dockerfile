# PwnPilot 동적 오프셋 확정 — 일회용(one-shot) 샌드박스 이미지.
#
# 이 이미지는 신뢰할 수 없는 업로드 바이너리를 한 번 실행해 반환 주소 오프셋을
# 확정한 뒤 종료한다. **네트워크 차단·read-only 루트·캡 드롭·일회용** 실행은
# 이미지가 아니라 `docker run` 플래그(또는 gVisor 런타임)로 강제한다 —
# `sandbox/run.sh` 및 docs/AUTO_EXPLOIT_SANDBOX.md 참조.
#
# 빌드 컨텍스트는 저장소 루트:
#   docker build -f sandbox/Dockerfile -t pwnpilot-sandbox .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAB_SANDBOX_EXECUTION_ENABLED=1 \
    PLAB_SANDBOX_ISOLATION_MARKER=/run/pwnpilot-sandbox \
    TMPDIR=/tmp

WORKDIR /app

# 러너/게이트/CLI 만 있으면 되지만, 패키지 전체를 설치해 import 경로를 단순화한다.
COPY backend/pyproject.toml backend/setup.py ./
COPY backend/pwnable_lab ./pwnable_lab

RUN pip install --no-cache-dir .

COPY sandbox/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0555 /usr/local/bin/entrypoint.sh

# 컨테이너 안에서는 root 로 실행한다. ptrace 러너는 Docker 기본 seccomp 를
# 통과하려면 effective CAP_SYS_PTRACE 가 필요한데, 비특권 사용자로 전환하면
# 그 capability 가 사라져 ptrace 가 막힌다(파일 capability 없음). 대신 컨테이너
# 밖에서 `docker run` 이 --network none / --read-only / --cap-drop ALL
# (+ --cap-add SYS_PTRACE 하나만) / --pids-limit / --memory 로 경계를 강제하고,
# 더 강한 격리는 gVisor(runsc) 로 얹는다. 이는 nsjail/gVisor 샌드박스의
# "안은 root, 밖은 강한 제약" 관례와 동일하다. 격리 마커(/run)·임시 실행파일
# (/tmp)은 런타임 tmpfs 에 쓴다.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
