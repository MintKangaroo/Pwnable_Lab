"""Phase 6A — auto-exploit sandbox (오프셋 확정 코어).

정적 exploit strategy(:mod:`pwnable_lab.analyzer.strategy`)가 추정한 오프셋을
**실제 실행으로 검증**하는 격리 러너의 핵심 로직을 제공한다. 이 증분은
`docs/AUTO_EXPLOIT_SANDBOX.md` 의 첫 단계(cyclic 주입 → 크래시 관측 →
`RIP`/스택 값으로 정확한 오프셋 확정)만 구현한다.

.. warning::
   이 모듈은 **신뢰할 수 없는 바이너리를 실행**한다. 여기서는 프로세스 단위
   자원 상한(rlimit)·타임아웃·프로세스그룹 강제 종료만 강제한다. 프로덕션
   노출 전에는 반드시 Phase 6 의 network-disabled 일회용 컨테이너(nsjail/gVisor
   등) 경계 안에서 호출해야 한다. 그 경계가 없는 상태로 업로드 API 파이프라인에
   직접 연결하지 말 것(현재 기본적으로 연결돼 있지 않다).
"""

from pwnable_lab.sandbox.debugger import (
    DebugSession,
    DebugWorker,
    StopEvent,
    run_debug_script,
)
from pwnable_lab.sandbox.executor import (
    auto_execve_in_container,
    auto_execve_pie_in_container,
    auto_fmt_got_overwrite_in_container,
    auto_fmt_got_overwrite_pie_in_container,
    auto_fmt_leak_pie_in_container,
    auto_ret2libc_in_container,
    auto_ret2system32_in_container,
    auto_ret2system32_pie_in_container,
    auto_ret2system_in_container,
    auto_ret2system_pie_in_container,
    auto_ret2win_pie_in_container,
    confirm_offset_in_container,
    confirm_offset_in_process,
    verify_exploit_in_container,
    verify_exploit_in_process,
)
from pwnable_lab.sandbox.execve import auto_execve as auto_execve_core
from pwnable_lab.sandbox.fmtleak import auto_fmt_leak_pie as auto_fmt_leak_pie_core
from pwnable_lab.sandbox.fmtwrite import (
    auto_fmt_got_overwrite as auto_fmt_got_overwrite_core,
)
from pwnable_lab.sandbox.fmtwrite import (
    auto_fmt_got_overwrite_pie as auto_fmt_got_overwrite_pie_core,
)
from pwnable_lab.sandbox.gate import (
    require_isolation_marker,
    require_sandbox_boundary,
    require_sandbox_enabled,
)
from pwnable_lab.sandbox.heap import inspect_heap, inspect_heap_session
from pwnable_lab.sandbox.heap_exploit import (
    build_poison_plan,
    detect_double_free,
    prove_tcache_poison,
    tcache_poison_fd,
)
from pwnable_lab.sandbox.memdump import dump_memory
from pwnable_lab.sandbox.oep import find_oep_candidate
from pwnable_lab.sandbox.orw import auto_orw as auto_orw_core
from pwnable_lab.sandbox.orw import auto_orw_pie as auto_orw_pie_core
from pwnable_lab.sandbox.pe_dynamic import run_pe
from pwnable_lab.sandbox.pie import auto_execve_pie as auto_execve_pie_core
from pwnable_lab.sandbox.pie import auto_ret2system_pie as auto_ret2system_pie_core
from pwnable_lab.sandbox.pie import auto_ret2win_pie as auto_ret2win_pie_core
from pwnable_lab.sandbox.qemu import run_under_qemu
from pwnable_lab.sandbox.ret2libc import auto_ret2libc as auto_ret2libc_core
from pwnable_lab.sandbox.ret2system import auto_ret2system as auto_ret2system_core
from pwnable_lab.sandbox.ret2system32 import auto_ret2system32 as auto_ret2system32_core
from pwnable_lab.sandbox.ret2system32 import (
    auto_ret2system32_pie as auto_ret2system32_pie_core,
)
from pwnable_lab.sandbox.runner import (
    CrashObservation,
    ExploitVerification,
    OffsetConfirmation,
    PieBaseResolution,
    SandboxLimits,
    ShellProof,
    confirm_return_offset,
    resolve_pie_base,
    run_two_stage,
    run_two_stage_shell,
    run_with_input,
    verify_payload,
    verify_shell,
)
from pwnable_lab.sandbox.runtime_strings import runtime_strings
from pwnable_lab.sandbox.srop import auto_srop as auto_srop_core
from pwnable_lab.sandbox.trace import execution_trace
from pwnable_lab.sandbox.unpack import unpack_upx

__all__ = [
    "CrashObservation",
    "DebugSession",
    "DebugWorker",
    "ExploitVerification",
    "OffsetConfirmation",
    "PieBaseResolution",
    "SandboxLimits",
    "ShellProof",
    "StopEvent",
    "auto_execve_core",
    "auto_execve_in_container",
    "auto_execve_pie_core",
    "auto_execve_pie_in_container",
    "auto_fmt_got_overwrite_core",
    "auto_fmt_got_overwrite_in_container",
    "auto_fmt_got_overwrite_pie_core",
    "auto_fmt_got_overwrite_pie_in_container",
    "auto_fmt_leak_pie_core",
    "auto_fmt_leak_pie_in_container",
    "auto_orw_core",
    "auto_orw_pie_core",
    "auto_ret2libc_core",
    "auto_ret2libc_in_container",
    "auto_ret2system32_core",
    "auto_ret2system32_in_container",
    "auto_ret2system32_pie_core",
    "auto_ret2system32_pie_in_container",
    "auto_ret2system_core",
    "auto_ret2system_in_container",
    "auto_ret2system_pie_core",
    "auto_ret2system_pie_in_container",
    "auto_ret2win_pie_core",
    "auto_ret2win_pie_in_container",
    "auto_srop_core",
    "build_poison_plan",
    "confirm_offset_in_container",
    "confirm_offset_in_process",
    "confirm_return_offset",
    "detect_double_free",
    "dump_memory",
    "execution_trace",
    "find_oep_candidate",
    "inspect_heap",
    "inspect_heap_session",
    "prove_tcache_poison",
    "tcache_poison_fd",
    "resolve_pie_base",
    "run_two_stage",
    "run_two_stage_shell",
    "require_isolation_marker",
    "require_sandbox_boundary",
    "require_sandbox_enabled",
    "run_debug_script",
    "run_pe",
    "run_under_qemu",
    "run_with_input",
    "runtime_strings",
    "unpack_upx",
    "verify_exploit_in_container",
    "verify_exploit_in_process",
    "verify_payload",
    "verify_shell",
]
