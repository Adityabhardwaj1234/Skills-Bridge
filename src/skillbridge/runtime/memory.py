"""Process-tree memory monitoring and deterministic fake memory provider for SkillBridge v2."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

try:  # POSIX-only module; Windows uses the Win32 working-set API below instead.
    import resource  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]


@dataclass
class MemorySnapshot:
    """Point-in-time resource and capacity measurement for the SkillBridge runtime."""

    process_rss_bytes: int
    child_rss_bytes: int
    total_process_tree_bytes: int
    total_process_tree_mib: float
    loaded_payload_bytes: int
    staged_bundle_disk_bytes: int
    active_skill_count: int
    in_use_skill_count: int
    pinned_skill_count: int
    active_worker_processes: int
    active_mcp_processes: int
    threshold_mib: float
    target_watermark_mib: float
    over_threshold: bool
    genuine_unrelieved_pressure: bool = False
    measurement_source: str = "system"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MemoryProvider(ABC):
    """Abstract provider for process and child-tree RSS measurements."""

    @abstractmethod
    def get_process_and_children_rss_bytes(self) -> tuple[int, int, int, str]:
        """Return (self_rss_bytes, child_rss_bytes, child_count, source_label)."""


class SystemMemoryProvider(MemoryProvider):
    """Real OS process and child-tree RSS provider using psutil, /proc, resource, or ps."""

    def get_process_and_children_rss_bytes(self) -> tuple[int, int, int, str]:
        pid = os.getpid()
        # 1. Try psutil if installed
        try:
            import psutil  # type: ignore

            proc = psutil.Process(pid)
            self_rss = int(proc.memory_info().rss)
            children = proc.children(recursive=True)
            child_rss = 0
            for ch in children:
                try:
                    child_rss += int(ch.memory_info().rss)
                except Exception:
                    pass
            return self_rss, child_rss, len(children), "psutil"
        except Exception:
            pass

        # 2. Linux /proc/self/status VmRSS + ps child tree
        self_rss = 0
        source = "resource"
        status_path = Path("/proc/self/status")
        if status_path.exists():
            try:
                for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("VmRSS:"):
                        kb = int(line.split()[1])
                        self_rss = kb * 1024
                        source = "/proc/self/status"
                        break
            except Exception:
                pass

        if self_rss == 0:
            if os.name == "nt":
                # Real working-set measurement on Windows via psapi (no third-party dependency).
                try:
                    import ctypes
                    from ctypes import wintypes

                    class _ProcessMemoryCounters(ctypes.Structure):
                        _fields_ = [
                            ("cb", wintypes.DWORD),
                            ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t),
                            ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t),
                            ("PeakPagefileUsage", ctypes.c_size_t),
                        ]

                    counters = _ProcessMemoryCounters()
                    counters.cb = ctypes.sizeof(counters)
                    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
                    psapi = ctypes.WinDLL("psapi", use_last_error=True)  # type: ignore[attr-defined]
                    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
                    psapi.GetProcessMemoryInfo.argtypes = [
                        wintypes.HANDLE,
                        ctypes.POINTER(_ProcessMemoryCounters),
                        wintypes.DWORD,
                    ]
                    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
                    handle = kernel32.GetCurrentProcess()
                    if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                        self_rss = int(counters.WorkingSetSize)
                        source = "win32_working_set"
                except Exception:
                    pass
            elif resource is not None:
                try:
                    usage = resource.getrusage(resource.RUSAGE_SELF)
                    # On Linux ru_maxrss is in KB; on macOS it is in bytes
                    factor = 1 if sys.platform == "darwin" else 1024
                    self_rss = int(usage.ru_maxrss * factor)
                except Exception:
                    self_rss = 32 * 1024 * 1024
        if self_rss == 0:
            self_rss = 32 * 1024 * 1024
            source = "fallback_estimate"

        child_rss = 0
        child_count = 0
        if os.name != "nt":
            try:
                proc = subprocess.run(
                    ["ps", "-eo", "pid,ppid,rss"],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=1.5,
                )
                if proc.returncode == 0:
                    children_map: dict[int, list[tuple[int, int]]] = {}
                    for line in proc.stdout.splitlines()[1:]:
                        parts = line.split()
                        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit() and parts[2].isdigit():
                            c_pid, p_pid, rss_kb = int(parts[0]), int(parts[1]), int(parts[2])
                            children_map.setdefault(p_pid, []).append((c_pid, rss_kb * 1024))
                    queue = list(children_map.get(pid, []))
                    visited: set[int] = set()
                    while queue:
                        c_pid, c_bytes = queue.pop(0)
                        if c_pid in visited:
                            continue
                        visited.add(c_pid)
                        child_rss += c_bytes
                        child_count += 1
                        queue.extend(children_map.get(c_pid, []))
            except Exception:
                pass

        return self_rss, child_rss, child_count, source


class FakeMemoryProvider(MemoryProvider):
    """Deterministic memory provider for testing the 250 MiB threshold and 210 MiB watermark."""

    def __init__(
        self,
        base_rss_mib: float = 120.0,
        per_skill_overhead_mib: float = 12.0,
        child_rss_mib: float = 0.0,
        child_count: int = 0,
    ) -> None:
        self.base_rss_bytes = int(base_rss_mib * 1024 * 1024)
        self.per_skill_overhead_bytes = int(per_skill_overhead_mib * 1024 * 1024)
        self.child_rss_bytes = int(child_rss_mib * 1024 * 1024)
        self.child_count = child_count
        self._active_skill_counter: int = 0
        self._extra_payload_bytes: int = 0

    def sync_runtime_state(self, active_skills: int, payload_bytes: int) -> None:
        self._active_skill_counter = active_skills
        self._extra_payload_bytes = payload_bytes

    def set_base_rss_mib(self, mib: float) -> None:
        self.base_rss_bytes = int(mib * 1024 * 1024)

    def get_process_and_children_rss_bytes(self) -> tuple[int, int, int, str]:
        self_rss = (
            self.base_rss_bytes
            + (self._active_skill_counter * self.per_skill_overhead_bytes)
            + self._extra_payload_bytes
        )
        return self_rss, self.child_rss_bytes, self.child_count, "fake_deterministic"


def compute_directory_disk_bytes(root: Path) -> int:
    if not root.exists():
        return 0
    total = 0
    for dirpath, _, filenames in os.walk(root, followlinks=False):
        for fname in filenames:
            try:
                total += (Path(dirpath) / fname).stat().st_size
            except OSError:
                pass
    return total
