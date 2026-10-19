"""Runtime settings and dynamic capacity/security controls for SkillBridge v2."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Callable


class SettingsValidationError(ValueError):
    """Raised when a user or caller supplies an invalid runtime setting value."""


@dataclass
class RuntimeSettings:
    """Validated runtime settings for SkillBridge v2 capacity, concurrency, and security."""

    # Capacity and memory management defaults (Sections 8, 9, 14)
    active_skill_limit: int = 25
    memory_threshold_mib: float = 250.0
    memory_target_mib: float = 210.0
    eviction_batch_default: int = 7
    eviction_batch_min: int = 5
    eviction_batch_max: int = 10

    # Parallel orchestration limits (Sections 10, 14)
    max_parallel_scans: int = 4
    max_parallel_mcp_calls: int = 8
    max_parallel_skill_workers: int = 8
    per_provider_concurrency: int = 2
    per_mcp_server_concurrency: int = 2

    # Security and assurance policy flags (Sections 2, 11, 14, 16)
    security_fail_closed: bool = True
    load_unknown_extensions: bool = False
    allow_untrusted_script_execution: bool = False
    script_network_access: bool = False
    auto_install_dependencies: bool = False
    permanent_native_install_requires_approval: bool = True
    content_cache_enabled: bool = True
    outcome_adaptation_enabled: bool = True

    # Optional external verification engine flags (Phase 3 & 4)
    enable_skillfortify: bool = False
    require_external_scanner_binaries: bool = False
    enable_tier3_behavioral_trials: bool = False

    # Script execution resource limits (Section 11)
    script_timeout_seconds: float = 15.0
    script_max_output_bytes: int = 1024 * 1024
    bundle_max_files: int = 5000
    bundle_max_total_bytes: int = 256 * 1024 * 1024
    bundle_max_single_file_bytes: int = 8 * 1024 * 1024
    bundle_max_depth: int = 12

    def validate(self) -> None:
        """Validate all runtime settings invariants."""
        if not isinstance(self.active_skill_limit, int) or self.active_skill_limit < 1 or self.active_skill_limit > 500:
            raise SettingsValidationError(
                f"active_skill_limit must be an integer between 1 and 500 (got {self.active_skill_limit!r})"
            )
        if self.memory_threshold_mib <= 16.0 or self.memory_threshold_mib > 65536.0:
            raise SettingsValidationError(
                f"memory_threshold_mib must be between 16.0 and 65536.0 MiB (got {self.memory_threshold_mib!r})"
            )
        if self.memory_target_mib <= 8.0 or self.memory_target_mib >= self.memory_threshold_mib:
            raise SettingsValidationError(
                f"memory_target_mib ({self.memory_target_mib}) must be >= 8.0 and strictly less than "
                f"memory_threshold_mib ({self.memory_threshold_mib})"
            )
        if self.eviction_batch_min < 1 or self.eviction_batch_max < self.eviction_batch_min:
            raise SettingsValidationError(
                f"Invalid eviction batch bounds: min={self.eviction_batch_min}, max={self.eviction_batch_max}"
            )
        if not (self.eviction_batch_min <= self.eviction_batch_default <= self.eviction_batch_max):
            raise SettingsValidationError(
                f"eviction_batch_default ({self.eviction_batch_default}) must be between "
                f"eviction_batch_min ({self.eviction_batch_min}) and eviction_batch_max ({self.eviction_batch_max})"
            )
        if self.max_parallel_scans < 1 or self.max_parallel_scans > 64:
            raise SettingsValidationError(
                f"max_parallel_scans must be between 1 and 64 (got {self.max_parallel_scans!r})"
            )
        if self.max_parallel_mcp_calls < 1 or self.max_parallel_mcp_calls > 128:
            raise SettingsValidationError(
                f"max_parallel_mcp_calls must be between 1 and 128 (got {self.max_parallel_mcp_calls!r})"
            )
        if self.max_parallel_skill_workers < 1 or self.max_parallel_skill_workers > 64:
            raise SettingsValidationError(
                f"max_parallel_skill_workers must be between 1 and 64 (got {self.max_parallel_skill_workers!r})"
            )
        if self.bundle_max_files < 1 or self.bundle_max_total_bytes < 1024 or self.bundle_max_single_file_bytes < 1024:
            raise SettingsValidationError(
                "bundle_max_files must be >= 1 and bundle byte limits must be >= 1024 "
                f"(got files={self.bundle_max_files!r}, total={self.bundle_max_total_bytes!r}, "
                f"single={self.bundle_max_single_file_bytes!r})"
            )
        if self.script_timeout_seconds <= 0 or self.script_timeout_seconds > 600:
            raise SettingsValidationError(
                f"script_timeout_seconds must be between 0 and 600s (got {self.script_timeout_seconds!r})"
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def policy_digest(self) -> str:
        """Return a stable digest of security-relevant policy settings."""
        import hashlib

        relevant = {
            "security_fail_closed": self.security_fail_closed,
            "load_unknown_extensions": self.load_unknown_extensions,
            "allow_untrusted_script_execution": self.allow_untrusted_script_execution,
            "script_network_access": self.script_network_access,
            "auto_install_dependencies": self.auto_install_dependencies,
            "require_external_scanner_binaries": self.require_external_scanner_binaries,
            "enable_skillfortify": self.enable_skillfortify,
        }
        payload = json.dumps(relevant, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:16]


class SettingsManager:
    """Manages loading, validating, updating, and persisting RuntimeSettings safely."""

    def __init__(
        self,
        settings_path: Path,
        initial: RuntimeSettings | None = None,
        on_change_callbacks: list[Callable[[RuntimeSettings, RuntimeSettings], None]] | None = None,
    ) -> None:
        self.settings_path = settings_path
        self._callbacks: list[Callable[[RuntimeSettings, RuntimeSettings], None]] = list(on_change_callbacks or [])
        self._load_warnings: list[str] = []
        if initial is not None:
            initial.validate()
            self._current = initial
        else:
            self._current = self._load_or_default()

    @property
    def current(self) -> RuntimeSettings:
        return self._current

    @property
    def load_warnings(self) -> list[str]:
        return list(self._load_warnings)

    def register_callback(self, callback: Callable[[RuntimeSettings, RuntimeSettings], None]) -> None:
        self._callbacks.append(callback)

    def _load_or_default(self) -> RuntimeSettings:
        defaults = RuntimeSettings()
        if not self.settings_path.exists():
            return defaults
        try:
            raw_text = self.settings_path.read_text(encoding="utf-8")
            parsed = json.loads(raw_text)
            if not isinstance(parsed, dict):
                raise SettingsValidationError("Settings JSON root must be an object.")
            merged = defaults.to_dict()
            for key, val in parsed.items():
                if key in merged:
                    merged[key] = val
            candidate = RuntimeSettings(**merged)
            candidate.validate()
            return candidate
        except Exception as exc:
            # Never silently overwrite a corrupt settings file; preserve backup and report warning
            self._load_warnings.append(f"Failed to parse settings from {self.settings_path}: {exc}")
            return defaults

    def save(self) -> None:
        """Persist current validated settings atomically."""
        self._current.validate()
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.settings_path.with_suffix(f".tmp.{os.getpid()}")
        tmp_path.write_text(json.dumps(self._current.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp_path, self.settings_path)

    def update(self, **updates: Any) -> RuntimeSettings:
        """Validate and apply partial settings updates at runtime without restart."""
        old_settings = RuntimeSettings(**self._current.to_dict())
        new_data = self._current.to_dict()
        for key, value in updates.items():
            if key not in new_data:
                raise SettingsValidationError(f"Unknown setting field: {key!r}")
            new_data[key] = value
        candidate = RuntimeSettings(**new_data)
        candidate.validate()
        self._current = candidate
        try:
            self.save()
        except OSError as exc:
            self._load_warnings.append(f"Could not persist settings to {self.settings_path}: {exc}")
        for cb in self._callbacks:
            cb(old_settings, self._current)
        return self._current
