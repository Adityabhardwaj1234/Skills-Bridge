"""Whole-directory skill bundle staging, manifest inventory, and script discovery."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any
from urllib.parse import unquote
import zipfile

from skillbridge.discovery.normalizer import is_link_like, parse_skill_md, validate_bundle_rel_path


class BundleIntegrityError(ValueError):
    """Raised when a skill bundle violates Tier 0 structural, symlink, size, or traversal constraints."""


@dataclass
class BundleFileEntry:
    """Single file entry inside a staged whole-directory skill bundle."""

    relative_path: str
    sha256: str
    size_bytes: int
    classification: str  # markdown, python, shell, javascript, typescript, config, manifest, asset, binary, archive, other
    is_executable: bool = False
    is_hidden: bool = False
    is_referenced: bool = False
    line_count: int = 0
    encoding_valid: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScriptEntryPoint:
    """Discovered executable script inside a skill bundle."""

    relative_path: str
    language: str  # python, shell, javascript, typescript, powershell
    sha256: str
    size_bytes: int
    is_referenced_in_skill_md: bool
    declared_dependencies: list[str] = field(default_factory=list)
    local_imports: list[str] = field(default_factory=list)
    observed_capabilities: list[str] = field(default_factory=list)
    syntax_valid: bool = True
    syntax_error: str | None = None
    execution_permitted_by_default: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BundleManifest:
    """Tier 0 immutable inventory and provenance manifest for a whole-directory skill bundle."""

    skill_id: str
    name: str
    version: str
    source_provider: str
    source_uri: str
    source_subpath: str
    resolved_revision: str
    bundle_digest: str
    staged_path: str
    total_files: int
    total_bytes: int
    max_depth_observed: int
    files: list[BundleFileEntry] = field(default_factory=list)
    scripts: list[ScriptEntryPoint] = field(default_factory=list)
    dependency_manifests: list[str] = field(default_factory=list)
    declared_dependencies: dict[str, list[str]] = field(default_factory=dict)
    declared_capabilities: list[str] = field(default_factory=list)
    observed_capabilities: list[str] = field(default_factory=list)
    has_executable_scripts: bool = False
    has_nested_archives: bool = False
    has_binary_payloads: bool = False
    has_encoding_errors: bool = False
    tier0_passed: bool = True
    tier0_violations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_SCRIPT_EXT_MAP = {
    ".py": "python",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
}

_CONFIG_EXTS = {".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
_ASSET_EXTS = {".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".txt", ".csv", ".html", ".css"}
_ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".whl"}
_DEPENDENCY_MANIFEST_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
}

_REF_PATTERN = re.compile(
    r"(?:\]\(([^)\s]+)\)|`((?:scripts|references|assets|examples|templates|config|tests)/[A-Za-z0-9_./-]+)`|"
    r"(?:python3?|bash|sh|node)\s+([A-Za-z0-9_./-]+\.(?:py|sh|js|ts|ps1)))"
)


def classify_bundle_file(rel_path: str, raw_bytes: bytes) -> tuple[str, bool, int]:
    """Return (classification, encoding_valid, line_count) for a bundle file."""
    path_obj = Path(rel_path)
    name = path_obj.name
    suffix = path_obj.suffix.lower()

    if name in _DEPENDENCY_MANIFEST_NAMES:
        try:
            text = raw_bytes.decode("utf-8")
            return "manifest", True, len(text.splitlines())
        except UnicodeDecodeError:
            return "manifest", False, 0

    if suffix in (".md", ".markdown", ".mdx"):
        try:
            text = raw_bytes.decode("utf-8")
            if "\x00" in text:
                return "markdown", False, 0
            return "markdown", True, len(text.splitlines())
        except UnicodeDecodeError:
            return "markdown", False, 0

    if suffix in _SCRIPT_EXT_MAP:
        try:
            text = raw_bytes.decode("utf-8")
            if "\x00" in text:
                return _SCRIPT_EXT_MAP[suffix], False, 0
            return _SCRIPT_EXT_MAP[suffix], True, len(text.splitlines())
        except UnicodeDecodeError:
            return _SCRIPT_EXT_MAP[suffix], False, 0

    if suffix in _ARCHIVE_EXTS:
        return "archive", True, 0

    if suffix in _CONFIG_EXTS:
        try:
            text = raw_bytes.decode("utf-8")
            return "config", True, len(text.splitlines())
        except UnicodeDecodeError:
            return "config", False, 0

    if suffix in (".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe", ".bin", ".wasm", ".pkl", ".pickle"):
        return "binary", True, 0

    if b"\x00" in raw_bytes[:4096]:
        if suffix in _ASSET_EXTS:
            return "asset", True, 0
        return "binary", True, 0

    try:
        text = raw_bytes.decode("utf-8")
        return ("asset" if suffix in _ASSET_EXTS else "other"), True, len(text.splitlines())
    except UnicodeDecodeError:
        return "binary", False, 0


def _infer_script_capabilities_and_imports(
    language: str, source_text: str
) -> tuple[list[str], list[str], bool, str | None]:
    """Inspect a script statically to determine capabilities, local imports, and syntax validity."""
    caps: set[str] = set()
    local_imports: list[str] = []
    syntax_valid = True
    syntax_error: str | None = None

    if language == "python":
        import ast

        try:
            tree = ast.parse(source_text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mod = alias.name.split(".")[0]
                        local_imports.append(mod)
                        if mod in ("urllib", "http", "socket", "requests", "httpx", "aiohttp"):
                            caps.add("network:outbound")
                        elif mod in ("subprocess", "pty", "multiprocessing"):
                            caps.add("process:exec")
                elif isinstance(node, ast.ImportFrom):
                    if node.level and node.level > 0:
                        local_imports.append(f".{node.module or ''}")
                    elif node.module:
                        mod = node.module.split(".")[0]
                        local_imports.append(mod)
                        if mod in ("urllib", "http", "socket", "requests", "httpx", "aiohttp"):
                            caps.add("network:outbound")
                        elif mod in ("subprocess", "pty"):
                            caps.add("process:exec")
                elif isinstance(node, ast.Call):
                    func_str = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
                    if any(k in func_str for k in ("subprocess.", "os.system", "os.popen", "os.exec", "eval", "exec")):
                        caps.add("process:exec")
                    if any(k in func_str for k in ("urlopen", "requests.", "httpx.", "socket.")):
                        caps.add("network:outbound")
                    if any(k in func_str for k in ("open", "write_text", "write_bytes", "rmtree", "unlink", "mkdir")):
                        caps.add("filesystem:read_write")
                elif isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
                        caps.add("env:read")
        except SyntaxError as exc:
            syntax_valid = False
            syntax_error = f"{exc.msg} (line {exc.lineno})"

    if re.search(r"\b(curl|wget|fetch|http://|https://|nc\s|netcat)\b", source_text):
        caps.add("network:outbound")
    if re.search(r"\b(rm\s|mv\s|cp\s|mkdir\s|chmod\s|>>|>)\b", source_text):
        caps.add("filesystem:read_write")
    if re.search(
        r"(\$\{?[A-Z0-9_]*KEY|\$\{?[A-Z0-9_]*TOKEN|\$\{?[A-Z0-9_]*SECRET|process\.env|os\.environ)",
        source_text,
    ):
        caps.add("env:read")
    if re.search(r"\b(subprocess|child_process|execSync|spawn|eval\s*\()\b", source_text):
        caps.add("process:exec")

    return sorted(caps), sorted(set(local_imports)), syntax_valid, syntax_error


def _parse_dependency_manifests(bundle_root: Path, manifest_rel_paths: list[str]) -> dict[str, list[str]]:
    """Extract declared package dependencies without executing setup.py or hooks."""
    deps: dict[str, list[str]] = {}
    for rel in manifest_rel_paths:
        p = bundle_root / rel
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        name = p.name
        items: list[str] = []
        if name == "requirements.txt":
            for line in text.splitlines():
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("#"):
                    items.append(cleaned)
        elif name == "package.json":
            try:
                data = json.loads(text)
                for sec in ("dependencies", "devDependencies", "peerDependencies"):
                    if isinstance(data.get(sec), dict):
                        for pkg, ver in data[sec].items():
                            items.append(f"{pkg}@{ver}")
            except Exception:
                pass
        elif name == "pyproject.toml":
            for m in re.finditer(r'"([a-zA-Z0-9_.-]+(?:[><=!~]+[^"]+)?)"', text):
                val = m.group(1)
                if any(op in val for op in (">=", "==", "<=", "~=", ">", "<")):
                    items.append(val)
        deps[rel] = items
    return deps


class BundleStager:
    """Tier 0 Provenance & Artifact Intake stager for whole-directory skill bundles."""

    def __init__(
        self,
        quarantine_staging_dir: Path,
        active_staging_dir: Path,
        *,
        max_files: int = 500,
        max_total_bytes: int = 15 * 1024 * 1024,
        max_single_file_bytes: int = 2 * 1024 * 1024,
        max_depth: int = 8,
    ) -> None:
        self.quarantine_staging_dir = quarantine_staging_dir
        self.active_staging_dir = active_staging_dir
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_single_file_bytes = max_single_file_bytes
        self.max_depth = max_depth
        self.quarantine_staging_dir.mkdir(parents=True, exist_ok=True)
        self.active_staging_dir.mkdir(parents=True, exist_ok=True)

    def stage_from_files_map(
        self,
        files_map: dict[str, bytes | str],
        *,
        skill_id: str,
        source_provider: str = "bundled",
        source_uri: str = "",
        source_subpath: str = "",
        resolved_revision: str = "HEAD",
    ) -> BundleManifest:
        """Materialize an in-memory ExtensionBundle files dict into quarantine staging and run Tier 0 validation.

        Every key is validated as a bundle-relative path before any write. This rejects Windows
        drive/UNC paths, traversal, NTFS streams, device names, and case-colliding entries that
        could otherwise write outside the staging directory or make the archive ambiguous.
        """
        safe_files: dict[str, bytes | str] = {}
        seen: dict[str, str] = {}
        rejected: list[str] = []
        for rel_p, content in files_map.items():
            try:
                safe_rel = validate_bundle_rel_path(rel_p)
            except ValueError as exc:
                rejected.append(f"{rel_p!r}: {exc}")
                continue
            key = safe_rel.casefold()
            if key in seen:
                rejected.append(f"duplicate/case-colliding bundle path: {seen[key]!r} vs {safe_rel!r}")
                continue
            seen[key] = safe_rel
            safe_files[safe_rel] = content
        if rejected:
            raise BundleIntegrityError(
                "Unsafe in-memory bundle rejected before staging: " + "; ".join(rejected[:8])
            )

        tmp_src = self.quarantine_staging_dir / f"_src_{re.sub(r'[^a-zA-Z0-9_.-]+', '_', skill_id)}"
        if tmp_src.exists():
            shutil.rmtree(tmp_src, ignore_errors=True)
        tmp_src.mkdir(parents=True, exist_ok=True)
        try:
            for rel_p, content in safe_files.items():
                dest = tmp_src.joinpath(*rel_p.split("/"))
                dest.parent.mkdir(parents=True, exist_ok=True)
                if not dest.resolve().is_relative_to(tmp_src.resolve()):
                    raise BundleIntegrityError(f"Bundle path escaped staging root: {rel_p}")
                if isinstance(content, bytes):
                    dest.write_bytes(content)
                else:
                    dest.write_text(str(content), encoding="utf-8")
            return self.stage_into_quarantine(
                tmp_src,
                skill_id=skill_id,
                source_provider=source_provider,
                source_uri=source_uri,
                source_subpath=source_subpath,
                resolved_revision=resolved_revision,
            )
        finally:
            shutil.rmtree(tmp_src, ignore_errors=True)

    def stage_into_quarantine(
        self,
        source_path: Path,
        *,
        skill_id: str,
        source_provider: str = "local",
        source_uri: str = "",
        source_subpath: str = "",
        resolved_revision: str = "HEAD",
    ) -> BundleManifest:
        """Create an immutable staged snapshot in quarantine and run Tier 0 intake validation."""
        violations: list[str] = []
        invalid_paths: set[str] = set()
        if not source_path.exists():
            raise BundleIntegrityError(f"Bundle source path does not exist: {source_path}")

        bundle_src = source_path.parent if source_path.is_file() else source_path

        all_entries: list[tuple[Path, str]] = []
        total_bytes = 0
        max_depth_seen = 0

        for dirpath, dirnames, filenames in os.walk(bundle_src, followlinks=False):
            dirnames[:] = [d for d in sorted(dirnames) if d not in ("__pycache__", ".git", ".pytest_cache")]
            rel_dir = Path(dirpath).relative_to(bundle_src)
            depth = 0 if str(rel_dir) == "." else len(rel_dir.parts)
            if depth > max_depth_seen:
                max_depth_seen = depth
            if depth > self.max_depth:
                violations.append(f"Directory recursion depth {depth} exceeds limit {self.max_depth}: {rel_dir}")
                continue

            for d in list(dirnames):
                dp = Path(dirpath) / d
                if is_link_like(dp):
                    violations.append(f"Symlinked/junction directory rejected by Tier 0 policy: {dp.relative_to(bundle_src)}")
                    dirnames.remove(d)

            for fname in sorted(filenames):
                if fname == ".skillbridge_bundle_manifest.json":
                    continue
                fpath = Path(dirpath) / fname
                rel_str = fpath.relative_to(bundle_src).as_posix()
                if ".." in Path(rel_str).parts:
                    violations.append(f"Path traversal segment in bundle path: {rel_str}")
                    continue
                try:
                    rel_str = validate_bundle_rel_path(rel_str, max_depth=max(self.max_depth, 1))
                except ValueError as exc:
                    violations.append(f"Unsafe bundle path rejected: {rel_str} ({exc})")
                    continue
                if is_link_like(fpath):
                    violations.append(f"Symlink/reparse point inside skill bundle rejected by Tier 0 policy: {rel_str}")
                    continue
                try:
                    st = fpath.lstat()
                except OSError as exc:
                    violations.append(f"Cannot stat file {rel_str}: {exc}")
                    continue
                if not stat.S_ISREG(st.st_mode):
                    violations.append(f"Non-regular file rejected: {rel_str}")
                    continue
                if getattr(st, "st_nlink", 1) > 1:
                    violations.append(
                        f"Hardlinked file rejected by Tier 0 policy (possible out-of-bundle data): {rel_str}"
                    )
                    continue
                if st.st_size > self.max_single_file_bytes:
                    violations.append(
                        f"File {rel_str} size ({st.st_size}B) exceeds single-file limit ({self.max_single_file_bytes}B)"
                    )
                    invalid_paths.add(rel_str)
                total_bytes += st.st_size
                all_entries.append((fpath, rel_str))

        if len(all_entries) > self.max_files:
            violations.append(f"Bundle file count ({len(all_entries)}) exceeds limit ({self.max_files})")
        if total_bytes > self.max_total_bytes:
            violations.append(f"Bundle total size ({total_bytes}B) exceeds limit ({self.max_total_bytes}B)")

        hasher = hashlib.sha256()
        for fpath, rel_str in sorted(all_entries, key=lambda x: x[1]):
            hasher.update(rel_str.encode("utf-8"))
            hasher.update(b"\x00")
            try:
                data = fpath.read_bytes()
                hasher.update(hashlib.sha256(data).digest())
            except OSError:
                hasher.update(b"READ_ERROR")
        bundle_digest = f"sha256:{hasher.hexdigest()[:32]}"

        digest_slug = bundle_digest.replace(":", "_")
        staged_dir = self.quarantine_staging_dir / digest_slug
        if staged_dir.exists():
            shutil.rmtree(staged_dir, ignore_errors=True)
        staged_dir.mkdir(parents=True, exist_ok=True)

        for fpath, rel_str in all_entries:
            if rel_str in invalid_paths:
                continue
            dest = staged_dir.joinpath(*rel_str.split("/"))
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.resolve().is_relative_to(staged_dir.resolve()):
                violations.append(f"Staged path escaped bundle root: {rel_str}")
                invalid_paths.add(rel_str)
                continue
            shutil.copy2(fpath, dest)

        skill_md_path = staged_dir / "SKILL.md"
        frontmatter: dict[str, Any] = {}
        referenced_paths: set[str] = set()
        if skill_md_path.exists():
            raw_md = skill_md_path.read_bytes()
            _, enc_ok, _ = classify_bundle_file("SKILL.md", raw_md)
            if not enc_ok:
                violations.append("Primary SKILL.md contains invalid UTF-8 or null bytes (unsupported_primary_content)")
            else:
                md_text = raw_md.decode("utf-8")
                frontmatter, _ = parse_skill_md(md_text)
                if "_invalid_frontmatter" in frontmatter:
                    violations.append(f"Malformed SKILL.md frontmatter: {frontmatter['_invalid_frontmatter']}")
                for m in _REF_PATTERN.finditer(md_text):
                    ref_candidate = (m.group(1) or m.group(2) or m.group(3) or "").strip()
                    if not ref_candidate or ref_candidate.startswith("#"):
                        continue
                    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", ref_candidate):
                        # Absolute URL or non-file scheme (http:, mailto:, data:, javascript:, ...).
                        continue
                    raw_ref = unquote(ref_candidate.split("#")[0].split("?")[0]).strip()
                    try:
                        referenced_paths.add(validate_bundle_rel_path(raw_ref))
                    except ValueError as exc:
                        violations.append(
                            f"SKILL.md references unsafe path escaping bundle root: {ref_candidate} ({exc})"
                        )
        else:
            violations.append("Missing required SKILL.md at bundle root")

        file_entries: list[BundleFileEntry] = []
        script_entries: list[ScriptEntryPoint] = []
        manifest_paths: list[str] = []
        observed_caps: set[str] = set()
        has_nested_archives = False
        has_binary_payloads = False
        has_encoding_errors = False

        for fpath, rel_str in all_entries:
            staged_file = staged_dir / rel_str
            if not staged_file.exists():
                continue
            raw_bytes = staged_file.read_bytes()
            f_hash = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()[:24]}"
            classification, enc_valid, line_count = classify_bundle_file(rel_str, raw_bytes)
            is_hidden = any(part.startswith(".") for part in Path(rel_str).parts)
            st_mode = staged_file.stat().st_mode
            is_exec = bool(st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) or classification in (
                "python",
                "shell",
                "javascript",
                "typescript",
                "powershell",
            )
            is_ref = rel_str in referenced_paths

            if not enc_valid:
                has_encoding_errors = True
                violations.append(f"Malformed text encoding or binary bytes in {rel_str}")
            if classification == "archive":
                has_nested_archives = True
                if rel_str.lower().endswith(".zip"):
                    try:
                        with zipfile.ZipFile(staged_file, "r") as zf:
                            uncompressed = sum(z.file_size for z in zf.infolist())
                            if uncompressed > self.max_total_bytes * 2:
                                violations.append(f"Nested archive {rel_str} exceeds decompression ratio/size limit")
                            for zinfo in zf.infolist():
                                if ".." in Path(zinfo.filename).parts or zinfo.filename.startswith("/"):
                                    violations.append(
                                        f"Nested archive {rel_str} contains path traversal: {zinfo.filename}"
                                    )
                    except Exception as exc:
                        violations.append(f"Corrupted nested archive {rel_str}: {exc}")
            if classification == "binary":
                has_binary_payloads = True
                if is_hidden:
                    violations.append(f"Hidden binary payload detected: {rel_str}")
            if is_hidden and is_exec:
                violations.append(f"Hidden executable script detected: {rel_str}")
            if classification == "manifest":
                manifest_paths.append(rel_str)

            file_entries.append(
                BundleFileEntry(
                    relative_path=rel_str,
                    sha256=f_hash,
                    size_bytes=len(raw_bytes),
                    classification=classification,
                    is_executable=is_exec,
                    is_hidden=is_hidden,
                    is_referenced=is_ref,
                    line_count=line_count,
                    encoding_valid=enc_valid,
                )
            )

            if classification in ("python", "shell", "javascript", "typescript", "powershell") and enc_valid:
                text = raw_bytes.decode("utf-8", errors="replace")
                s_caps, s_imports, syn_ok, syn_err = _infer_script_capabilities_and_imports(classification, text)
                observed_caps.update(s_caps)
                script_entries.append(
                    ScriptEntryPoint(
                        relative_path=rel_str,
                        language=classification,
                        sha256=f_hash,
                        size_bytes=len(raw_bytes),
                        is_referenced_in_skill_md=is_ref,
                        local_imports=s_imports,
                        observed_capabilities=s_caps,
                        syntax_valid=syn_ok,
                        syntax_error=syn_err,
                        execution_permitted_by_default=False,
                    )
                )

        declared_deps = _parse_dependency_manifests(staged_dir, manifest_paths)
        flat_deps = [dep for dep_list in declared_deps.values() for dep in dep_list]
        for s_entry in script_entries:
            s_entry.declared_dependencies = list(flat_deps)

        declared_caps: list[str] = []
        for key in ("capabilities", "allowed-tools", "tools", "permissions"):
            val = frontmatter.get(key)
            if isinstance(val, list):
                declared_caps.extend(str(x) for x in val)
            elif isinstance(val, str):
                declared_caps.extend(x.strip() for x in val.split(",") if x.strip())

        name = str(frontmatter.get("name") or bundle_src.name)
        version = str(frontmatter.get("version") or "1.0.0")

        manifest = BundleManifest(
            skill_id=skill_id,
            name=name,
            version=version,
            source_provider=source_provider,
            source_uri=source_uri or str(bundle_src),
            source_subpath=source_subpath,
            resolved_revision=resolved_revision,
            bundle_digest=bundle_digest,
            staged_path=str(staged_dir),
            total_files=len(file_entries),
            total_bytes=total_bytes,
            max_depth_observed=max_depth_seen,
            files=file_entries,
            scripts=script_entries,
            dependency_manifests=manifest_paths,
            declared_dependencies=declared_deps,
            declared_capabilities=sorted(set(declared_caps)),
            observed_capabilities=sorted(observed_caps),
            has_executable_scripts=len(script_entries) > 0,
            has_nested_archives=has_nested_archives,
            has_binary_payloads=has_binary_payloads,
            has_encoding_errors=has_encoding_errors,
            tier0_passed=(len(violations) == 0),
            tier0_violations=violations,
        )

        manifest_file = staged_dir / ".skillbridge_bundle_manifest.json"
        manifest_file.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
        return manifest

    def promote_to_active_staging(self, manifest: BundleManifest, session_id: str) -> Path:
        """Copy a verified bundle from quarantine staging into a session-scoped active staging directory."""
        if not manifest.tier0_passed:
            raise BundleIntegrityError(
                f"Cannot promote bundle {manifest.skill_id} with Tier 0 violations: {manifest.tier0_violations}"
            )
        src = Path(manifest.staged_path)
        if not src.exists():
            raise BundleIntegrityError(f"Quarantine staged bundle missing at {src}")

        current_hash = self.recompute_staged_digest(src)
        if current_hash != manifest.bundle_digest:
            raise BundleIntegrityError(
                f"Bundle digest mismatch during promotion (expected {manifest.bundle_digest}, got {current_hash})"
            )

        safe_skill = re.sub(r"[^a-zA-Z0-9_.-]+", "_", manifest.skill_id)
        safe_session = re.sub(r"[^a-zA-Z0-9_.-]+", "_", session_id)
        dest = self.active_staging_dir / safe_session / safe_skill
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dest)
        return dest

    def recompute_staged_digest(self, staged_dir: Path) -> str:
        """Recompute the Tier 0 bundle digest of a staged directory (excluding .skillbridge_bundle_manifest.json)."""
        hasher = hashlib.sha256()
        entries: list[tuple[Path, str]] = []
        for dirpath, dirnames, filenames in os.walk(staged_dir, followlinks=False):
            dirnames[:] = [d for d in sorted(dirnames) if d not in ("__pycache__", ".git", ".pytest_cache")]
            for fname in sorted(filenames):
                if fname == ".skillbridge_bundle_manifest.json":
                    continue
                fpath = Path(dirpath) / fname
                rel_str = fpath.relative_to(staged_dir).as_posix()
                entries.append((fpath, rel_str))
        for fpath, rel_str in sorted(entries, key=lambda x: x[1]):
            hasher.update(rel_str.encode("utf-8"))
            hasher.update(b"\x00")
            hasher.update(hashlib.sha256(fpath.read_bytes()).digest())
        return f"sha256:{hasher.hexdigest()[:32]}"
