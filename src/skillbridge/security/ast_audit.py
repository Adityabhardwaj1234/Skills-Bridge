"""AST-level deep security and dynamic behavior audit for Python scripts inside extensions."""

from __future__ import annotations

import ast
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, List

IGNORED_DIRS = {"__pycache__", ".venv", "venv", "node_modules", ".git"}

DYNAMIC_CALLS = {
    "__import__": (0, "dynamic_import_computed", "high", "__import__() with non-literal module name"),
    "getattr": (1, "dynamic_getattr", "medium", "getattr() with non-literal attribute name"),
    "eval": (0, "ast_eval_call", "high", "Direct call to eval() builtin"),
    "exec": (0, "ast_exec_call", "high", "Direct call to exec() builtin"),
    "compile": (0, "ast_compile_call", "medium", "Direct call to compile() builtin"),
}


def scan_python_ast(source_code: str, rel_path: str = "<memory>") -> List[Dict[str, Any]]:
    """Parse Python source code into an AST and inspect for dynamic code loading or evasion."""
    try:
        tree = ast.parse(source_code)
    except (SyntaxError, ValueError, RecursionError, TypeError):
        return []

    findings: List[Dict[str, Any]] = []

    def add_finding(node: ast.AST, pid: str, severity: str, reason: str) -> None:
        findings.append(
            {
                "file": rel_path,
                "line": getattr(node, "lineno", 1),
                "pattern_id": pid,
                "severity": severity,
                "category": "ast_dynamic_behavior",
                "reason": reason,
            }
        )

    class SecurityNodeVisitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "import_module":
                add_finding(node, "dynamic_import_module", "high", "importlib.import_module() loads arbitrary modules at runtime")
            elif isinstance(func, ast.Name) and func.id in DYNAMIC_CALLS:
                arg_idx, pid, sev, desc = DYNAMIC_CALLS[func.id]
                if func.id in ("eval", "exec"):
                    add_finding(node, pid, sev, desc)
                elif len(node.args) > arg_idx and not isinstance(node.args[arg_idx], ast.Constant):
                    add_finding(node, pid, sev, desc)
            self.generic_visit(node)

        def visit_Subscript(self, node: ast.Subscript) -> None:
            if (
                isinstance(node.value, ast.Attribute)
                and node.value.attr in ("__dict__", "__globals__", "__builtins__")
                and not isinstance(node.slice, ast.Constant)
            ):
                add_finding(node, "dynamic_dict_subscript", "high", f"Dynamic computed access on {node.value.attr}")
            self.generic_visit(node)

        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                if alias.name == "importlib" or alias.name.startswith("importlib.") or alias.name == "ctypes":
                    add_finding(node, "low_level_import", "medium", f"Imports {alias.name} enabling dynamic/native loading")
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            mod = node.module or ""
            if mod == "importlib" or mod.startswith("importlib.") or mod == "ctypes":
                add_finding(node, "low_level_import_from", "medium", f"Imports from {mod} enabling dynamic/native loading")
            self.generic_visit(node)

    with suppress(RecursionError, ValueError, RuntimeError):
        SecurityNodeVisitor().visit(tree)

    return findings


def ast_audit_directory(root_dir: Path) -> List[Dict[str, Any]]:
    """Run AST security inspection across all Python files in a directory."""
    if not root_dir.exists():
        return []
    if root_dir.is_file():
        if root_dir.suffix.lower() == ".py":
            try:
                return scan_python_ast(root_dir.read_text(encoding="utf-8-sig", errors="replace"), root_dir.name)
            except OSError:
                return []
        return []
    all_findings: List[Dict[str, Any]] = []
    for py_file in sorted(root_dir.rglob("*.py")):
        if set(py_file.parent.parts) & IGNORED_DIRS:
            continue
        try:
            content = py_file.read_text(encoding="utf-8-sig", errors="replace")
            rel = py_file.relative_to(root_dir).as_posix()
            all_findings.extend(scan_python_ast(content, rel))
        except OSError:
            continue
    return all_findings
