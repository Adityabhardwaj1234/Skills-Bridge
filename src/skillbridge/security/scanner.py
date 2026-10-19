"""Security scanner for skills, agent files, supporting scripts, and MCP server launch specifications.

Incorporates Hermes Skills Guard v10 patterns plus MCP server IOC & shell egress checks,
invisible Unicode detection, symlink escape checks, and context-aware false-positive reduction.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from skillbridge.discovery.normalizer import (
    compute_bundle_content_hash,
    compute_directory_content_hash,
    parse_skill_md,
    validate_bundle_rel_path,
)
from skillbridge.models import (
    ExtensionBundle,
    MCPTransportSpec,
    SecurityAssessment,
    SecurityFinding,
    SecurityVerdict,
    utc_now_iso,
)
from skillbridge.security.ast_audit import ast_audit_directory, scan_python_ast

SCANNER_VERSION = "skillbridge-guard-v1"

MAX_FILE_COUNT = 50
MAX_TOTAL_SIZE_KB = 5120
MAX_SINGLE_FILE_KB = 256

SCANNABLE_EXTENSIONS = {
    ".md", ".txt", ".py", ".sh", ".bash", ".js", ".ts", ".rb", ".yaml", ".yml",
    ".json", ".toml", ".cfg", ".ini", ".conf", ".html", ".css", ".xml", ".tex", ".r", ".jl", ".pl", ".php",
}
SUSPICIOUS_BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".com", ".msi", ".dmg", ".app", ".deb", ".rpm",
}
SCRIPT_EXTENSIONS = {".sh", ".bash", ".py", ".rb", ".pl", ".ps1"}

INVISIBLE_CHAR_NAMES = {
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u2060": "word joiner",
    "\u2062": "invisible times",
    "\u2063": "invisible separator",
    "\u2064": "invisible plus",
    "\ufeff": "BOM/zero-width no-break space",
    "\u202a": "LTR embedding",
    "\u202b": "RTL embedding",
    "\u202c": "pop directional",
    "\u202d": "LTR override",
    "\u202e": "RTL override",
    "\u2066": "LTR isolate",
    "\u2067": "RTL isolate",
    "\u2068": "first strong isolate",
    "\u2069": "pop directional isolate",
}
INVISIBLE_CHARS = set(INVISIBLE_CHAR_NAMES.keys())

MODIFY_VERB_RE = (
    r"(?:\bwrit(?:e|es|ing)\b|\bwritten\b|\bedit(?:s|ed|ing)?\b"
    r"|\bmodif(?:y|ies|ied|ying|ication)s?\b|\bupdat(?:e|es|ed|ing)\b"
    r"|\bappend(?:s|ed|ing)?\b|\bprepend(?:s|ed|ing)?\b"
    r"|\binject(?:s|ed|ing)?\b|\boverwrit(?:e|es|ing)\b|\boverwritten\b"
    r"|\breplac(?:e|es|ed|ing)\b|\balter(?:s|ed|ing)?\b|\badd(?:s|ed|ing)\b)"
)
_AGENT_CONFIG_FILES = r"(?:AGENTS\.md|CLAUDE\.md|\.cursorrules|\.clinerules|opencode\.jsonc?|\.mcp\.json)"
_HERMES_CONFIG_FILES = r"\.hermes/(?:config\.yaml|SOUL\.md)"
_OTHER_AGENT_CONFIG_FILES = r"\.(?:claude/settings|codex/config)[\w.]*"


def _shell_write_re(file_alt: str) -> str:
    return (
        rf"(?:>>|[\w\"'`)\]]\s*>)\s*[~\w./-]*{file_alt}(?!\.?\w)"
        rf"|\bsed\b[^\n]*\s(?:-[A-Za-z]*i[A-Za-z]*|--in-place)\b[^\n]*{file_alt}(?!\.?\w)"
        rf"|\btee\s+(?:-a\s+)?[~\w./\"'-]*{file_alt}(?!\.?\w)"
        rf"|\b(?:cp|mv)\s+[^\s|;&]+\s+[^\n|;&]{{0,40}}?{file_alt}(?!\.?\w)"
    )


def _prose_modify_re(file_alt: str) -> str:
    return (
        rf"^\s*(?:[-*+]\s+|\d+[.)]\s+)?{MODIFY_VERB_RE}[^\n,]{{0,80}}?{file_alt}\b"
        rf"|(?:\byou\s+(?:must|should|need\s+to)\s+|\bplease\s+"
        rf"|\bmake\s+sure\s+(?:to\s+|you\s+)|\bbe\s+sure\s+to\s+)"
        rf"{MODIFY_VERB_RE}[^\n,]{{0,80}}?{file_alt}\b"
    )


def _content_contract_re(file_alt: str) -> str:
    return rf"{file_alt}\b[^\n]{{0,40}}?\b(?:should|must|needs?\s+to)\s+(?:contain|say|include|have|list)\b"


_NO_TRANSFER = (
    r"(?!(?:\w+\s+){0,4}?(?:never|not|no|doesn\'?t|didn\'?t|won\'?t|isn\'?t|aren\'?t|can\'?t|cannot|mustn\'?t|shouldn\'?t)\b)"
)
_SHORT_FILLER = r"(?:\w+\s+){0,3}?"
_NOT_DELEGATE = (
    r"(?!(?:(?:the|your|each|every|all|to|a)\s+)?(?:sub-?agents?|sub-?tasks?)\b"
    r"|(?:(?:the|your|each|every|all|to|a)\s+)(?:workers?|delegates?|children|child)\b)"
)
_CTX_SCOPE = (
    r"(?:your|their|our|its|the\s+(?:full|entire|whole|complete|current)"
    r"|full|entire|whole|complete|current|conversation|session|chat)\s+"
)
_CTX_DEST = r"(?:\s+(?:to|at|with)\b)"
_CTX_DATIVE = r"(?:[a-z]+s\s+)(?:the|a|an)\s+context\b"
_SHELL_NAMES_RE = r"(?:bash|sh|zsh|ksh|dash)\b"
_SUDO_PREFIX = r"(?:sudo\s+(?:-\S+\s+)*)?"
_CRED_FILE = r"(?:\.ssh[/\\]id_(?:rsa|ed25519|ecdsa|dsa)(?!\.pub)|\.env\b|credentials\b|\.netrc\b|\.pgpass\b|\.npmrc\b|\.pypirc\b)"
_CRED_FILE_LITERAL = r"[\"'][^\"'\n]*" + _CRED_FILE + r"[^\"'\n]*[\"']"
_PY_CRED_FILE_ARG = r"(?:os\.path\.expanduser\s*\(\s*)?" + _CRED_FILE_LITERAL + r"\s*\)?"

THREAT_PATTERNS: List[Tuple[str, str, str, str, str, str]] = [
    # (regex, pattern_id, severity, category, reason, remediation)
    (
        r"curl\s+(?![^\n]*https?://(?:localhost|127\.0\.0\.1|\[::1\]))[^\n]*\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)S?\b",
        "env_exfil_curl", "critical", "exfiltration",
        "curl command interpolating secret environment variable to external host",
        "Remove secret interpolation in outbound curl commands.",
    ),
    (
        r"wget\s+(?![^\n]*https?://(?:localhost|127\.0\.0\.1|\[::1\]))[^\n]*\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)S?\b",
        "env_exfil_wget", "critical", "exfiltration",
        "wget command interpolating secret environment variable to external host",
        "Remove secret interpolation in outbound wget commands.",
    ),
    (
        r"fetch\s*\((?![^\n]*https?://(?:localhost|127\.0\.0\.1|\[::1\]))[^\n]*\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD)S?\b",
        "env_exfil_fetch", "critical", "exfiltration",
        "fetch() call interpolating secret environment variable",
        "Do not pass secret variables into outbound fetch URLs/payloads.",
    ),
    (
        r"httpx?\.(get|post|put|patch)\s*\((?![^\n]*https?://(?:localhost|127\.0\.0\.1|\[::1\]))[^\n]*(KEY|TOKEN|SECRET|PASSWORD)",
        "env_exfil_httpx", "critical", "exfiltration",
        "HTTP client call transmitting secret variable",
        "Ensure credentials are only passed via documented secure auth headers to verified endpoints.",
    ),
    (
        r"requests\.(get|post|put|patch)\s*\((?![^\n]*https?://(?:localhost|127\.0\.0\.1|\[::1\]))[^\n]*(KEY|TOKEN|SECRET|PASSWORD)",
        "env_exfil_requests", "critical", "exfiltration",
        "requests library call transmitting secret variable",
        "Remove secret variables from outbound requests calls.",
    ),
    (
        r"base64[^\n]*env",
        "encoded_exfil", "high", "exfiltration",
        "base64 encoding combined with environment access",
        "Audit base64 encoding of environment variables.",
    ),
    (
        r"\$HOME/\.ssh|\~/\.ssh",
        "ssh_dir_access", "high", "exfiltration",
        "References user SSH directory (~/.ssh)",
        "Remove references to ~/.ssh.",
    ),
    (
        r"\$HOME/\.aws|\~/\.aws",
        "aws_dir_access", "high", "exfiltration",
        "References user AWS credentials directory (~/.aws)",
        "Use standard AWS SDK environment flows rather than reading ~/.aws directly.",
    ),
    (
        r"\$HOME/\.gnupg|\~/\.gnupg",
        "gpg_dir_access", "high", "exfiltration",
        "References user GPG keyring (~/.gnupg)",
        "Remove direct access to ~/.gnupg.",
    ),
    (
        r"\$HOME/\.kube|\~/\.kube",
        "kube_dir_access", "high", "exfiltration",
        "References Kubernetes config directory (~/.kube)",
        "Review ~/.kube access requirements.",
    ),
    (
        r"\$HOME/\.hermes/\.env|\~/\.hermes/\.env",
        "hermes_env_access", "critical", "exfiltration",
        "Directly references Hermes secrets file (~/.hermes/.env)",
        "Never read ~/.hermes/.env directly.",
    ),
    (
        r"cat\s+(?!>)[^\n]*(\.env|credentials|\.netrc|\.pgpass|\.npmrc|\.pypirc)",
        "read_secrets_file", "critical", "exfiltration",
        "Reads known credential/secrets file via cat",
        "Do not read credential stores or .env files into output.",
    ),
    (
        r"\b(?:readFile(?:Sync)?|readTextFile)\s*\(\s*" + _CRED_FILE_LITERAL,
        "js_read_secrets_file", "critical", "exfiltration",
        "JavaScript reads a known credential file",
        "Remove direct file reads on credential files.",
    ),
    (
        r"\bopen\s*\(\s*" + _PY_CRED_FILE_ARG
        + r"(?!\s*\)?\s*,\s*[\"'][^\"']*[wax][^\"']*[\"'])(?![^\n]*\bmode\s*=\s*[\"'][^\"']*[wax])"
        + r"|\bPath\s*\(\s*" + _PY_CRED_FILE_ARG + r"\s*\)\.(?:read_text|read_bytes|readlines|readline)\s*\(",
        "py_read_secrets_file", "critical", "exfiltration",
        "Python reads a known credential file",
        "Remove Python file reads targeting credential files.",
    ),
    (
        r"printenv|(?<![A-Za-z0-9_])env\s*\|(?!\|)(?!\s*[{(])",
        "dump_all_env", "high", "exfiltration",
        "Dumps all environment variables",
        "Access only specific required variables instead of dumping all environment variables.",
    ),
    (
        r"^[^#\n]*os\.environ\b(?!\s*\.get\s*\()",
        "python_os_environ", "high", "exfiltration",
        "Accesses os.environ dict directly (potential full environment dump)",
        "Use os.environ.get('SPECIFIC_KEY') instead of iterating os.environ.",
    ),
    (
        r"(?<![-/])\b(?:dig|nslookup)\s+(?:[-+@]\S*(?:\s+[^\s$\"'-][^\s$]*)?\s+)*[\"']?[^\s\"'$()]*"
        r"\$(?:\{[^}\s]*\}|\([^\n]*?\)+|\w+)[\w-]*[\"']?\.[a-z]",
        "dns_exfil", "critical", "exfiltration",
        "DNS lookup with variable interpolation in domain name (DNS exfiltration)",
        "Remove variable interpolation inside DNS query domain names.",
    ),
    (
        r">\s*/tmp/[^\s]*\s*&&\s*(curl|wget|nc|python)",
        "tmp_staging", "critical", "exfiltration",
        "Writes to /tmp then immediately invokes network/interpreter command",
        "Remove /tmp staging and exfiltration chain.",
    ),
    (
        r"!\[.*\]\(https?://[^\)]*\$\{?",
        "md_image_exfil", "high", "exfiltration",
        "Markdown image URL with variable interpolation (image beacon exfiltration)",
        "Use static trusted image URLs without variable interpolation.",
    ),
    # Prompt Injection & Deception
    (
        r"ignore\s+(?:\w+\s+)*(previous|all|above|prior)\s+instructions",
        "prompt_injection_ignore", "critical", "injection",
        "Prompt injection attempting to ignore previous instructions",
        "Remove instruction override directives.",
    ),
    (
        r"you\s+are\s+(?:\w+\s+)*now\s+(?:in\s+)?(?:unrestricted|root|admin|god|dan)\b",
        "role_hijack", "critical", "injection",
        "Attempts to hijack the agent's role into an unrestricted mode",
        "Remove role hijack phrasing.",
    ),
    (
        r"do\s+not\s+(?:\w+\s+)*tell\s+(?:\w+\s+)*the\s+user(?!\s+to\s+[\"'\u201c\u2018])"
        r"(?!.*\b(?:unless|except|until|confirm|diagnos\w*|verify|check)\b)",
        "deception_hide", "high", "injection",
        "Instructs the agent to conceal actions or information from the user",
        "Remove concealment/deception instructions.",
    ),
    (
        r"system\s+(?:\w+\s+)*prompt\s+(?:\w+\s+)*override",
        "sys_prompt_override", "critical", "injection",
        "Attempts to override the system prompt",
        "Remove system prompt override text.",
    ),
    (
        r"disregard\s+(?:\w+\s+)*(your|all|any)\s+(?:\w+\s+)*(instructions|rules|guidelines)",
        "disregard_rules", "critical", "injection",
        "Instructs agent to disregard safety rules or guidelines",
        "Remove rule-disregard instructions.",
    ),
    (
        r"output\s+(?:\w+\s+)*(system|initial)\s+prompt",
        "leak_system_prompt", "high", "injection",
        "Attempts to extract the system prompt",
        "Remove system prompt extraction instructions.",
    ),
    (
        r"act\s+as\s+(if|though)\s+(?:\w+\s+)*you\s+(?:\w+\s+)*(have\s+no|don\'t\s+have)\s+(?:\w+\s+)*(restrictions|limits|rules)",
        "bypass_restrictions", "critical", "injection",
        "Instructs agent to act without restrictions",
        "Remove restriction-bypass instructions.",
    ),
    (
        r"<!--[^>]*(?:\b(?:ignore|forget|disregard|override)\s+(?:\w+\s+)*?"
        r"(?:previous|prior|above|earlier|all|any|your|the)\s+(?:\w+\s+)*?"
        r"(?:instructions?|rules|prompts?|guidelines|directions|restrictions)"
        r"|\bsystem\s*(?:prompt|message|instructions?|override)|\b(?:override|secret|hidden|system)\s*:"
        r"|\b(?:ignore|override|bypass|disable)\s+(?:\w+\s+)*?(?:safety|security|guardrails|filters)\b"
        r"|\b(?:secret|hidden|new)\s+(?:instructions?|commands?|directives?|tasks?)\b|\byou\s+are\s+now\b"
        r"|\bdo\s+not\s+(?:tell|reveal|show|mention|inform)\b)[^>]*-->",
        "html_comment_injection", "critical", "injection",
        "Hidden prompt injection instructions inside HTML comments",
        "Remove hidden directives in HTML comments.",
    ),
    (
        r"<\s*div\s+style\s*=\s*[\"'][\s\S]*?display\s*:\s*none",
        "hidden_div", "high", "injection",
        "Hidden HTML div with display:none",
        "Remove hidden HTML elements.",
    ),
    (
        r"\bDAN\s+mode\b|Do\s+Anything\s+Now",
        "jailbreak_dan", "critical", "injection",
        "DAN (Do Anything Now) jailbreak attempt",
        "Remove jailbreak payload.",
    ),
    # Destructive operations
    (
        r"rm\s+-rf\s+((?:[^\s;&|<>#][^\s;&|<>]*\s+)+?)?/(?(1)(?!/(?:\s|$)))(?:"
        r"(?!(?:tmp|var/tmp|dev/shm|run|var/lib/apt/lists|var/cache/(?:apt|apk|yum|dnf))(?:\b|/))"
        r"|(?:tmp|var/tmp|dev/shm|run|var/lib/apt/lists|var/cache/(?:apt|apk|yum|dnf))/(?:[^/\s]*/)*\.\.(?=/|[\s;&|]|$))",
        "destructive_root_rm", "critical", "destructive",
        "Recursive delete targeting root or system directories",
        "Scope deletions strictly to temporary or build subdirectories.",
    ),
    (
        r"(?<![A-Za-z0-9])rm\s+(-[^\s]*)?r.*(?:\$HOME|~[/\s*]|~$)|(?<![A-Za-z0-9])rmdir\s+.*(?:\$HOME|~[/\s*]|~$)",
        "destructive_home_rm", "critical", "destructive",
        "Recursive delete targeting user home directory ($HOME or ~)",
        "Never recursively delete $HOME or ~.",
    ),
    (
        r">\s*/etc/|\bmkfs\b|\bdd\s+.*if=.*of=/dev/|truncate\s+-s\s*0\s+/",
        "destructive_system", "critical", "destructive",
        "Destructive system file overwrite or disk format command",
        "Remove destructive system/device commands.",
    ),
    (
        r"shutil\.rmtree\s*\(\s*[\"'/]",
        "python_rmtree_root", "high", "destructive",
        "Python shutil.rmtree on absolute or root-relative path",
        "Validate and scope paths before calling shutil.rmtree.",
    ),
    # Persistence & Config modification
    (
        r"authorized_keys",
        "ssh_backdoor", "critical", "persistence",
        "References or modifies SSH authorized_keys",
        "Remove SSH authorized_keys manipulation.",
    ),
    (
        r"/etc/sudoers|visudo|NOPASSWD",
        "sudoers_mod", "critical", "persistence",
        "Modifies sudoers or configures passwordless privilege escalation",
        "Remove sudoers modifications.",
    ),
    (
        _prose_modify_re(_AGENT_CONFIG_FILES),
        "agent_config_mod", "critical", "persistence",
        "Instructs modification of agent configuration files (AGENTS.md, CLAUDE.md, opencode.json, .mcp.json)",
        "Do not instruct the agent to silently alter its own configuration files.",
    ),
    (
        _shell_write_re(_AGENT_CONFIG_FILES),
        "agent_config_mod_shell", "critical", "persistence",
        "Shell write targeting agent configuration files",
        "Remove shell redirects/writes into agent config files.",
    ),
    (
        _content_contract_re(_AGENT_CONFIG_FILES),
        "agent_config_contract", "high", "persistence",
        "Dictates agent configuration file contents",
        "Review whether modifying agent config is expected by the user.",
    ),
    (
        _shell_write_re(_OTHER_AGENT_CONFIG_FILES),
        "other_agent_config_mod_shell", "critical", "persistence",
        "Shell write targeting `.claude/settings` or `.codex/config`",
        "Do not modify native client settings via shell scripts.",
    ),
    # Network & Reverse Shells
    (
        r"\bnc\s+-[lp]|ncat\s+-[lp]|\bsocat\b[^\n]*\b(?:tcp|udp|openssl|ssl|exec|system|pty|unix)[\w-]*:",
        "reverse_shell", "critical", "network",
        "Reverse shell or network listener command",
        "Remove netcat/socat shell listeners.",
    ),
    (
        rf"/bin/{_SHELL_NAMES_RE}\s+-i\s+.*>/dev/tcp/",
        "bash_reverse_shell", "critical", "network",
        "Interactive bash reverse shell via /dev/tcp",
        "Remove /dev/tcp reverse shell.",
    ),
    (
        r"python[23]?\s+-c\s+[\"']import\s+socket",
        "python_socket_oneliner", "critical", "network",
        "Python one-liner socket connection (typical reverse shell)",
        "Remove inline socket reverse shell.",
    ),
    (
        r"webhook\.site|requestbin\.com|pipedream\.net|hookbin\.com",
        "exfil_service", "high", "network",
        "References known data exfiltration/webhook capture service",
        "Remove webhook capture domain.",
    ),
    # Obfuscation & Unsafe Execution
    (
        r"(?:\bbase64\s+(?:-[^\s|]+\s+)*?(?:-[a-z]*d[a-z]*|--decode)\b|\bopenssl\s+(?:base64|enc)\b[^|;&\n]*?\s-d\b)"
        r"[^\n]*?(?:\||;|&&)\s*(?:\w+=\S*\s+)*(?:\S*/)?"
        r"(?:sh|bash|zsh|ksh|dash|fish|python[\d.]*|perl|ruby|node|nodejs|php|eval|source|exec|xargs|env|sudo"
        r"|iex|pwsh|powershell|tar|bsdtar|unzip)(?![\w.-])",
        "base64_decode_pipe", "critical", "obfuscation",
        "Base64 payload decoded and piped directly to shell/interpreter",
        "Do not pipe base64-decoded strings to an interpreter.",
    ),
    (
        rf"echo\s+[^\n]*\|\s*(?:{_SHELL_NAMES_RE}|python|perl|ruby|node)",
        "echo_pipe_exec", "critical", "obfuscation",
        "Echo piped directly to interpreter for execution",
        "Replace piped execution with clear, inspectable scripts.",
    ),
    (
        r"getattr\s*\(\s*__builtins__|__import__\s*\(\s*[\"']os[\"']\s*\)",
        "python_builtins_evasion", "high", "obfuscation",
        "Dynamic access to Python __builtins__ or __import__('os')",
        "Use standard top-level imports.",
    ),
    (
        r"!`[^`\s][^`\n]*`",
        "inline_shell_exec", "high", "execution",
        "Inline-shell auto-execution snippet (!`cmd`) in skill markdown",
        "Inspect inline shell command before enabling dynamic context injection.",
    ),
    # Supply Chain
    (
        rf"curl\s+[^|\s][^\n]*\|\s*{_SUDO_PREFIX}{_SHELL_NAMES_RE}",
        "curl_pipe_shell", "critical", "supply_chain",
        "curl piped directly to shell (unverified download-and-execute)",
        "Download artifacts, verify checksums, and inspect before execution.",
    ),
    (
        rf"wget\s+[^\n]*-O\s*-\s*\|\s*{_SUDO_PREFIX}{_SHELL_NAMES_RE}",
        "wget_pipe_shell", "critical", "supply_chain",
        "wget piped directly to shell (unverified download-and-execute)",
        "Download artifacts and verify checksums before execution.",
    ),
    (
        r"pip\s+install\s+(?!-r\s)(?!.*==)",
        "unpinned_pip_install", "medium", "supply_chain",
        "Unpinned pip install command",
        "Pin package versions with == for reproducible and safe dependency resolution.",
    ),
    # Traversal
    (
        r"\.\./\.\./\.\.",
        "path_traversal_deep", "high", "traversal",
        "Deep relative path traversal (../../../)",
        "Keep file paths within the extension root directory.",
    ),
    (
        r"/etc/passwd|/etc/shadow",
        "system_passwd_access", "critical", "traversal",
        "References /etc/passwd or /etc/shadow",
        "Remove system password file references.",
    ),
    # Embedded Credentials
    (
        r"(?-i:-----BEGIN\s+(RSA\s+|OPENSSH\s+|EC\s+)?PRIVATE\s+KEY-----)",
        "embedded_private_key", "critical", "credential_exposure",
        "Embedded cryptographic private key in extension file",
        "Remove embedded private keys immediately.",
    ),
    (
        r"(?-i:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,}|sk-ant-[A-Za-z0-9_-]{40,}|AKIA[0-9A-Z]{16})",
        "leaked_api_token", "critical", "credential_exposure",
        "Hardcoded provider API token or access key detected",
        "Replace hardcoded tokens with environment variable references.",
    ),
    # Context Exfiltration
    (
        rf"\b(?:include|output|print|send|share)\s+{_NO_TRANSFER}{_SHORT_FILLER}(?:conversation|chat\s+history|previous\s+messages)\b"
        rf"|\b(?:print|send|share|output|upload|transmit)\s+{_NO_TRANSFER}{_NOT_DELEGATE}"
        rf"(?:(?:\w+\s+){{0,2}}?{_CTX_SCOPE}(?:\w+\s+){{0,2}}?context\b|(?:\w+\s+){{0,3}}?context\b{_CTX_DEST}|{_CTX_DATIVE})",
        "context_exfil", "high", "exfiltration",
        "Instructs agent to exfiltrate or transmit conversation history/context",
        "Remove conversation history transmission directives.",
    ),
]

COMPILED_THREAT_PATTERNS = [
    (re.compile(pat, re.IGNORECASE | re.MULTILINE), pid, sev, cat, reason, rem)
    for pat, pid, sev, cat, reason, rem in THREAT_PATTERNS
]

PATH_REFERENCE_PATTERN_IDS = frozenset({
    "ssh_dir_access", "aws_dir_access", "gpg_dir_access", "kube_dir_access",
    "ssh_backdoor", "system_passwd_access",
})
COMMENT_PREFIX = {
    ".py": ("#",), ".sh": ("#",), ".bash": ("#",), ".rb": ("#",), ".yaml": ("#",), ".yml": ("#",),
    ".toml": ("#",), ".js": ("//",), ".ts": ("//",),
}
DENYLIST_OWNER_RE = re.compile(
    r"^\s*(?:(?:const|let|var|export)\s+)?[\w.\-]*(?:deny|black|block|skip|exclu|ignor|forbid|refus|reject|never"
    r"|unsafe|sensitive|secret_?file|redact)[\w.\-]*\s*(?::[^=]*?)?(?:=|:\s*(?:$|[\[({]))",
    re.IGNORECASE,
)
ACTION_ON_LINE_RE = re.compile(
    r"\b(?:cat|less|more|head|tail|cp|mv|rm|scp|rsync|curl|wget|tee|chmod|chown|(?<![./\w])ssh|sudo|install|source|eval|exec"
    r"|system|popen|run|check_output|copyfile|copy2|sendfile)\b|\.(?:read|write|open|unlink|copy|append)\w*\s*\("
    r"|\bopen\s*\(|readFileSync|writeFileSync|appendFileSync|>>",
    re.IGNORECASE,
)

# MCP Server Security IOCs & Egress Checks (from Hermes mcp_security.py)
MCP_SHELL_INTERPRETERS = frozenset({
    "bash", "sh", "zsh", "dash", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
})
MCP_EGRESS_RE = re.compile(
    r"(?<![\w.-])(?:curl|wget|nc|ncat|socat)(?![\w.-])|/dev/tcp/|\bInvoke-WebRequest\b|\bInvoke-RestMethod\b",
    re.IGNORECASE,
)
MCP_PERSISTENCE_RE = re.compile(
    r"authorized_keys|\.ssh/|/etc/ssh\b|/etc/pam\.d\b|/etc/sudoers|/etc/cron|crontab\b|/etc/systemd|\.bashrc\b|\.zshrc\b",
    re.IGNORECASE,
)
MCP_IOC_SUBSTRINGS = (
    "AAAAC3NzaC1lZDI1NTE5AAAAICBoh1oDC4DnsO1m5mJ4yfEKrQebaFh",
    "hermes-0day",
    "60.165.167.",
    "118.182.244.156",
    "61.178.23.196",
)


def _compute_docstring_lines(lines: List[str]) -> set[int]:
    doc_lines: set[int] = set()
    inside = False
    for i, line in enumerate(lines, start=1):
        was_in = inside
        counts = [line.count(m) for m in ('"""', "'''")]
        inside ^= sum(counts) % 2 == 1
        if was_in or inside or any(counts):
            doc_lines.add(i)
    return doc_lines


def _mask_markdown_links(line: str) -> str:
    masked = list(line)
    search_from = 0
    while (start := line.find("](", search_from)) != -1:
        depth = 1
        escaped = False
        cursor = start + 2
        while cursor < len(line):
            ch = line[cursor]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    masked[start + 2 : cursor] = " " * (cursor - start - 2)
                    search_from = cursor + 1
                    break
            cursor += 1
        else:
            break
    return "".join(masked)


def scan_text_content(content: str, rel_path: str) -> List[SecurityFinding]:
    """Scan a single file's text content for security threats and invisible Unicode characters."""
    findings: List[SecurityFinding] = []
    lines = content.split("\n")
    suffix = Path(rel_path).suffix.lower()
    docstring_lines = _compute_docstring_lines(lines) if suffix == ".py" else set()
    is_md = suffix == ".md" or Path(rel_path).name == "SKILL.md"

    if Path(rel_path).name == "SKILL.md":
        fm, _ = parse_skill_md(content)
        if "_invalid_frontmatter" in fm:
            findings.append(
                SecurityFinding(
                    pattern_id="corrupted_frontmatter",
                    severity="high",
                    category="structural",
                    file=rel_path,
                    line=1,
                    match=str(fm["_invalid_frontmatter"])[:100],
                    reason=f"Corrupted or invalid SKILL.md YAML frontmatter: {fm['_invalid_frontmatter']}",
                    remediation="Fix YAML syntax in SKILL.md frontmatter.",
                )
            )

    for pattern, pid, severity, category, reason, remediation in COMPILED_THREAT_PATTERNS:
        for i, line in enumerate(lines, start=1):
            if i in docstring_lines and category != "injection":
                continue
            scan_line = _mask_markdown_links(line) if (is_md and pid == "path_traversal_deep") else line
            if pattern.search(scan_line):
                eff_sev = severity
                eff_reason = reason
                if pid in PATH_REFERENCE_PATTERN_IDS:
                    if line.lstrip().startswith(COMMENT_PREFIX.get(suffix, ())):
                        eff_sev = "low"
                        eff_reason = f"{reason} (in comment; informational)"
                    elif DENYLIST_OWNER_RE.match(line) and not ACTION_ON_LINE_RE.search(line):
                        eff_sev = "low"
                        eff_reason = f"{reason} (in denylist/filter pattern; informational)"
                snippet = line.strip()
                findings.append(
                    SecurityFinding(
                        pattern_id=pid,
                        severity=eff_sev,
                        category=category,
                        file=rel_path,
                        line=i,
                        match=snippet if len(snippet) <= 120 else snippet[:117] + "...",
                        reason=eff_reason,
                        remediation=remediation,
                    )
                )

    for i, line in enumerate(lines, start=1):
        for ch in line:
            if ch in INVISIBLE_CHARS and not (i == 1 and ch == "\ufeff"):
                cname = INVISIBLE_CHAR_NAMES.get(ch, f"U+{ord(ch):04X}")
                findings.append(
                    SecurityFinding(
                        pattern_id="invisible_unicode",
                        severity="high",
                        category="injection",
                        file=rel_path,
                        line=i,
                        match=f"U+{ord(ch):04X} ({cname})",
                        reason=f"Invisible or bidirectional Unicode character ({cname}) detected (potential text hiding)",
                        remediation="Strip zero-width and bidirectional override Unicode characters.",
                    )
                )
                break

    return findings


def scan_mcp_transport(name: str, transport: MCPTransportSpec) -> List[SecurityFinding]:
    """Inspect an MCP server transport configuration for malicious launch commands, IOCs, or shell egress."""
    findings: List[SecurityFinding] = []
    flat_parts = [str(transport.command or ""), " ".join(str(a) for a in transport.args), str(transport.url or "")]
    for k, v in (transport.env or {}).items():
        flat_parts.append(f"{k}={v}")
    flat_text = " ".join(flat_parts)

    for ioc in MCP_IOC_SUBSTRINGS:
        if ioc in flat_text:
            findings.append(
                SecurityFinding(
                    pattern_id="mcp_known_ioc",
                    severity="critical",
                    category="supply_chain",
                    file="mcp_transport",
                    line=1,
                    match=ioc[:60],
                    reason=f"MCP server '{name}' contains a known indicator-of-compromise ('{ioc}')",
                    remediation="Do not install or run this MCP server.",
                )
            )

    cmd_str = str(transport.command or "").strip()
    if cmd_str:
        try:
            parts = shlex.split(cmd_str, posix=(os.name != "nt"))
        except ValueError:
            parts = cmd_str.split()
        base_cmd = os.path.basename(parts[0]).lower() if parts else ""
        inline_script = " ".join(str(a) for a in transport.args)
        if base_cmd in MCP_SHELL_INTERPRETERS and inline_script:
            if MCP_EGRESS_RE.search(inline_script):
                findings.append(
                    SecurityFinding(
                        pattern_id="mcp_shell_egress",
                        severity="critical",
                        category="exfiltration",
                        file="mcp_transport",
                        line=1,
                        match=inline_script[:100],
                        reason=f"MCP server '{name}' invokes shell interpreter '{base_cmd}' with outbound network egress",
                        remediation="Use a dedicated MCP server package rather than an inline shell egress command.",
                    )
                )
            if MCP_PERSISTENCE_RE.search(inline_script):
                findings.append(
                    SecurityFinding(
                        pattern_id="mcp_shell_persistence",
                        severity="critical",
                        category="persistence",
                        file="mcp_transport",
                        line=1,
                        match=inline_script[:100],
                        reason=f"MCP server '{name}' modifies OS persistence surfaces via inline shell script",
                        remediation="Block MCP server modifying SSH/PAM/cron/shell startup files.",
                    )
                )

    for env_key, env_val in (transport.env or {}).items():
        if any(s in env_key.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD")) and env_val and not env_val.startswith(("${", "{env:")):
            if len(env_val) >= 16 and " " not in env_val:
                findings.append(
                    SecurityFinding(
                        pattern_id="mcp_hardcoded_credential",
                        severity="high",
                        category="credential_exposure",
                        file="mcp_transport.env",
                        line=1,
                        match=f"{env_key}=<redacted>",
                        reason=f"MCP environment variable '{env_key}' contains a literal credential value instead of an env reference",
                        remediation=f"Use ${{env:{env_key}}} or ${{{env_key}}} reference instead of embedding raw secrets.",
                    )
                )
    return findings


def determine_verdict(findings: List[SecurityFinding]) -> str:
    """Determine policy verdict (SAFE, CAUTION, DANGEROUS) from structured findings."""
    severities = {f.severity for f in findings}
    if "critical" in severities:
        return SecurityVerdict.DANGEROUS.value
    if "high" in severities:
        return SecurityVerdict.CAUTION.value
    return SecurityVerdict.SAFE.value


def scan_directory(
    directory: Path,
    *,
    extension_id: str = "",
    source: str = "community",
    trust_level: str = "community",
) -> SecurityAssessment:
    """Perform a full structural, regex pattern, and AST security scan on a local extension directory."""
    name = directory.name
    ext_id = extension_id or name
    findings: List[SecurityFinding] = []
    file_count = 0
    total_size = 0

    if not directory.exists():
        return SecurityAssessment(
            extension_id=ext_id,
            name=name,
            source=source,
            trust_level=trust_level,
            verdict=SecurityVerdict.UNKNOWN.value,
            policy_reason="Target path does not exist",
        )

    root_resolved = directory.resolve()
    for entry in sorted(directory.rglob("*")):
        rel = entry.relative_to(directory).as_posix()
        if rel.startswith(".git/") or "__pycache__" in rel.split("/"):
            continue
        if entry.is_symlink():
            file_count += 1
            try:
                target = entry.resolve()
                if not target.is_relative_to(root_resolved):
                    findings.append(
                        SecurityFinding(
                            pattern_id="symlink_escape",
                            severity="critical",
                            category="traversal",
                            file=rel,
                            line=0,
                            match=f"symlink -> {target}",
                            reason="Symlink points outside the extension root directory",
                            remediation="Remove symlinks pointing outside the skill bundle.",
                        )
                    )
            except OSError:
                findings.append(
                    SecurityFinding(
                        pattern_id="broken_symlink",
                        severity="medium",
                        category="traversal",
                        file=rel,
                        line=0,
                        match="broken symlink",
                        reason="Broken or circular symlink inside extension directory",
                    )
                )
            continue

        if not entry.is_file():
            continue
        file_count += 1
        try:
            st = entry.stat()
        except OSError:
            continue
        size = st.st_size
        total_size += size
        if size > MAX_SINGLE_FILE_KB * 1024:
            findings.append(
                SecurityFinding(
                    pattern_id="oversized_file",
                    severity="high" if size > 1024 * 1024 else "medium",
                    category="structural",
                    file=rel,
                    line=0,
                    match=f"{size // 1024}KB",
                    reason=f"File size ({size // 1024}KB) exceeds single-file inspection threshold ({MAX_SINGLE_FILE_KB}KB)",
                )
            )
        ext = entry.suffix.lower()
        if ext in SUSPICIOUS_BINARY_EXTENSIONS:
            findings.append(
                SecurityFinding(
                    pattern_id="binary_executable",
                    severity="critical",
                    category="structural",
                    file=rel,
                    line=0,
                    match=f"binary: {ext}",
                    reason=f"Suspicious compiled binary/executable ({ext}) inside skill bundle",
                    remediation="Skills must distribute inspectable text/scripts, not opaque compiled binaries.",
                )
            )
        if ext in SCANNABLE_EXTENSIONS or entry.name == "SKILL.md":
            try:
                text = entry.read_text(encoding="utf-8-sig")
                findings.extend(scan_text_content(text, rel))
            except (UnicodeDecodeError, OSError):
                pass

    if file_count > MAX_FILE_COUNT:
        findings.append(
            SecurityFinding(
                pattern_id="too_many_files",
                severity="medium",
                category="structural",
                file="(directory)",
                line=0,
                match=f"{file_count} files",
                reason=f"Extension contains {file_count} files (threshold: {MAX_FILE_COUNT})",
            )
        )

    ast_findings = ast_audit_directory(directory)
    verdict = determine_verdict(findings)
    c_hash = compute_directory_content_hash(directory)
    return SecurityAssessment(
        extension_id=ext_id,
        name=name,
        source=source,
        trust_level=trust_level,
        verdict=verdict,
        findings=findings,
        ast_findings=ast_findings,
        content_hash=c_hash,
        scanned_at=utc_now_iso(),
        scanner_version=SCANNER_VERSION,
    )


def scan_bundle(bundle: ExtensionBundle) -> SecurityAssessment:
    """Scan an in-memory ExtensionBundle without executing any code."""
    findings: List[SecurityFinding] = []
    ast_findings: List[Dict[str, Any]] = []
    total_size = 0

    for rel_path, content in sorted(bundle.files.items()):
        try:
            safe_rel = validate_bundle_rel_path(rel_path)
        except ValueError as exc:
            findings.append(
                SecurityFinding(
                    pattern_id="bundle_path_traversal",
                    severity="critical",
                    category="traversal",
                    file=str(rel_path),
                    line=0,
                    match=str(rel_path)[:80],
                    reason=f"Unsafe relative path in bundle: {exc}",
                    remediation="Reject archive/bundle containing path traversal or drive components.",
                )
            )
            continue

        raw_bytes = content if isinstance(content, bytes) else content.encode("utf-8")
        size = len(raw_bytes)
        total_size += size
        if size > MAX_SINGLE_FILE_KB * 1024:
            findings.append(
                SecurityFinding(
                    pattern_id="oversized_file",
                    severity="high" if size > 1024 * 1024 else "medium",
                    category="structural",
                    file=safe_rel,
                    line=0,
                    match=f"{size // 1024}KB",
                    reason=f"File size ({size // 1024}KB) exceeds {MAX_SINGLE_FILE_KB}KB limit",
                )
            )
        ext = Path(safe_rel).suffix.lower()
        if ext in SUSPICIOUS_BINARY_EXTENSIONS:
            findings.append(
                SecurityFinding(
                    pattern_id="binary_executable",
                    severity="critical",
                    category="structural",
                    file=safe_rel,
                    line=0,
                    match=f"binary: {ext}",
                    reason=f"Binary executable ({ext}) is prohibited in skill bundles",
                )
            )
            continue

        if isinstance(content, bytes):
            try:
                text = content.decode("utf-8-sig")
            except UnicodeDecodeError:
                continue
        else:
            text = content

        findings.extend(scan_text_content(text, safe_rel))
        if ext == ".py":
            ast_findings.extend(scan_python_ast(text, safe_rel))

    if bundle.record and bundle.record.mcp_transport:
        findings.extend(scan_mcp_transport(bundle.name, bundle.record.mcp_transport))

    verdict = determine_verdict(findings) if (bundle.files or (bundle.record and bundle.record.mcp_transport)) else SecurityVerdict.UNKNOWN.value
    c_hash = bundle.content_hash or compute_bundle_content_hash(bundle.files)
    return SecurityAssessment(
        extension_id=bundle.extension_id,
        name=bundle.name,
        source=bundle.source_provider,
        trust_level=bundle.trust_level,
        verdict=verdict,
        findings=findings,
        ast_findings=ast_findings,
        content_hash=c_hash,
        scanned_at=utc_now_iso(),
        scanner_version=SCANNER_VERSION,
    )
