# SkillBridge Security Threat Model, Scanning Pipeline & Trust Policy

## 1. Threat Model

AI coding agents operate with high privileges: they read local source code, execute shell commands, access environment variables, and interact with Git and cloud APIs. Third-party extensions (skills, subagents, and MCP servers) introduce four primary attack vectors:

1. **Indirect Prompt Injection & Instruction Hijacking**:
   - Malicious `SKILL.md` files or reference documents containing instructions to ignore system prompts (`ignore previous instructions`), impersonate system/developer roles, or conceal actions from the user (`do not tell the user`, Unicode zero-width invisible characters `U+200B`–`U+200F`, `U+E0000` tag characters, or HTML comment payloads `<!-- ignore ... -->`).
2. **Credential Harvesting & Exfiltration**:
   - Skills or scripts reading `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.claude.json`, `~/.hermes/.env`, or harvesting environment secrets (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`) and sending them to external webhooks (`curl -d @$HOME/.env`, `ngrok`, `webhook.site`, `dnslog`).
3. **Destructive Execution, Obfuscation & Persistence**:
   - Scripts executing `rm -rf /`, `mkfs`, `curl ... | sh`, base64-encoded execution stubs, Python `eval(compile(...))`, modifying `~/.bashrc`, installing `crontab` entries, systemd units, or macOS LaunchAgents, or overwriting `.claude/settings.json` / `AGENTS.md` to disable permission checks (`--dangerously-skip-permissions`).
4. **Supply-Chain, Archive & MCP Transport Attacks**:
   - Malicious MCP packages (e.g., `mcp-remote` CVE-2025-6514 command injection, `postmark-mcp` bcc exfiltration), zip-slip path traversal (`../../etc/passwd`), symlink escapes outside the skill directory, or SSRF redirects targeting loopback (`127.0.0.1`) or cloud metadata (`169.254.169.254`).

---

## 2. Multi-Layer Security Review Pipeline

SkillBridge inspects **all** files in an extension package (`SKILL.md`, markdown references, `.py`, `.sh`, `.ps1`, `.js`, `.ts`, `.json`, `.toml`) without ever executing third-party code during discovery or preview:

### Layer 1: Filesystem, Symlink & Archive Containment
- **Path Traversal Guard**: Every relative path in `SKILL.md` or archive entries is resolved via `Path.resolve()` and verified with `relative_to(skill_root)`. Escapes produce `CRITICAL` findings (`path_escape_outside_root`).
- **Symlink Escape Guard**: Symlinks pointing outside the skill root (`symlink_escape`) are immediately flagged as `CRITICAL`.
- **Safe ZIP Stream Extraction**: `ClawHubProvider` inspects every `ZipInfo` entry before extraction, blocking `..` segments, absolute paths, POSIX symlink modes (`0o120000`), files exceeding `max_file_bytes`, and total uncompressed sizes exceeding `10 MB` (zip-bomb protection).
- **SSRF & Redirect Guard**: `validate_safe_url()` blocks `file://`, `ftp://`, `gopher://`, loopback addresses (`localhost`, `127.0.0.0/8`), private RFC 1918 networks, and cloud metadata IPs (`169.254.169.254`) on both initial requests and HTTP redirects (`_SafeRedirectHandler`).

### Layer 2: 60+ Static Threat Signatures (`security/scanner.py`)
Adapted and expanded from Hermes `tools/skills_guard.py` and `tools/mcp_security.py`, covering 12 threat categories:
- `exfiltration`: `env_Dump`, `credential_harvest`, `silent_exfil_curl`, `exfil_wget`, `python_net_secret`, `webhook_exfil`, `encoded_exfil`, `dns_tunnel`, `env_full_iteration`.
- `prompt_injection`: `ignore_previous_instructions`, `system_role_override`, `disregard_rules`, `act_without_restrictions`, `deception_hide_from_user`, `html_comment_injection`, `Hidden_div_injection`, `translate_execute_injection`, `sys_prompt_leak`, `context_smuggling`.
- `concealment`: Invisible Unicode zero-width spaces, directional overrides, BOM abuse, and Unicode Tag characters (`U+E0001`–`U+E007F`).
- `credential_harvesting`: Direct access to `.ssh/id_*`, `.aws/credentials`, `.kube/config`, `.pgpass`, `.netrc`, macOS Keychain (`security find-generic-password`).
- `destructive`: `rm_rf_root_or_home`, `chmod_777`, `mkfs_format`, `dd_raw_disk`, `sql_drop_truncate`, `shutil_rmtree_var`.
- `persistence`: `authorized_keys_inject`, `crontab_modify`, `shell_rc_mod`, `git_hooks_inject`, `systemd_service_persist`, `launchagents_persist`, `ld_preload_hijack`, `pam_backdoor`, `sudoers_nopasswd`.
- `obfuscation`: `base64_decode_pipe_exec`, `hex_array_payload`, `char_code_reconstruction`, `eval_compile_exec`, `marshal_loads_exec`, `zlib_decompress_exec`.
- `unsafe_download`: `curl_pipe_sh`, `wget_pipe_sh`, `urllib_exec_remote`, `powershell_iex_download`.
- `dependency_attack`: `pip_install_untrusted_index`, `pip_install_git_url`, `npm_install_ignore_scripts_false`.
- `permission_weakening`: `agent_config_mod`, `hermes_config_mod`, `claude_skip_permissions`, `git_config_global_exec`, `tls_verify_disabled`.
- `mcp_security`: Known malicious MCP package IOCs (`postmark-mcp`, `mcp-remote`, `lotus-ai-mcp`), dangerous interpreter commands (`bash -c`, `python -c`), shell chaining (`&&`, `;`, `|`, `` ` ``) in MCP args, and sensitive env var pass-through (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, etc.).

### Layer 3: Deep Python AST Security Auditor (`security/ast_audit.py`)
For every `.py` script inside a skill directory, `PythonASTSecurityAuditor` parses the syntax tree using Python's `ast` module and detects:
- Dynamic code execution (`eval()`, `exec()`, `compile()`, `__import__()`).
- Deserialization sinks (`pickle.loads()`, `marshal.loads()`, `yaml.load()` without `SafeLoader`).
- Subprocess execution with `shell=True`.
- Intra-file taint combinations where both credential/env harvesting (`os.environ`, `.ssh`) and outbound network sinks (`urllib.request.urlopen`, `httpx`, `requests`, `socket`) appear in the same module (`ast_combined_env_and_network_exfil`, `CRITICAL`).
- Obfuscated nested call chains such as `exec(base64.b64decode(...))` (`ast_obfuscated_exec_b64decode`, `CRITICAL`).

### Layer 4: Context-Aware Demotion for False-Positive Reduction
To avoid penalizing legitimate documentation or defensive security skills:
- Path references inside markdown prose (`SKILL.md`) are only flagged at `HIGH`/`CRITICAL` severity if an executable action keyword (`cat`, `curl`, `read`, `open`, `scp`) appears on the same line; otherwise they are demoted to `LOW`.
- String assignments inside static constant lists (`DENYLIST = ['~/.ssh', ...]`), comments, or regex definitions (`re.compile(...)`) are demoted to `LOW` so benign security scanners are not blocked.

---

## 3. Policy Verdict Matrix (`security/policy.py`)

Based on both the findings and the extension's **Trust Level** (`BUILTIN`, `TRUSTED`, `COMMUNITY`, `UNTRUSTED`), `evaluate_policy_decision()` computes the final verdict:

| Verdict | Criteria | Installation & Runtime Loading Behavior |
| :--- | :--- | :--- |
| **`SAFE`** | Zero `CRITICAL` or `HIGH` findings (and for `UNTRUSTED` sources, zero `MEDIUM` findings). | Permitted for runtime loading and native installation. |
| **`CAUTION`** | At least one `HIGH` finding (on a `TRUSTED`/`BUILTIN` source) or `MEDIUM` finding, with zero `CRITICAL` findings. | Permitted for runtime preview/loading with explicit warnings; native installation requires explicit user approval (`approve=True`). |
| **`DANGEROUS`** | Any `CRITICAL` finding, or any `HIGH` finding on a `COMMUNITY` / `UNTRUSTED` extension. | **Hard-blocked (`allowed=False`, `can_override=False`)**. Even passing `approve=True` or `--force` raises `SecurityBlockedError`. Quarantined automatically. |
| **`UNKNOWN`** | Unreadable files, missing source directory, or corrupted manifest. | Blocked from installation until source integrity is established. |

---

## 4. Limitations of Static Analysis

Static pattern matching and AST inspection provide strong defense-in-depth against known prompt injection templates, shell backdoors, and credential stealers, but **cannot guarantee that arbitrary third-party code is benign** (Rice's theorem). Attackers may use novel semantic phrasing, multi-step logic split across benign-looking helper functions, or external API responses that dynamically inject instructions at runtime. Therefore:
1. SkillBridge never executes scripts during discovery, preview, or loading.
2. Users must explicitly approve (`--approve`) any extension that alters native client configurations or carries a `CAUTION` verdict.
3. Sensitive environment variables and tokens are automatically redacted from all logs and audit trails via `redact_secrets()`.
