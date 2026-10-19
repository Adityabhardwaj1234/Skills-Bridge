# SkillBridge v2 Brand & Visual Design Guidelines (`docs/brand-guidelines.md`)

## 1. Brand Identity & Symbol Concept

SkillBridge's visual identity is designed for a high-trust developer security and runtime orchestration platform:
- **Core Motif**: A suspension bridge arc linking three verification pillars (`Tier 1`, `Tier 2`, `Tier 3`) inside a geometric hexagonal integrity shield.
- **Original SVG Assets (`assets/brand/`)**:
  - `assets/brand/skillbridge-mark.svg` — Primary 120×120 symbol mark.
  - `assets/brand/skillbridge-wordmark.svg` — Dark-surface horizontal wordmark (460×96).
  - `assets/brand/skillbridge-wordmark-light.svg` — Light-surface horizontal wordmark (460×96).
  - `assets/brand/skillbridge-mark-compact.svg` — 32×32 monochrome `currentColor` mark for compact UI and terminal headers.
  - `assets/brand/favicon.svg` — 64×64 application icon and browser favicon.

## 2. Color System

| Token | Hex | Role |
| :--- | :--- | :--- |
| `--bg-primary` | `#0B1120` | Deep graphite-navy application canvas |
| `--bg-surface` | `#111827` | Elevated panel and table surface |
| `--bg-elevated` | `#1E293B` | Tag, code block, and interactive hover surface |
| `--border` | `#334155` | Crisp 1px structural divider |
| `--text-primary` | `#F8FAFC` | High-contrast primary copy and headings |
| `--text-secondary` | `#94A3B8` | Muted metadata labels and secondary captions |
| `--accent-blue` | `#38BDF8` | Primary brand accent and active focus border |
| `--accent-teal` | `#14B8A6` | Verification node and category tag accent |
| `--state-pass` | `#10B981` | Verified `SAFE` / `PASS` assurance indicator |
| `--state-warn` | `#F59E0B` | `CAUTION` / `UNKNOWN` / incomplete evidence indicator |
| `--state-fail` | `#EF4444` | `UNSAFE` / `DANGEROUS` blocked indicator |

## 3. Typography & Status Presentation Rules

- **UI Sans-Serif**: `Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`
- **Technical Monospace**: `"JetBrains Mono", "Fira Code", Consolas, monospace` (used for digests, skill IDs, file paths, and latency figures)
- **Honest Security Indicators**: Every security status badge pairs color with an explicit text label (`SAFE`, `CAUTION`, `UNKNOWN`, `DANGEROUS`). Skipped or incomplete scans always render with the amber `UNKNOWN` / `DISABLED` badge—never a green `SAFE` badge.
