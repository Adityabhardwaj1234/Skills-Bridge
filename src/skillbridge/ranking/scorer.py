"""Explainable multi-factor candidate ranking, comparison, and complementary selection engine."""

from __future__ import annotations

import math
import re
from typing import Dict, List, Optional, Set, Tuple

from skillbridge.config import LoaderLimits
from skillbridge.models import CandidatePreview, ExtensionRecord, SecurityVerdict, TrustLevel

STOPWORDS = frozenset({
    "a", "an", "the", "and", "or", "for", "to", "in", "on", "of", "with", "by", "from", "at", "as",
    "is", "are", "be", "this", "that", "it", "how", "can", "i", "me", "my", "we", "our", "you",
    "please", "help", "write", "create", "build", "make", "use", "using", "need", "want", "task",
    "implement", "run", "do", "set", "up", "new", "code", "file", "files", "project", "app", "tool",
})

SYNONYM_EXPANSIONS: Dict[str, List[str]] = {
    "docx": ["word", "docx", "document", "microsoft", "specification", "report"],
    "word": ["word", "docx", "document"],
    "xlsx": ["excel", "xlsx", "spreadsheet", "workbook", "financial", "formulas"],
    "excel": ["excel", "xlsx", "spreadsheet", "workbook"],
    "pptx": ["powerpoint", "pptx", "presentation", "slides", "deck"],
    "powerpoint": ["powerpoint", "pptx", "presentation", "slides", "deck"],
    "pdf": ["pdf", "pypdf", "reportlab", "document", "extract", "tables"],
    "debug": ["debug", "debugging", "traceback", "pdb", "troubleshoot", "bug", "error", "fix", "deadlock", "segmentation"],
    "debugging": ["debug", "debugging", "traceback", "pdb", "troubleshoot", "bug", "error", "deadlock"],
    "test": ["test", "testing", "pytest", "unittest", "verification", "qa", "coverage", "e2e", "fixtures", "mocked"],
    "testing": ["test", "testing", "pytest", "unittest", "verification", "coverage", "e2e", "fixtures"],
    "pytest": ["pytest", "test", "testing", "unittest", "fixtures", "coverage", "parameterized"],
    "frontend": ["frontend", "ui", "web", "react", "html", "css", "design", "tailwind", "interface", "dashboard", "landing"],
    "review": ["review", "pr", "pull", "request", "sdlc", "audit", "quality", "diff", "code", "lens", "maintainability"],
    "release": ["release", "changelog", "tag", "version", "git", "github", "publish", "semver"],
    "security": ["security", "vulnerability", "audit", "pentest", "penetration", "owasp", "scan", "auth", "threat", "ssrf", "injection"],
    "pentest": ["pentest", "penetration", "security", "owasp", "vulnerability", "web"],
    "docs": ["documentation", "docs", "markdown", "readme", "mintlify", "diagram", "architecture"],
    "documentation": ["documentation", "docs", "markdown", "readme", "diagram", "architecture"],
    "scaffold": ["scaffold", "scaffolding", "template", "init", "cookiecutter", "pyproject", "bootstrap", "setuptools", "package"],
    "scaffolding": ["scaffold", "scaffolding", "template", "init", "pyproject", "bootstrap", "setuptools"],
    "bootstrap": ["scaffold", "scaffolding", "bootstrap", "pyproject", "setuptools", "package", "cli"],
    "mcp": ["mcp", "server", "fastmcp", "mcporter", "protocol", "oauth", "gateway"],
    "fastmcp": ["fastmcp", "mcp", "server", "python", "tools", "resources"],
    "browser": ["browser", "playwright", "computer-use", "scrape", "web", "webapp", "automation"],
    "playwright": ["playwright", "browser", "automation", "e2e", "web", "testing"],
    "diagram": ["diagram", "architecture", "excalidraw", "mermaid", "chart", "concept", "microservice", "flow"],
    "excalidraw": ["excalidraw", "diagram", "visual", "architecture", "flow"],
    "merge": ["merge", "conflict", "conflicts", "arbiter", "git", "branch", "branches"],
    "email": ["email", "inbox", "triage", "messages", "action", "items"],
    "p5js": ["p5", "p5js", "canvas", "generative", "art", "animation", "algorithmic"],
}


def tokenize(text: str) -> List[str]:
    """Tokenize text into lowercase alphanumeric words, filtering out generic stopwords."""
    raw = [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 2]
    return [t for t in raw if t not in STOPWORDS]


def expand_query_tokens(tokens: List[str]) -> Set[str]:
    expanded = set(tokens)
    for t in tokens:
        if t in SYNONYM_EXPANSIONS:
            expanded.update(SYNONYM_EXPANSIONS[t])
    return expanded


def classify_task_query(query: str) -> str:
    """Classify a task query into a concise canonical category."""
    tokens = set(tokenize(query))
    categories = [
        ("security_review", {"security", "vulnerability", "pentest", "exploit", "owasp", "threat", "injection"}),
        ("python_debugging", {"debug", "debugging", "traceback", "pdb", "exception", "crash", "bug"}),
        ("testing_verification", {"test", "testing", "pytest", "unittest", "verify", "coverage", "e2e"}),
        ("code_review", {"review", "pr", "diff", "sdlc", "lint", "pull"}),
        ("git_release", {"release", "changelog", "tag", "semver", "git", "branch", "merge"}),
        ("frontend_design", {"frontend", "react", "css", "ui", "tailwind", "html", "design", "component", "canvas"}),
        ("documentation", {"documentation", "docs", "readme", "architecture", "diagram", "markdown", "writeup"}),
        ("document_office", {"pdf", "docx", "word", "xlsx", "excel", "pptx", "powerpoint", "slides"}),
        ("mcp_integration", {"mcp", "fastmcp", "mcporter", "oauth", "registry"}),
        ("project_scaffolding", {"scaffold", "scaffolding", "bootstrap", "init", "template", "packaging"}),
    ]
    best_cat = "general_software"
    best_overlap = 0
    for cat, kw in categories:
        overlap = len(tokens & kw)
        if overlap > best_overlap:
            best_overlap = overlap
            best_cat = cat
    return best_cat


class CandidateRanker:
    """Explainable multi-factor scorer and selector for candidate previews.

    Scoring breakdown (0.0 to 100.0):
    - Relevance Score (0..45): Lexical + domain synonym match across name, description, tags, and body excerpt.
    - Instruction Quality Score (0..15): Frontmatter validity, body depth, actionable headings, reference completeness.
    - Compatibility Score (0..15): OS platform match, client match, dependency availability.
    - Security & Trust Score (0..15): SAFE/CAUTION/DANGEROUS verdict + builtin/trusted/community provenance.
    - Historical Outcome Score (-20..+7): Verified past task successes vs regressions.
    - Popularity Bonus (0..3): Bounded secondary tie-breaker signal (never overrides relevance or safety).
    """

    MIN_SELECTION_RELEVANCE = 14.0
    MIN_TOTAL_SCORE = 44.0

    def __init__(self, limits: Optional[LoaderLimits] = None):
        self.limits = limits or LoaderLimits()

    def score_preview(
        self,
        query: str,
        preview: CandidatePreview,
        record: Optional[ExtensionRecord] = None,
        *,
        approved: bool = False,
    ) -> CandidatePreview:
        """Compute deterministic, explainable multi-factor score for a CandidatePreview."""
        q_lower = query.strip().lower()
        q_tokens = tokenize(query)
        q_expanded = expand_query_tokens(q_tokens)

        name_lower = preview.name.lower()
        name_tokens = set(tokenize(preview.name))
        desc_tokens = set(tokenize(preview.description))
        tag_tokens = set(tokenize(" ".join(record.tags if record else [])))
        body_tokens = set(tokenize(preview.body_excerpt))
        all_cand_tokens = name_tokens | tag_tokens | desc_tokens | body_tokens

        # 1. Relevance Score (0..45)
        relevance = 0.0
        if not q_tokens:
            relevance = 15.0
        else:
            exact_name_in_query = (
                name_lower == q_lower
                or name_lower.replace("-", " ") in q_lower
                or (name_lower in q_lower and len(name_lower) >= 4)
            )
            if exact_name_in_query:
                relevance += 28.0

            direct_name_hits = len(set(q_tokens) & name_tokens)
            syn_name_hits = len(q_expanded & name_tokens) - direct_name_hits
            direct_tag_hits = len(set(q_tokens) & tag_tokens)
            syn_tag_hits = len(q_expanded & tag_tokens) - direct_tag_hits
            direct_desc_hits = len(set(q_tokens) & desc_tokens)
            syn_desc_hits = len(q_expanded & desc_tokens) - direct_desc_hits
            body_hits = len(q_expanded & body_tokens)

            denom = max(1, len(q_tokens))
            token_score = (
                (direct_name_hits * 15.0)
                + (syn_name_hits * 10.0)
                + (direct_tag_hits * 11.0)
                + (syn_tag_hits * 6.5)
                + (direct_desc_hits * 7.5)
                + (syn_desc_hits * 4.0)
                + (body_hits * 2.5)
            ) / math.sqrt(denom)
            relevance = min(45.0, relevance + token_score)

            # Query token coverage check: how many distinct query tokens (with synonym expansion) hit the candidate?
            matched_q_count = 0
            for qt in q_tokens:
                qt_group = {qt, *SYNONYM_EXPANSIONS.get(qt, [])}
                if qt_group & all_cand_tokens:
                    matched_q_count += 1
            coverage = matched_q_count / len(q_tokens)

            # If a multi-word query (4+ tokens) only matches a single incidental word (< 25% coverage)
            # and does not explicitly name the skill, cap relevance below MIN_SELECTION_RELEVANCE.
            if len(q_tokens) >= 4 and matched_q_count <= 1 and not exact_name_in_query:
                relevance = min(relevance, 9.0)
            elif len(q_tokens) >= 3 and len(q_expanded & (name_tokens | tag_tokens)) == 0 and direct_desc_hits < 2:
                relevance = min(relevance, 9.0)
            elif coverage < 0.30 and not exact_name_in_query:
                relevance *= 0.65

        # 2. Instruction Quality & Specificity (0..15)
        quality = 0.0
        if preview.frontmatter.get("name") and preview.frontmatter.get("description"):
            quality += 4.0
        if preview.full_body_chars >= 400:
            quality += 5.0
        elif preview.full_body_chars >= 120:
            quality += 3.0
        elif preview.full_body_chars > 0:
            quality += 1.0
        if "##" in preview.body_excerpt or "```" in preview.body_excerpt or "-" in preview.body_excerpt:
            quality += 3.0
        if not preview.missing_references:
            quality += 3.0
        else:
            quality = max(0.0, quality - 2.0 * len(preview.missing_references))
        quality = min(15.0, quality)

        # 3. Platform, Client & Dependency Compatibility (0..15)
        compatibility = 15.0
        if not preview.platform_compatible:
            compatibility -= 12.0
        if preview.missing_dependencies:
            compatibility -= min(8.0, 3.0 * len(preview.missing_dependencies))
        compatibility = max(0.0, compatibility)

        # 4. Security & Trust Score (0..15)
        verdict = preview.security.verdict if preview.security else SecurityVerdict.UNKNOWN.value
        trust = preview.trust_level
        trust_base = {
            TrustLevel.BUILTIN.value: 6.0,
            TrustLevel.TRUSTED.value: 5.0,
            TrustLevel.AGENT_CREATED.value: 3.5,
            TrustLevel.COMMUNITY.value: 2.5,
            TrustLevel.UNTRUSTED.value: 0.0,
        }.get(trust, 2.0)

        if verdict == SecurityVerdict.DANGEROUS.value:
            sec_score = 0.0
        elif verdict == SecurityVerdict.SAFE.value:
            sec_score = 9.0 + trust_base
        elif verdict == SecurityVerdict.CAUTION.value:
            sec_score = (5.0 if trust in ("builtin", "trusted") else 1.5) + (trust_base * 0.5)
        else:
            sec_score = 2.0 + (trust_base * 0.5)
        sec_score = min(15.0, sec_score)

        # 5. Historical Verified Outcome Score (-20..+7)
        outcome_score = 0.0
        stats = (record.outcome_stats if record else {}) or {}
        total_runs = int(stats.get("total_runs") or 0)
        successes = int(stats.get("successes") or 0)
        regressions = int(stats.get("regressions") or 0)
        if total_runs > 0:
            if regressions > 0:
                outcome_score -= min(20.0, regressions * 7.5)
            if successes > 0 and regressions == 0:
                outcome_score += min(7.0, successes * 2.5)
            elif successes > regressions:
                outcome_score += min(3.0, (successes - regressions) * 1.0)
        if stats.get("trust_override") == "trusted":
            outcome_score += 2.0
        elif stats.get("trust_override") == "blocked":
            outcome_score -= 50.0

        # 6. Popularity Bonus (0..3) - strictly secondary signal
        pop_signals = (record.popularity_signals if record else {}) or {}
        installs = int(pop_signals.get("weekly_installs") or pop_signals.get("installs") or pop_signals.get("install_count") or pop_signals.get("token_usage") or 0)
        pop_bonus = min(3.0, math.log10(max(1, installs)) * 0.6) if installs > 0 else 0.0

        # Hard disqualifiers (builtin DANGEROUS sources may proceed only with explicit operator approval)
        approved_builtin_dangerous = (
            approved and verdict == SecurityVerdict.DANGEROUS.value and trust == TrustLevel.BUILTIN.value
        )
        if (verdict == SecurityVerdict.DANGEROUS.value and not approved_builtin_dangerous) or not preview.platform_compatible or stats.get("trust_override") == "blocked":
            total = 0.0
        else:
            total = max(0.0, round(relevance + quality + compatibility + sec_score + outcome_score + pop_bonus, 2))

        preview.relevance_score = round(relevance, 2)
        preview.quality_score = round(quality, 2)
        preview.compatibility_score = round(compatibility, 2)
        preview.security_score = round(sec_score, 2)
        preview.outcome_score = round(outcome_score, 2)
        preview.popularity_bonus = round(pop_bonus, 2)
        preview.total_score = total
        preview.score_breakdown = {
            "relevance": preview.relevance_score,
            "quality": preview.quality_score,
            "compatibility": preview.compatibility_score,
            "security": preview.security_score,
            "outcomes": preview.outcome_score,
            "popularity_bonus": preview.popularity_bonus,
            "total": preview.total_score,
        }
        return preview

    def rank_and_select(
        self,
        query: str,
        previews: List[CandidatePreview],
        records_by_id: Optional[Dict[str, ExtensionRecord]] = None,
        *,
        max_select: Optional[int] = None,
        max_tokens: Optional[int] = None,
        approved: bool = False,
    ) -> Tuple[List[CandidatePreview], List[str], Dict[str, str], str]:
        """Score, sort deterministically, and select the best candidate(s) or explicit NO_MATCH."""
        records_map = records_by_id or {}
        for p in previews:
            self.score_preview(query, p, records_map.get(p.extension_id), approved=approved)

        ranked = sorted(
            previews,
            key=lambda p: (-p.total_score, -p.relevance_score, -p.security_score, p.extension_id),
        )

        cap_count = max_select or self.limits.max_selected_skills
        cap_tokens = max_tokens or self.limits.max_context_tokens

        selected_ids: List[str] = []
        rejection_reasons: Dict[str, str] = {}
        covered_capabilities: Set[str] = set()
        used_tokens = 0
        top_score = ranked[0].total_score if ranked else 0.0

        for cand in ranked:
            verdict = cand.security.verdict if cand.security else "UNKNOWN"
            approved_builtin_dangerous = (
                approved
                and verdict == SecurityVerdict.DANGEROUS.value
                and cand.trust_level == TrustLevel.BUILTIN.value
            )
            if verdict == SecurityVerdict.DANGEROUS.value and not approved_builtin_dangerous:
                rejection_reasons[cand.extension_id] = f"Blocked by security scanner (verdict=DANGEROUS, {len(cand.security.findings if cand.security else [])} finding(s))"
                continue
            if cand.security and cand.security.allowed is False and not approved_builtin_dangerous:
                rejection_reasons[cand.extension_id] = f"Blocked by trust policy ({cand.security.policy_reason})"
                continue
            if not cand.platform_compatible:
                rejection_reasons[cand.extension_id] = "Incompatible with current OS platform"
                continue
            if cand.relevance_score < self.MIN_SELECTION_RELEVANCE:
                rejection_reasons[cand.extension_id] = (
                    f"Insufficient task relevance ({cand.relevance_score:.1f} < {self.MIN_SELECTION_RELEVANCE})"
                )
                continue
            if cand.total_score < self.MIN_TOTAL_SCORE:
                rejection_reasons[cand.extension_id] = (
                    f"Total suitability score below threshold ({cand.total_score:.1f} < {self.MIN_TOTAL_SCORE})"
                )
                continue

            cand_tokens = set(tokenize(cand.name))
            if selected_ids:
                if cand.name.lower() in {s.split("/")[-1].lower() for s in selected_ids}:
                    rejection_reasons[cand.extension_id] = "Duplicate skill name already selected from higher-priority source"
                    continue
                if cand_tokens and cand_tokens.issubset(covered_capabilities):
                    rejection_reasons[cand.extension_id] = "Redundant capability already covered by higher-ranked selected skill"
                    continue
                if cand.total_score < top_score * 0.72:
                    rejection_reasons[cand.extension_id] = (
                        f"Lower suitability ({cand.total_score:.1f}) compared to primary selection ({top_score:.1f})"
                    )
                    continue

            if len(selected_ids) >= cap_count:
                rejection_reasons[cand.extension_id] = f"Selection limit reached (max_selected_skills={cap_count})"
                continue
            if used_tokens + cand.estimated_tokens > cap_tokens and selected_ids:
                rejection_reasons[cand.extension_id] = f"Context token budget exceeded ({used_tokens + cand.estimated_tokens} > {cap_tokens})"
                continue

            selected_ids.append(cand.extension_id)
            covered_capabilities.update(cand_tokens)
            used_tokens += cand.estimated_tokens

        if not selected_ids:
            reason = (
                f"NO_MATCH: Inspected {len(ranked)} candidate(s) for query '{query}', but none cleared both the "
                f"relevance threshold (>={self.MIN_SELECTION_RELEVANCE}) and safety/suitability gate (>={self.MIN_TOTAL_SCORE}). "
                "Proceeding safely with native agent capabilities."
            )
        else:
            top = next(p for p in ranked if p.extension_id == selected_ids[0])
            reason = (
                f"Selected {len(selected_ids)} extension(s) [{', '.join(selected_ids)}]. "
                f"Primary match '{top.extension_id}' scored {top.total_score:.1f}/100 "
                f"(relevance={top.relevance_score:.1f}, quality={top.quality_score:.1f}, "
                f"security={top.security_score:.1f} [{top.security.verdict if top.security else 'UNKNOWN'}], "
                f"outcomes={top.outcome_score:+.1f})."
            )

        return ranked, selected_ids, rejection_reasons, reason

    @staticmethod
    def lexical_baseline_select(query: str, candidates: List[ExtensionRecord]) -> Optional[str]:
        """Simple baseline that chooses the first lexical substring match (used in evaluation comparison)."""
        q_tokens = tokenize(query)
        if not q_tokens:
            return candidates[0].extension_id if candidates else None
        for cand in candidates:
            hay = f"{cand.name} {cand.description}".lower()
            if any(t in hay for t in q_tokens):
                return cand.extension_id
        return None
