"""Deterministic prose lint for generated report artifacts (Markdown).

The reports this plugin produces are read by human stakeholders, so their
prose is held to the writing rules in
skills/aws-architecture-gap-analysis/references/writing-style.md: no
machine-voice filler, no leaked template placeholders, no copy-paste
duplicated lines, and an orientation paragraph before the first section.

Only *prose* lines are linted. Code fences carry commands and diagram
source; table rows carry AWS-sourced data (finding titles, resource names)
that the plugin quotes rather than writes -- both are exempt by design.

Used by tests/test_prose_quality.py against every skill's rendered report,
and by bin/lint-report-prose against a directory of real generated reports.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Vocabulary that reads machine-written. Patterns, not plain words, so that
# legitimate technical terms survive: "utilization" (a Cost Explorer metric)
# must not trip over "utilize".
BANNED_PHRASES = {
    "seamless": re.compile(r"\bseamless(?:ly)?\b", re.IGNORECASE),
    "leverage": re.compile(r"\bleverag(?:e[sd]?|ing)\b", re.IGNORECASE),
    "robust": re.compile(r"\brobust(?:ly|ness)?\b", re.IGNORECASE),
    "comprehensive": re.compile(r"\bcomprehensive(?:ly)?\b", re.IGNORECASE),
    "delve": re.compile(r"\bdelv(?:e[sd]?|ing)\b", re.IGNORECASE),
    "utilize": re.compile(r"\butiliz(?:e[sd]?|ing)\b", re.IGNORECASE),
    "holistic": re.compile(r"\bholistic(?:ally)?\b", re.IGNORECASE),
    "cutting-edge": re.compile(r"\bcutting.edge\b", re.IGNORECASE),
    "state-of-the-art": re.compile(r"\bstate.of.the.art\b", re.IGNORECASE),
    "best-in-class": re.compile(r"\bbest.in.class\b", re.IGNORECASE),
    "world-class": re.compile(r"\bworld.class\b", re.IGNORECASE),
    "game-changing": re.compile(r"\bgame.chang(?:er|ing)\b", re.IGNORECASE),
    "synergy": re.compile(r"\bsynerg(?:y|ies|istic)\b", re.IGNORECASE),
    "it is worth noting": re.compile(r"\bit\s+is\s+worth\s+noting\b", re.IGNORECASE),
    "in today's": re.compile(r"\bin\s+today'?s\b", re.IGNORECASE),
}

# Unfilled template placeholders. `<profile>`/`<region>`-style CLI argument
# placeholders are legitimate only inside code (fences/spans), which the
# linter already exempts -- in prose they are a leak.
PLACEHOLDER_PATTERNS = (
    re.compile(r"<[A-Za-z][A-Za-z0-9 _-]*>"),   # <AccountId>, <name>, <your-bucket>
    re.compile(r"\{\{[^}]*\}\}"),               # {{ mustache }}
    re.compile(r"\b(?:TODO|TBD|FIXME)\b"),
    re.compile(r"\blorem ipsum\b", re.IGNORECASE),
    re.compile(r"\bY{4}-M{2}-D{2}\b"),          # YYYY-MM-DD left unfilled
)


@dataclass
class Finding:
    line_no: int  # 1-based; 0 for whole-document findings
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"line {self.line_no}: [{self.rule}] {self.detail}"


def _is_prose(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    return not stripped.startswith("|")  # table rows carry quoted AWS data


def _strip_code_spans(line: str) -> str:
    return re.sub(r"`[^`]*`", "", line)


def lint_markdown(text: str, require_intro: bool = True) -> list[Finding]:
    """Lint one Markdown document; returns [] when clean."""
    findings: list[Finding] = []
    lines = text.splitlines()

    in_fence = False
    seen_headings: dict[str, int] = {}
    previous_prose: tuple[int, str] | None = None
    saw_intro_prose = False
    saw_section_heading = False

    for idx, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            previous_prose = None
            continue
        if in_fence:
            continue

        if stripped.startswith("#"):
            if re.match(r"#{2,}\s", stripped):
                saw_section_heading = True
                key = stripped.lstrip("#").strip().lower()
                if key in seen_headings:
                    findings.append(
                        Finding(idx, "duplicate-heading",
                                f"heading repeats line {seen_headings[key]}: {stripped!r}")
                    )
                else:
                    seen_headings[key] = idx
            previous_prose = None
            continue

        if not _is_prose(raw):
            previous_prose = None
            continue

        # A prose line before the first section heading is the orientation
        # paragraph; metadata lines (Generated:, bullets, the _subtitle_
        # line, embedded images) don't count as one.
        if not saw_section_heading and not re.match(r"(-\s|_.*_$|!\[|Generated:)", stripped):
            saw_intro_prose = True

        checkable = _strip_code_spans(raw)
        for name, pattern in BANNED_PHRASES.items():
            if pattern.search(checkable):
                findings.append(Finding(idx, "banned-phrase", f"{name!r} in: {stripped!r}"))
        for pattern in PLACEHOLDER_PATTERNS:
            match = pattern.search(checkable)
            if match:
                findings.append(
                    Finding(idx, "unfilled-placeholder", f"{match.group(0)!r} in: {stripped!r}")
                )

        # Copy-paste duplication: the same non-trivial prose line twice in
        # a row (duplicated header/metadata bullets are the classic case).
        if previous_prose and previous_prose[1] == stripped and len(stripped) > 3:
            findings.append(
                Finding(idx, "duplicated-line", f"repeats line {previous_prose[0]}: {stripped!r}")
            )
        previous_prose = (idx, stripped)

    if require_intro and saw_section_heading and not saw_intro_prose:
        findings.append(
            Finding(0, "missing-orientation",
                    "no orientation paragraph before the first section heading")
        )

    return findings
