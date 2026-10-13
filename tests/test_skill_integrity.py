"""Structural integrity of the plugin's skills and manifest.

Nothing else in the suite catches skill-definition rot: a SKILL.md with
broken YAML frontmatter, a `name:` that drifted from its directory, a
`view ${CLAUDE_PLUGIN_ROOT}/...` pointing at a reference file that was
renamed or never created, or a script path quoted in a SKILL.md that
doesn't exist. All of those fail silently at runtime -- Claude loads the
skill, follows the instructions, and hits a missing file mid-task.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "skills"
SKILL_FILES = sorted(SKILLS_DIR.glob("*/SKILL.md"))

# Every skill dir must have a SKILL.md; catch a dir that lost one.
SKILL_DIRS = sorted(p for p in SKILLS_DIR.iterdir() if p.is_dir())


def _frontmatter(skill_md: Path) -> dict:
    text = skill_md.read_text()
    assert text.startswith("---\n"), f"{skill_md} does not open with YAML frontmatter"
    _, fm, _ = text.split("---", 2)
    return yaml.safe_load(fm)


def test_every_skill_directory_has_a_skill_md():
    missing = [d.name for d in SKILL_DIRS if not (d / "SKILL.md").exists()]
    assert not missing, f"skill directories with no SKILL.md: {missing}"


def test_expected_skill_count():
    """Guards against a skill being accidentally deleted or an unintended
    stray directory appearing under skills/."""
    assert len(SKILL_FILES) == 9, [p.parent.name for p in SKILL_FILES]


@pytest.mark.parametrize("skill_md", SKILL_FILES, ids=lambda p: p.parent.name)
def test_frontmatter_parses_as_yaml(skill_md):
    fm = _frontmatter(skill_md)
    assert isinstance(fm, dict), f"{skill_md} frontmatter is not a YAML mapping"


@pytest.mark.parametrize("skill_md", SKILL_FILES, ids=lambda p: p.parent.name)
def test_frontmatter_name_matches_directory(skill_md):
    fm = _frontmatter(skill_md)
    assert fm.get("name") == skill_md.parent.name, (
        f"{skill_md}: frontmatter name {fm.get('name')!r} != directory "
        f"{skill_md.parent.name!r} -- the skill will not resolve correctly"
    )


@pytest.mark.parametrize("skill_md", SKILL_FILES, ids=lambda p: p.parent.name)
def test_frontmatter_has_substantive_description(skill_md):
    """The description is what Claude matches a user request against -- an
    empty or one-line one makes the skill effectively undiscoverable."""
    fm = _frontmatter(skill_md)
    description = fm.get("description", "")
    assert isinstance(description, str) and len(description) > 120, (
        f"{skill_md}: description missing or too short to be discoverable"
    )


@pytest.mark.parametrize("skill_md", SKILL_FILES, ids=lambda p: p.parent.name)
def test_referenced_plugin_root_paths_exist(skill_md):
    """Every ${CLAUDE_PLUGIN_ROOT}/... path quoted in a SKILL.md -- whether
    in a `view` line, a python invocation, or prose -- must exist on disk."""
    text = skill_md.read_text()
    referenced = re.findall(r"\$\{CLAUDE_PLUGIN_ROOT\}/([^\s`'\"\\]+)", text)
    assert referenced, f"{skill_md} references no plugin files at all -- suspicious"

    missing = [rel for rel in referenced if not (ROOT / rel).exists()]
    assert not missing, f"{skill_md} references non-existent paths: {missing}"


@pytest.mark.parametrize("skill_md", SKILL_FILES, ids=lambda p: p.parent.name)
def test_skill_scripts_are_executable_python(skill_md):
    """If a skill ships scripts/, each must be importable Python with a
    main() -- the SKILL.md tells the user to run it directly."""
    scripts_dir = skill_md.parent / "scripts"
    if not scripts_dir.exists():
        pytest.skip("skill has no scripts/ directory")

    scripts = list(scripts_dir.glob("*.py"))
    assert scripts, f"{scripts_dir} exists but contains no .py files"
    for script in scripts:
        source = script.read_text()
        assert "def main(" in source, f"{script} has no main() entry point"
        assert "__main__" in source, f"{script} is not runnable as a script"


@pytest.mark.parametrize("skill_md", SKILL_FILES, ids=lambda p: p.parent.name)
def test_scripts_run_through_the_venv_launcher(skill_md):
    """A bare `python script.py` fails on a marketplace install: `python`
    may not exist (stock macOS) and nothing has installed requirements.txt.
    Every invocation must go through bin/run-skill-script instead."""
    text = skill_md.read_text()
    bare = re.findall(r"^\s*python3?\s+\S+\.py", text, flags=re.MULTILINE)
    assert not bare, f"{skill_md} invokes a script without the launcher: {bare}"
    for line in re.findall(r"^.*/scripts/\w+\.py.*$", text, flags=re.MULTILINE):
        if line.lstrip().startswith("${CLAUDE_PLUGIN_ROOT}/"):
            assert line.lstrip().startswith("${CLAUDE_PLUGIN_ROOT}/bin/run-skill-script "), line


def test_venv_launcher_is_executable():
    launcher = ROOT / "bin" / "run-skill-script"
    assert launcher.is_file() and os.access(launcher, os.X_OK)


def test_plugin_manifest_is_valid_json_with_required_fields():
    manifest_path = ROOT / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text())
    for field in ("name", "version", "description"):
        assert manifest.get(field), f"plugin.json missing {field}"


def test_plugin_manifest_name_matches_repo_directory():
    manifest = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["name"] == ROOT.name


@pytest.mark.parametrize("skill_md", SKILL_FILES, ids=lambda p: p.parent.name)
def test_skill_references_directory_has_no_orphans(skill_md):
    """Every file under a skill's references/ should actually be referenced
    by its SKILL.md -- an unreferenced reference file is dead weight Claude
    will never load."""
    references_dir = skill_md.parent / "references"
    if not references_dir.exists():
        pytest.skip("skill has no references/ directory")

    text = skill_md.read_text()
    orphans = [
        ref.relative_to(ROOT).as_posix()
        for ref in references_dir.rglob("*.md")
        if ref.name not in text and ref.relative_to(ROOT).as_posix() not in text
    ]
    assert not orphans, f"{skill_md} never references: {orphans}"


DIAGRAM_SKILLS = ("aws-architecture-discovery", "aws-lucid-diagrams")
DIAGRAM_CONVENTIONS = "skills/aws-lucid-diagrams/references/diagram-conventions.md"


@pytest.mark.parametrize("skill_name", DIAGRAM_SKILLS)
def test_diagram_skills_load_the_shared_diagram_conventions(skill_name):
    """Both skills that draw diagrams must load the one document defining
    the conventions (labelled edges, expanded abbreviations, concise labels,
    legend). If one stops referencing it, the two deliverables drift apart."""
    assert (ROOT / DIAGRAM_CONVENTIONS).exists()
    text = (SKILLS_DIR / skill_name / "SKILL.md").read_text()
    assert DIAGRAM_CONVENTIONS in text, (
        f"{skill_name}/SKILL.md no longer loads {DIAGRAM_CONVENTIONS}"
    )
