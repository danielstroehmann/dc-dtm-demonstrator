"""CI contract: a release (v* tag) needs written release notes – checked in the test job, before
any image is built, and used as the GitHub release text."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())


def steps(job: str) -> list[dict]:
    return CI["jobs"][job]["steps"]


def test_release_notes_are_checked_in_the_test_job_for_tags_only():
    checks = [s for s in steps("test") if "docs/releases/${GITHUB_REF_NAME}.md" in s.get("run", "")]
    assert len(checks) == 1
    (check,) = checks
    assert check["if"] == "startsWith(github.ref, 'refs/tags/v')"
    assert check["run"].startswith('[ -s "docs/releases/${GITHUB_REF_NAME}.md" ]') and "exit 1" in check["run"]
    # before any image is built: the image job needs the test job, the release job the image
    assert CI["jobs"]["image"]["needs"] == "test" and CI["jobs"]["release"]["needs"] == "image"
    assert not any("docs/releases" in s.get("run", "") and "-s" in s.get("run", "") for s in steps("release"))


def test_release_job_uses_the_notes_file():
    (create,) = [s for s in steps("release") if "gh release create" in s.get("run", "")]
    assert '--notes-file "docs/releases/${GITHUB_REF_NAME}.md"' in create["run"]


def test_release_notes_exist_and_are_named_by_version():
    notes = sorted((ROOT / "docs" / "releases").glob("*.md"))
    assert ROOT / "docs" / "releases" / "v0.2.0.md" in notes
    for note in notes:
        assert re.fullmatch(r"v\d+\.\d+\.\d+\.md", note.name), note.name
        assert note.read_text().strip(), note.name
