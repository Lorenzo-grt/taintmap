import os
import sys
from pathlib import Path

import pytest

from taintmap.discover import Glob, discover, relative_posix


def write(root: Path, rel: str, text: str = "x") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def rels(root: Path, paths: list[Path]) -> list[str]:
    return [relative_posix(p, root) for p in paths]


def link_dir(link: Path, target: Path) -> None:
    """Create a directory symlink, or a junction on Windows without symlink privilege."""
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError:
        if sys.platform != "win32":
            pytest.skip("cannot create directory symlinks here")
        import _winapi

        _winapi.CreateJunction(str(target), str(link))


def link_file(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("cannot create file symlinks here (needs privilege on Windows)")


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for rel in [
        ".github/workflows/ci.yml",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        ".mcp.json",
        "claude_desktop_config.json",
        "src/app.py",
        "src/nested/deep/config.yaml",
        ".git/config",
        "node_modules/pkg/.mcp.json",
        "dist/out.yml",
        "build/out.yml",
        "src/build/generated.yml",
        "src/__pycache__/app.pyc",
        ".venv/lib/site.py",
        "venv/lib/site.py",
        "myenv/pyvenv.cfg",
        "myenv/lib/site.py",
        ".idea/workspace.xml",
        ".env",
        "vendor/lib.yml",
        "src/vendor/lib.yml",
    ]:
        write(root, rel)
    return root


def test_default_skips(tree: Path) -> None:
    assert rels(tree, discover(tree)) == [
        ".cursor/mcp.json",
        ".github/workflows/ci.yml",
        ".mcp.json",
        ".vscode/mcp.json",
        "claude_desktop_config.json",
        "src/app.py",
        "src/nested/deep/config.yaml",
        "src/vendor/lib.yml",
        "vendor/lib.yml",
    ]


def test_results_are_absolute_under_resolved_root(tree: Path) -> None:
    for path in discover(tree):
        assert path.is_absolute()
        assert path.is_file()
        assert tree.resolve() in path.parents


def test_include_globs(tree: Path) -> None:
    found = rels(tree, discover(tree, include=["**/*.json"]))
    assert found == [
        ".cursor/mcp.json",
        ".mcp.json",
        ".vscode/mcp.json",
        "claude_desktop_config.json",
    ]
    found = rels(tree, discover(tree, include=[".github/workflows/*.yml", "*.yaml"]))
    assert found == [".github/workflows/ci.yml", "src/nested/deep/config.yaml"]


def test_exclude_globs(tree: Path) -> None:
    found = rels(tree, discover(tree, exclude=["vendor", "src/**/*.yaml", "*.py"]))
    assert found == [
        ".cursor/mcp.json",
        ".github/workflows/ci.yml",
        ".mcp.json",
        ".vscode/mcp.json",
        "claude_desktop_config.json",
    ]


def test_exclude_wins_over_include(tree: Path) -> None:
    found = rels(tree, discover(tree, include=["**/*.json"], exclude=[".cursor/**"]))
    assert ".cursor/mcp.json" not in found
    assert ".mcp.json" in found


def test_glob_semantics() -> None:
    assert Glob("*.yml").matches("a/b/c.yml")  # slash-free pattern matches the name
    assert not Glob("src/*.yml").matches("src/a/b.yml")  # * does not cross /
    assert Glob("src/**/*.yml").matches("src/b.yml")  # **/ matches zero directories
    assert Glob("src/**/*.yml").matches("src/a/b/c.yml")
    assert Glob("./src\\*.yml").matches("src/a.yml")  # ./ and backslashes normalised
    assert Glob("file?.json").matches("file1.json")
    assert Glob("[ab].json").matches("a.json")
    assert not Glob("[!ab].json").matches("a.json")
    assert Glob("weird[.json").matches("weird[.json")  # unclosed class is literal
    with pytest.raises(ValueError):
        Glob("  ")


def test_root_must_be_a_directory(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        discover(tmp_path / "missing")
    with pytest.raises(NotADirectoryError):
        discover(write(tmp_path, "file.txt"))


def test_directory_link_escaping_root_is_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write(root, "inside.yml")
    outside = tmp_path / "outside"
    write(outside, "secret.yml")
    link_dir(root / "escape", outside)
    assert rels(root, discover(root)) == ["inside.yml"]


def test_directory_link_inside_root_is_followed_and_loops_terminate(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write(root, "conf/workflows/ci.yml")
    link_dir(root / "alias", root / "conf")
    link_dir(root / "conf" / "loop", root / "conf")
    assert rels(root, discover(root)) == ["conf/workflows/ci.yml"]


def test_files_reached_through_linked_directories_are_deduplicated(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write(root, "configuration/mcp/servers.json")
    write(root, "configuration/other.json")
    link_dir(root / "c", root / "configuration")
    link_dir(root / "configuration" / "m", root / "configuration" / "mcp")
    # Each real file is listed once, under its shortest relative path.
    assert rels(root, discover(root)) == ["c/m/servers.json", "c/other.json"]


def test_dedup_ties_break_alphabetically(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write(root, "bbb/x.yml")
    link_dir(root / "aaa", root / "bbb")
    assert rels(root, discover(root)) == ["aaa/x.yml"]


def test_file_link_escaping_root_is_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write(root, "inside.yml")
    secret = write(tmp_path / "outside", "secret.json")
    link_file(root / ".mcp.json", secret)
    assert rels(root, discover(root)) == ["inside.yml"]


def test_file_link_inside_root_is_followed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    target = write(root, "config/mcp.json")
    link_file(root / ".mcp.json", target)
    assert rels(root, discover(root)) == [".mcp.json", "config/mcp.json"]


def test_broken_link_is_skipped(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write(root, "inside.yml")
    link_file(root / "dangling.yml", root / "missing.yml")
    assert rels(root, discover(root)) == ["inside.yml"]
