from pathlib import Path

import pytest

from taintmap.loaders import load_json, load_yaml, parse_json, parse_yaml
from taintmap.loaders.json_lines import pointer
from taintmap.loaders.yaml_lines import key_line, value_line

WORKFLOW = """\
name: triage
on:
  issues:
    types: [opened]
permissions:
  contents: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Echo
        env:
          TITLE: ${{ github.event.issue.title }}
        run: |
          echo "$TITLE"
      - name: Second
        env:
          TITLE: other
"""


# -- YAML ---------------------------------------------------------------------------------------


def test_yaml_nested_keys_and_list_items() -> None:
    doc = parse_yaml(WORKFLOW, "wf.yml")
    assert doc.ok
    assert doc.line_of() == 1
    assert doc.line_of(["name"]) == 1
    assert doc.line_of(["on", "issues", "types"]) == 4
    assert doc.line_of(["on", "issues", "types", 0]) == 4
    assert doc.line_of(["jobs", "triage", "steps"]) == 10
    assert doc.line_of(["jobs", "triage", "steps", 0]) == 11
    assert doc.line_of(["jobs", "triage", "steps", 1]) == 12
    assert doc.line_of(["jobs", "triage", "steps", 1, "run"]) == 15


def test_yaml_on_key_stays_a_string() -> None:
    doc = parse_yaml(WORKFLOW, "wf.yml")
    assert "on" in doc.data
    assert True not in doc.data


def test_yaml_same_key_in_sibling_mappings_has_its_own_line() -> None:
    doc = parse_yaml(WORKFLOW, "wf.yml")
    assert doc.line_of(["jobs", "triage", "steps", 1, "env", "TITLE"]) == 14
    assert doc.line_of(["jobs", "triage", "steps", 2, "env", "TITLE"]) == 19


def test_yaml_value_line_of_block_scalar() -> None:
    step = parse_yaml(WORKFLOW, "wf.yml").data["jobs"]["triage"]["steps"][1]
    assert key_line(step, "run") == 15
    assert value_line(step, "run") == 15  # the block indicator; content follows on 16


def test_yaml_missing_path_raises_key_error() -> None:
    doc = parse_yaml(WORKFLOW, "wf.yml")
    with pytest.raises(KeyError):
        doc.line_of(["jobs", "nope"])
    with pytest.raises(KeyError):
        doc.line_of(["jobs", "triage", "steps", 9])
    with pytest.raises(KeyError):
        doc.line_of(["name", "deeper"])


def test_yaml_crlf_line_numbers() -> None:
    doc = parse_yaml(WORKFLOW.replace("\n", "\r\n"), "wf.yml")
    assert doc.ok
    assert doc.line_of(["jobs", "triage", "steps", 2, "env", "TITLE"]) == 19


def test_yaml_duplicate_key_is_a_warning_without_values() -> None:
    doc = parse_yaml("env:\n  TOKEN: one\n  TOKEN: FAKE_TOKEN_FOR_TESTS\n", "dup.yml")
    assert doc.data is None
    [warning] = doc.warnings
    assert (warning.file, warning.line) == ("dup.yml", 3)
    assert 'duplicate key "TOKEN"' in warning.message
    assert "FAKE_TOKEN_FOR_TESTS" not in warning.message
    assert "one" not in warning.message


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("a: [1, 2\n", 2),
        ("a:\n\tb: 1\n", 2),
        ("a: 1\n b: 2\n", 2),
        ("a: 1\n---\nb: 2\n", 2),
        ('key: "unterminated\n', 2),
    ],
)
def test_yaml_malformed_input_is_a_warning(text: str, line: int) -> None:
    doc = parse_yaml(text, "bad.yml")
    assert doc.data is None
    [warning] = doc.warnings
    assert warning.file == "bad.yml"
    assert warning.line == line
    assert warning.message.startswith("invalid YAML")
    assert "\n" not in warning.message


def test_yaml_empty_file() -> None:
    doc = parse_yaml("", "empty.yml")
    assert doc.ok
    assert doc.data is None


def test_load_yaml_from_disk_uses_relative_posix_path(tmp_path: Path) -> None:
    path = tmp_path / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True)
    path.write_bytes(WORKFLOW.replace("\n", "\r\n").encode("utf-8"))
    doc = load_yaml(path, tmp_path)
    assert doc.file == ".github/workflows/ci.yml"
    assert doc.line_of(["permissions", "contents"]) == 6


def test_load_yaml_invalid_utf8_is_a_warning(tmp_path: Path) -> None:
    path = tmp_path / "bad.yml"
    path.write_bytes(b"name: \xff\xfe\n")
    doc = load_yaml(path, tmp_path)
    assert doc.data is None
    assert doc.warnings[0].message.startswith("not valid UTF-8")


def test_load_yaml_unreadable_file_is_a_warning(tmp_path: Path) -> None:
    doc = load_yaml(tmp_path / "missing.yml", tmp_path)
    assert doc.data is None
    assert doc.warnings[0].message.startswith("cannot read file")


# -- JSON ---------------------------------------------------------------------------------------

MCP = """\
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "-y",
        "example-server"
      ],
      "env": {
        "TOKEN": "FAKE_TOKEN_FOR_TESTS"
      }
    },
    "a/b": {"command": "x"},
    "m~n": {"command": "y"},
    "quote\\"d": {"command": "z"}
  }
}
"""


def test_json_nested_pointer() -> None:
    doc = parse_json(MCP, "mcp.json")
    assert doc.ok
    assert doc.line_of("") == 1
    assert doc.line_of("/mcpServers") == 2
    assert doc.line_of("/mcpServers/github") == 3
    assert doc.line_of("/mcpServers/github/env/TOKEN") == 10
    assert doc.data["mcpServers"]["github"]["env"]["TOKEN"] == "FAKE_TOKEN_FOR_TESTS"


def test_json_list_items() -> None:
    doc = parse_json(MCP, "mcp.json")
    assert doc.line_of("/mcpServers/github/args") == 5
    assert doc.line_of("/mcpServers/github/args/0") == 6
    assert doc.line_of("/mcpServers/github/args/1") == 7
    with pytest.raises(KeyError):
        doc.line_of("/mcpServers/github/args/2")


def test_json_pointer_escapes_for_duplicate_looking_keys() -> None:
    doc = parse_json(MCP, "mcp.json")
    assert doc.line_of("/mcpServers/a~1b") == 13
    assert doc.line_of("/mcpServers/a~1b/command") == 13
    assert doc.line_of("/mcpServers/m~0n") == 14
    assert doc.line_of('/mcpServers/quote"d') == 15
    assert pointer("mcpServers", "a/b") == "/mcpServers/a~1b"
    assert pointer("mcpServers", "m~n", 0) == "/mcpServers/m~0n/0"
    with pytest.raises(KeyError):
        doc.line_of("/mcpServers/a/b")  # a different path, not the "a/b" key


def test_json_same_key_in_sibling_objects() -> None:
    doc = parse_json('{"x": {"env": {"K": 1}},\n "y": {"env": {"K": 2}}}', "f.json")
    assert doc.line_of("/x/env/K") == 1
    assert doc.line_of("/y/env/K") == 2


def test_json_duplicate_key_last_wins_with_warning() -> None:
    text = '{\n  "s": {"old": 1},\n  "s": {\n    "new": "FAKE_TOKEN_FOR_TESTS"\n  }\n}\n'
    doc = parse_json(text, "dup.json")
    assert doc.data == {"s": {"new": "FAKE_TOKEN_FOR_TESTS"}}
    assert doc.line_of("/s") == 3
    assert doc.line_of("/s/new") == 4
    with pytest.raises(KeyError):
        doc.line_of("/s/old")
    [warning] = doc.warnings
    assert (warning.line, warning.message) == (
        3,
        'duplicate key "s" (first on line 2); the last one is used',
    )


def test_json_invalid_pointer_raises_value_error() -> None:
    doc = parse_json(MCP, "mcp.json")
    with pytest.raises(ValueError):
        doc.line_of("mcpServers")
    with pytest.raises(ValueError):
        doc.line_of("/bad~2escape")


def test_json_crlf_and_bom(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_bytes(b"\xef\xbb\xbf" + MCP.replace("\n", "\r\n").encode("utf-8"))
    doc = load_json(path, tmp_path)
    assert doc.ok
    assert doc.file == ".mcp.json"
    assert doc.line_of("/mcpServers/github/env/TOKEN") == 10


def test_json_scalars_and_empty_containers() -> None:
    doc = parse_json('{"a": [],\n"b": {},\n"c": [true, null, -1.5e3, "s"]\n}', "f.json")
    assert doc.line_of("/b") == 2
    assert doc.line_of("/c/3") == 3


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ('{\n  "a": 1,\n}\n', 3),  # trailing comma
        ('{\n  // comment\n  "a": 1\n}\n', 2),
        ('{\n  "a": \n', 3),
        ("", 1),
        ('{"a": "FAKE_TOKEN_FOR_TESTS" "b": 2}', 1),
    ],
)
def test_json_malformed_input_is_a_warning(text: str, line: int) -> None:
    doc = parse_json(text, "bad.json")
    assert doc.data is None
    [warning] = doc.warnings
    assert (warning.file, warning.line) == ("bad.json", line)
    assert warning.message.startswith("invalid JSON")
    assert "FAKE_TOKEN_FOR_TESTS" not in warning.message
    with pytest.raises(KeyError):
        doc.line_of("/a")


def test_json_deep_nesting_is_a_warning() -> None:
    doc = parse_json("[" * 100_000 + "]" * 100_000, "deep.json")
    assert doc.data is None
    assert "nested too deeply" in doc.warnings[0].message
