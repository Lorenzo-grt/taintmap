"""File loaders that keep 1-based line numbers for every key and list item."""

from taintmap.loaders.json_lines import JsonDocument, load_json, parse_json
from taintmap.loaders.yaml_lines import YamlDocument, load_yaml, parse_yaml

__all__ = [
    "JsonDocument",
    "YamlDocument",
    "load_json",
    "load_yaml",
    "parse_json",
    "parse_yaml",
]
