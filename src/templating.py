"""Safe parameter substitution for playbook actions.

Supports `{{ alert.field }}` and `{{ playbook.field }}` interpolation only.
No expressions, no code execution -- keeps playbooks safe for analysts to edit
without opening a code-injection surface.
"""
from __future__ import annotations

import re
from typing import Any

_TOKEN = re.compile(r"\{\{\s*([a-zA-Z_][\w.]*)\s*\}\}")


def _lookup(path: str, scopes: dict[str, Any]) -> Any:
    head, *rest = path.split(".")
    if head not in scopes:
        raise KeyError(f"unknown scope '{head}' in template token '{path}'")
    value: Any = scopes[head]
    for part in rest:
        if isinstance(value, dict):
            if part not in value:
                raise KeyError(f"missing field '{part}' on '{head}' in '{path}'")
            value = value[part]
        else:
            value = getattr(value, part)
    return value


def render(value: Any, scopes: dict[str, Any]) -> Any:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            return str(_lookup(match.group(1), scopes))
        return _TOKEN.sub(replace, value)
    if isinstance(value, dict):
        return {k: render(v, scopes) for k, v in value.items()}
    if isinstance(value, list):
        return [render(item, scopes) for item in value]
    return value
