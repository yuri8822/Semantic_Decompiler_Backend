"""Pulling structured answers (JSON objects, C++ code blocks) out of model text."""

import json
import re

_FENCE_RE = re.compile(r"```[ \t]*([A-Za-z0-9_+-]*)[ \t]*\n(.*?)(?:\n[ \t]*```|\Z)", re.DOTALL)


class ParseError(ValueError):
    pass


def extract_json(text: str) -> dict:
    """
    The first JSON object in `text`: inside a fenced block if there is one,
    otherwise the first balanced {...} span. Tolerates trailing commas and
    // comments, which models emit often enough to be worth absorbing.
    """
    candidates = [body for lang, body in _FENCE_RE.findall(text) if lang.lower() in ("", "json")]
    candidates.append(text)
    last_error = None
    for candidate in candidates:
        span = _first_object_span(candidate)
        if span is None:
            continue
        raw = candidate[span[0]:span[1]]
        for attempt in (raw, _relax(raw)):
            try:
                value = json.loads(attempt)
            except json.JSONDecodeError as exc:
                last_error = exc
                continue
            if isinstance(value, dict):
                return value
    raise ParseError(f"no JSON object found ({last_error})" if last_error else "no JSON object found")


def _first_object_span(text: str):
    start = text.find("{")
    while start != -1:
        depth, in_str, escape = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return start, i + 1
        start = text.find("{", start + 1)
    return None


def _relax(raw: str) -> str:
    out, in_str, escape, i = [], False, False, 0
    while i < len(raw):
        ch = raw[i]
        if in_str:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif raw.startswith("//", i):
            while i < len(raw) and raw[i] != "\n":
                i += 1
            continue
        else:
            out.append(ch)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def extract_code(text: str) -> str:
    """
    The C++ in a model answer: the largest fenced block tagged cpp/c++/c (or
    untagged), else the whole text with any stray fence lines removed.
    """
    blocks = [body for lang, body in _FENCE_RE.findall(text)
              if lang.lower() in ("", "cpp", "c++", "c", "cxx", "cc")]
    if blocks:
        return max(blocks, key=len).strip()
    text = re.sub(r"^[ \t]*```[A-Za-z0-9_+-]*[ \t]*$", "", text, flags=re.MULTILINE)
    return text.strip()
