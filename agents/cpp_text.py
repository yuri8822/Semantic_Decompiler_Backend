"""
Lightweight C/C++ text analysis — enough to locate top-level function
definitions and compare structural properties of two pieces of code. Not a
parser: the compiler is the real judge; this only has to be robust on
decompiler output and LLM-written functions.

All masking preserves character offsets, so positions found in masked text
index straight into the original.
"""

import re
from dataclasses import dataclass

_KEYWORD_CALLS = frozenset({
    "if", "while", "for", "switch", "return", "sizeof", "catch", "alignof", "decltype",
    "static_cast", "reinterpret_cast", "const_cast", "dynamic_cast", "typeid", "noexcept",
    "defined", "do", "else", "case", "new", "delete", "throw", "operator",
})


def mask(code: str, strings: bool = True) -> str:
    """Blank out comments (and, if `strings`, string/char literal contents)."""
    out = list(code)
    i, n = 0, len(code)
    while i < n:
        ch = code[i]
        if code.startswith("//", i):
            j = code.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif code.startswith("/*", i):
            j = code.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif ch in ('"', "'"):
            j = i + 1
            while j < n and code[j] != ch and code[j] != "\n":
                j += 2 if code[j] == "\\" else 1
            if strings:
                for k in range(i + 1, min(j, n)):
                    out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


@dataclass
class Definition:
    name: str          # qualified name as written, e.g. "Player::TakeDamage"
    head: str          # text before the opening brace, comments removed
    params: str        # raw parameter list text
    start: int         # start of the definition (including a comment block above it)
    end: int           # one past the closing brace

    @property
    def param_count(self) -> int:
        p = self.params.strip()
        if not p or p == "void":
            return 0
        depth, count = 0, 1
        for ch in p:
            if ch in "(<[":
                depth += 1
            elif ch in ")>]":
                depth -= 1
            elif ch == "," and depth == 0:
                count += 1
        return count

    @property
    def return_part(self) -> str:
        """Everything in the head before the function name."""
        idx = self.head.find(self.name)
        prefix = self.head[:idx] if idx >= 0 else ""
        return re.sub(r"\b(static|inline|virtual|extern|constexpr)\b", " ", prefix).strip()


def find_definitions(code: str) -> list:
    """Top-level function definitions in `code` (class bodies, namespaces ignored)."""
    m = mask(code)
    defs = []
    depth, boundary, i, n = 0, 0, 0, len(m)
    while i < n:
        ch = m[i]
        if ch == "{":
            if depth == 0:
                head = m[boundary:i].strip()
                close = _matching(m, i, "{", "}")
                if close is None:
                    break
                d = _as_function(head)
                if d:
                    name, params = d
                    defs.append(Definition(name, head, params, _skip_space(code, boundary), close + 1))
                    i = close + 1
                    boundary = i
                    continue
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
            if depth == 0:
                boundary = i + 1
        elif ch == ";" and depth == 0:
            boundary = i + 1
        i += 1
    return defs


def _as_function(head: str):
    if not head or re.match(r"^(class|struct|union|enum|namespace|typedef|extern\s+\"C\"|template)\b", head):
        return None
    head = re.sub(r"^\s*#.*$", "", head, flags=re.MULTILINE).strip()
    open_idx = head.find("(")
    if open_idx <= 0:
        return None
    close_idx = _matching(head, open_idx, "(", ")")
    if close_idx is None:
        return None
    before = head[:open_idx].rstrip()
    mname = re.search(r"((?:[A-Za-z_]\w*\s*::\s*)*~?[A-Za-z_]\w*)\s*$", before)
    if not mname or mname.group(1) in _KEYWORD_CALLS:
        return None
    name = re.sub(r"\s+", "", mname.group(1))
    return name, head[open_idx + 1:close_idx]


def _matching(text: str, open_idx: int, open_ch: str, close_ch: str):
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return None


def _skip_space(code: str, j: int) -> int:
    # The span from the previous top-level boundary already includes any
    # comment block directly above the head; only leading blank space goes.
    while j < len(code) and code[j].isspace():
        j += 1
    return j


def extract_definition(code: str, qualified: str, name: str):
    """The definition of `qualified` (or one ending in `::name`) in `code`, else None."""
    defs = find_definitions(code)
    for d in defs:
        if d.name == qualified:
            return d
    for d in defs:
        if d.name == name or d.name.endswith("::" + name.lstrip("~")) or d.name.endswith("::" + name):
            return d
    return defs[0] if len(defs) == 1 else None


def decision_points(code: str) -> int:
    """if / loops / case labels / short-circuit operators / ternaries."""
    m = mask(code)
    return (len(re.findall(r"\b(if|while|for|case)\b", m))
            + m.count("&&") + m.count("||")
            + len(re.findall(r"\?(?!\?)", m)))


def called_names(code: str) -> set:
    """Identifiers used in call position: foo(...), A::foo(...), obj->foo(...)."""
    m = mask(code)
    names = set()
    for match in re.finditer(r"((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\(", m):
        full = match.group(1)
        last = full.split("::")[-1]
        if last not in _KEYWORD_CALLS:
            names.add(full)
            names.add(last)
    return names


def identifiers(code: str) -> set:
    return set(re.findall(r"[A-Za-z_]\w*", mask(code)))


def returns_value(code: str) -> bool:
    return bool(re.search(r"\breturn\b\s*[^;\s]", mask(code)))
