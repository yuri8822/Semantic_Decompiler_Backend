"""
Identifier and type-name normalization between the three vocabularies in
play: Ghidra's (undefined4, longlong, FUN_1400...), C++'s (uint32_t, long
long, Player::TakeDamage), and whatever the LLM wrote.
"""

import re

# ---------------------------------------------------------------------------
# Ghidra default names (auto-generated, safe to replace)
# ---------------------------------------------------------------------------

_DEFAULT_FUNCTION_RE = re.compile(r"^(FUN|thunk_FUN|SUB|LAB|Unwind@|Catch@|entry)_?[0-9a-fA-F]*$")
_DEFAULT_VARIABLE_RE = re.compile(
    r"^(param_\d+|local_[0-9a-fA-F_]+|local_res[0-9a-fA-F]+|[a-z]{1,6}Var\d+|in_\w+|unaff_\w+|"
    r"extraout_\w+|in_stack_\w+|[a-z]{1,4}Stack_[0-9a-fA-F]+|stack0x[0-9a-fA-F]+)$"
)
_DEFAULT_GLOBAL_RE = re.compile(
    r"^(DAT|PTR_DAT|PTR|UNK|BYTE|WORD|DWORD|QWORD|INT|UINT|LONG|FLOAT|DOUBLE|"
    r"PTR_LOOP|switchD|caseD|s|u)_[0-9a-fA-F_]+$|^PTR_\w+_[0-9a-fA-F]{6,}$"
)

# Ghidra decompiler artifacts that should not survive into readable C++.
DECOMPILER_RESIDUE_RE = re.compile(
    r"\b(FUN_[0-9a-fA-F]+|DAT_[0-9a-fA-F]+|PTR_\w*_?[0-9a-fA-F]{6,}|param_\d+|local_[0-9a-fA-F]+|"
    r"[a-z]{1,6}Var\d+|in_[A-Z]{2,3}\b|unaff_\w+|extraout_\w+|CONCAT\d\d|SUB\d\d|ZEXT\d\d|SEXT\d\d|"
    r"undefined[1248]?\b|code\s*\*)"
)


def is_default_function_name(name: str) -> bool:
    return bool(_DEFAULT_FUNCTION_RE.match(name))


def is_default_variable_name(name: str) -> bool:
    return bool(_DEFAULT_VARIABLE_RE.match(name))


def is_default_global_name(name: str) -> bool:
    return bool(_DEFAULT_GLOBAL_RE.match(name))


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------

CPP_KEYWORDS = frozenset("""
alignas alignof and and_eq asm auto bitand bitor bool break case catch char char8_t char16_t
char32_t class compl concept const consteval constexpr constinit const_cast continue co_await
co_return co_yield decltype default delete do double dynamic_cast else enum explicit export
extern false float for friend goto if inline int long mutable namespace new noexcept not not_eq
nullptr operator or or_eq private protected public register reinterpret_cast requires return
short signed sizeof static static_assert static_cast struct switch template this thread_local
throw true try typedef typeid typename union unsigned using virtual void volatile wchar_t while
xor xor_eq
""".split())


def split_qualified(name: str) -> list:
    """'A::B<x::y>::C' -> ['A', 'B<x::y>', 'C'] (ignores '::' inside templates)."""
    parts, depth, cur, i = [], 0, [], 0
    while i < len(name):
        ch = name[i]
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        if depth == 0 and name.startswith("::", i):
            parts.append("".join(cur))
            cur = []
            i += 2
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p for p in parts if p]


def sanitize_identifier(name: str, fallback: str = "unnamed") -> str:
    """A valid C++ identifier from a Ghidra/LLM name ('Draw[abi:cxx11]' -> 'Draw')."""
    name = re.sub(r"\[abi:[^\]]*\]", "", name or "")
    destructor = name.startswith("~")
    name = re.sub(r"<.*>", "", name.lstrip("~"))
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", name)
    if cleaned != name:
        cleaned = cleaned.rstrip("_")   # only trailing junk the replacement introduced
    name = cleaned or fallback
    if name[0].isdigit():
        name = "_" + name
    if name in CPP_KEYWORDS:
        name += "_"
    return ("~" + name) if destructor else name


def sanitize_class_name(qualified: str) -> str:
    """Flatten a (possibly nested) class path into one identifier: 'ns::Player' -> 'ns_Player'."""
    parts = [sanitize_identifier(p) for p in split_qualified(qualified)]
    return "_".join(p.lstrip("~") for p in parts) if parts else ""


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

_GHIDRA_TO_CPP = {
    "undefined": "uint8_t", "undefined1": "uint8_t", "undefined2": "uint16_t",
    "undefined4": "uint32_t", "undefined8": "uint64_t",
    "byte": "uint8_t", "sbyte": "int8_t", "word": "uint16_t", "dword": "uint32_t", "qword": "uint64_t",
    "uchar": "unsigned char", "ushort": "unsigned short", "uint": "unsigned int", "ulong": "unsigned long",
    "longlong": "long long", "ulonglong": "unsigned long long",
    "uint3": "uint32_t", "int3": "int32_t", "uint5": "uint64_t", "uint6": "uint64_t", "uint7": "uint64_t",
    "int5": "int64_t", "int6": "int64_t", "int7": "int64_t", "uint16": "unsigned __int128",
    "float10": "long double", "code": "void", "pointer": "void *", "string": "char",
    "wchar16": "char16_t", "wchar32": "char32_t", "_Bool": "bool",
}

_CPP_TO_GHIDRA = {
    "int": "int", "signed int": "int", "int32_t": "int", "signed": "int",
    "unsigned int": "uint", "unsigned": "uint", "uint32_t": "uint", "DWORD": "uint",
    "short": "short", "int16_t": "short", "unsigned short": "ushort", "uint16_t": "ushort", "WORD": "ushort",
    "char": "char", "signed char": "char", "int8_t": "char",
    "unsigned char": "uchar", "uint8_t": "uchar", "BYTE": "byte",
    "long": "long", "unsigned long": "ulong",
    "long long": "longlong", "int64_t": "longlong", "intptr_t": "longlong", "ptrdiff_t": "longlong",
    "unsigned long long": "ulonglong", "uint64_t": "ulonglong", "uintptr_t": "ulonglong",
    "bool": "bool", "BOOL": "int", "float": "float", "double": "double", "long double": "float10",
    "void": "void", "wchar_t": "wchar_t", "char16_t": "wchar16", "char32_t": "wchar32",
}

PRIMITIVE_SIZES = {
    "char": 1, "signed char": 1, "unsigned char": 1, "int8_t": 1, "uint8_t": 1, "bool": 1,
    "short": 2, "unsigned short": 2, "int16_t": 2, "uint16_t": 2, "wchar_t": 2, "char16_t": 2,
    "int": 4, "unsigned int": 4, "int32_t": 4, "uint32_t": 4, "float": 4, "long": 4,
    "unsigned long": 4, "char32_t": 4,
    "long long": 8, "unsigned long long": 8, "int64_t": 8, "uint64_t": 8, "double": 8,
    "intptr_t": 8, "uintptr_t": 8, "size_t": 8, "ptrdiff_t": 8,
}

_QUALIFIER_RE = re.compile(r"\b(const|volatile|struct|class|enum|union)\b")


def split_type(type_str: str):
    """'const Player * *' -> ('Player', 2). References count as pointers."""
    t = _QUALIFIER_RE.sub(" ", type_str or "").replace("&", "*")
    pointers = t.count("*")
    t = re.sub(r"\s+", " ", t.replace("*", " ")).strip()
    return t, pointers


def ghidra_to_cpp_type(type_str: str) -> str:
    """
    Ghidra display type or LLM-written type -> normalized readable C++
    ('undefined4' -> 'uint32_t', 'char * *' -> 'char **', 'const std::string&'
    -> 'const std::string &'). A leading const and one reference survive.
    """
    t = re.sub(r"\s+", " ", (type_str or "").strip())
    lead_const = bool(re.match(r"^const\b", t))
    has_ref = "&" in t
    base, pointers = split_type(t.replace("&", ""))
    if not base:
        base = "void"
    m = re.match(r"^(\w+)\s*\[(\d*)\]$", base)
    if m:  # arrays decay to pointers in signatures
        base, pointers = m.group(1), pointers + 1
    cpp = _GHIDRA_TO_CPP.get(base, base)
    if cpp.endswith("*"):
        cpp, pointers = cpp.rstrip(" *"), pointers + 1
    out = ("const " if lead_const else "") + cpp
    if pointers:
        out += " " + "*" * pointers
    if has_ref:
        out += " &"
    return out


def ghidra_return_to_cpp(type_str: str) -> str:
    """Return types: Ghidra's bare 'undefined' means 'unknown/none', i.e. void."""
    return "void" if (type_str or "").strip() in ("", "undefined") else ghidra_to_cpp_type(type_str)


def cpp_to_ghidra_type(type_str: str, known_classes=(), pointer_size: int = 8):
    """
    C++/LLM type -> a name ApplyKnowledge.java can resolve, or None when
    Ghidra has no faithful equivalent (std::string by value, templates...).
    """
    base, pointers = split_type(type_str)
    if not base:
        return None
    if base in ("size_t", "ssize_t"):
        base = "ulonglong" if pointer_size == 8 else "uint"
    if base in _CPP_TO_GHIDRA:
        ghidra = _CPP_TO_GHIDRA[base]
    elif base in known_classes:
        ghidra = base
    elif "::" in base or "<" in base:
        if not pointers:
            return None
        ghidra = "void"
    elif base in _GHIDRA_TO_CPP or re.match(r"^[A-Za-z_]\w*$", base):
        ghidra = base   # already a Ghidra name, or a class Ghidra may know
    else:
        return None
    return ghidra + (" " + "*" * pointers if pointers else "")


def type_size(type_str: str, pointer_size: int = 8, class_sizes: dict = None) -> int:
    base, pointers = split_type(ghidra_to_cpp_type(type_str))
    if pointers:
        return pointer_size
    if base in PRIMITIVE_SIZES:
        return PRIMITIVE_SIZES[base]
    if base == "std::string":
        return 32 if pointer_size == 8 else 24
    if class_sizes and base in class_sizes:
        return class_sizes[base]
    return 0
