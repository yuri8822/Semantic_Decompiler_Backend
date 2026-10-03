"""
Writes the reconstructed C++ project:

    reconstructed/
        CMakeLists.txt
        include/ghidra_types.h     typedefs/macros for residual Ghidra types
        include/types.h            every reconstructed class with its layout
        include/functions.h        free-function prototypes and globals
        include/reconstructed.h    umbrella header
        src/<Class>.cpp            member function definitions per class
        src/functions.cpp          free function definitions
        src/globals.cpp            global variable definitions
        function_map.json          source line ranges -> function address

Headers are generated deterministically from the knowledge base, never by
the LLM, and are built to always compile: class layouts use explicit
padding under #pragma pack(1) so recovered offsets are exact, and any type
name the knowledge base can't define becomes an opaque placeholder.
"""

import json
import re
from collections import defaultdict
from pathlib import Path

from knowledge.confidence import accepted, needs_todo
from knowledge.filters import is_imported_data
from knowledge.naming import PRIMITIVE_SIZES, ghidra_to_cpp_type, sanitize_identifier, split_type

_STD_TYPES = ("std::",)
_BUILTIN = set(PRIMITIVE_SIZES) | {
    "void", "char", "short", "int", "long", "float", "double", "bool", "signed", "unsigned", "wchar_t",
    "size_t", "char16_t", "char32_t", "long double", "unsigned __int128", "__int128",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8", "byte", "sbyte", "word", "dword",
    "qword", "uchar", "ushort", "uint", "ulong", "longlong", "ulonglong", "code", "float10",
}

GHIDRA_TYPES_H = """#pragma once
// Support definitions for types and helpers that Ghidra's decompiler uses.
// Reconstructed code should not need these; they let residual decompiler
// idioms compile while they are being cleaned up.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

typedef unsigned char undefined;
typedef uint8_t undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
typedef uint8_t byte;
typedef int8_t sbyte;
typedef uint16_t word;
typedef uint32_t dword;
typedef uint64_t qword;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef long double float10;
typedef void code;

#define CONCAT11(hi, lo) ((uint16_t)(((uint16_t)(uint8_t)(hi) << 8) | (uint8_t)(lo)))
#define CONCAT22(hi, lo) ((uint32_t)(((uint32_t)(uint16_t)(hi) << 16) | (uint16_t)(lo)))
#define CONCAT44(hi, lo) ((uint64_t)(((uint64_t)(uint32_t)(hi) << 32) | (uint32_t)(lo)))
#define ZEXT14(x) ((uint32_t)(uint8_t)(x))
#define ZEXT24(x) ((uint32_t)(uint16_t)(x))
#define ZEXT48(x) ((uint64_t)(uint32_t)(x))
#define SEXT14(x) ((int32_t)(int8_t)(x))
#define SEXT24(x) ((int32_t)(int16_t)(x))
#define SEXT48(x) ((int64_t)(int32_t)(x))
#define SUB41(x, n) ((uint8_t)((uint32_t)(x) >> ((n) * 8)))
#define SUB42(x, n) ((uint16_t)((uint32_t)(x) >> ((n) * 8)))
#define SUB81(x, n) ((uint8_t)((uint64_t)(x) >> ((n) * 8)))
#define SUB84(x, n) ((uint32_t)((uint64_t)(x) >> ((n) * 8)))
"""


def _looks_like_sdk_type(name: str) -> bool:
    """HANDLE, DWORD, LPVOID, PIMAGE_SECTION_HEADER, FILE... come from system headers."""
    return bool(re.match(r"^[A-Z][A-Z0-9_]*$", name)) or name in ("FILE", "va_list", "jmp_buf")


def type_identifiers(type_str: str) -> list:
    """Identifiers in a type that might need a definition ('Board *' -> ['Board'])."""
    base, _ = split_type(type_str)
    if not base or base in _BUILTIN or base.startswith(_STD_TYPES) or " " in base:
        return []
    base = re.sub(r"\[.*\]$", "", base)
    return [base] if re.match(r"^[A-Za-z_]\w*$", base) else []


class ProjectWriter:
    def __init__(self, root: Path, kb, ir, signatures: dict, project_name: str):
        self.root = Path(root)
        self.kb = kb
        self.ir = ir
        self.sigs = signatures
        self.name = re.sub(r"[^A-Za-z0-9_]", "_", project_name)
        self.ptr = ir.program.pointer_size
        self._emit_rank = {}   # class -> position in types.h, set by _dependency_order
        self._hoist_cache = {}

    @property
    def include_dir(self) -> Path:
        return self.root / "include"

    @property
    def src_dir(self) -> Path:
        return self.root / "src"

    # -- headers -----------------------------------------------------------------

    def write_headers(self):
        self.include_dir.mkdir(parents=True, exist_ok=True)
        (self.include_dir / "ghidra_types.h").write_text(GHIDRA_TYPES_H, encoding="utf-8")
        (self.include_dir / "types.h").write_text(self._types_header(), encoding="utf-8")
        (self.include_dir / "functions.h").write_text(self._functions_header(), encoding="utf-8")
        (self.include_dir / "reconstructed.h").write_text(
            "#pragma once\n#include \"ghidra_types.h\"\n#include \"types.h\"\n#include \"functions.h\"\n",
            encoding="utf-8",
        )

    def class_names(self) -> list:
        names = set(self.kb.types)
        names |= {s.class_name for s in self.sigs.values() if s.is_member}
        return sorted(names)

    def _placeholders(self, classes: set) -> list:
        needed = set()
        for s in self.sigs.values():
            for t in [s.return_type] + [p.type for p in s.params]:
                needed.update(type_identifiers(t))
        for t in self.kb.types.values():
            for f in t.fields:
                needed.update(type_identifiers(f.type))
        for g in self._globals():
            needed.update(type_identifiers(g[1]))
        return sorted(n for n in needed if n not in classes and not _looks_like_sdk_type(n))

    def _types_header(self) -> str:
        classes = self.class_names()
        class_set = set(classes)
        out = ["#pragma once", "#include \"ghidra_types.h\"", "",
               "// Forward declarations", ""]
        out += [f"{self._kind(c)} {c};" for c in classes]
        placeholders = self._placeholders(class_set)
        if placeholders:
            out += ["", "// Types referenced by recovered signatures whose layout is unknown"]
            out += [f"struct {p} {{ /* TODO: layout not recovered */ }};" for p in placeholders]
        out.append("")
        for c in self._dependency_order(classes):
            out.append(self._class_definition(c, class_set))
        return "\n".join(out) + "\n"

    def _kind(self, name: str) -> str:
        t = self.kb.types.get(name)
        return t.kind if t else "class"

    def _dependency_order(self, classes: list) -> list:
        """Bases and by-value members before the classes that contain them."""
        deps = {}
        for c in classes:
            t = self.kb.types.get(c)
            d = set()
            if t:
                if t.base_class:
                    d.add(t.base_class)
                for f in t.fields:
                    base, ptrs = split_type(f.type)
                    if not ptrs and base in classes:
                        d.add(base)
            deps[c] = d & set(classes)
        order, state = [], {}

        def visit(c):
            if state.get(c) == 2:
                return
            if state.get(c) == 1:
                return  # cycle: by-value member emitted as raw bytes (see _field_line)
            state[c] = 1
            for d in sorted(deps[c]):
                visit(d)
            state[c] = 2
            order.append(c)

        for c in classes:
            visit(c)
        self._emit_rank = {c: i for i, c in enumerate(order)}
        return order

    def _class_definition(self, name: str, class_set: set) -> str:
        t = self.kb.types.get(name)
        members = sorted((s for s in self.sigs.values() if s.is_member and s.class_name == name),
                         key=lambda s: s.address)
        base = self._accepted_base(t)
        head = f"{self._kind(name)} {name}" + (f" : public {base}" if base else "")
        lines = []
        if t:
            lines.append(f"// {name}: size {t.size:#x}, layout confidence {t.confidence:.2f}"
                         + (f" - {t.notes[:160]}" if t.notes else ""))
        lines += ["#pragma pack(push, 1)", head + " {", "public:"]
        for s in members:
            note = f"  // {s.address}" + (" TODO: " + "; ".join(x.split(': ', 1)[-1] for x in s.todos)
                                          if s.todos else "")
            lines.append(f"    {s.declaration()}{note}")
        lines += self._layout_lines(name, t, base)
        lines += ["};", "#pragma pack(pop)", ""]
        return "\n".join(lines)

    def _accepted_base(self, t) -> str:
        if t and t.base_class and t.base_class in self.kb.types and accepted(t.base_confidence):
            return t.base_class
        return ""

    def _hoisted(self, name: str) -> list:
        """
        [(field, [classes])] that derived classes place inside this class's own
        byte range where it declares nothing (e.g. Rook::x and Knight::x at
        +0x8 inside Piece). C++ can't put a derived member into a base's gap,
        so they are declared in the base, where the binary actually has them;
        the derived classes inherit them at the same offsets. When siblings
        disagree, the definition most of them share wins.
        """
        if name in self._hoist_cache:
            return self._hoist_cache[name]
        self._hoist_cache[name] = []   # guards against cycles while computing
        t = self.kb.types.get(name)
        if t is None:
            return []
        base = self._accepted_base(t)
        start = self._emitted_size(base) if base else 0
        own = [f for f in t.fields if accepted(f.confidence)]
        groups = defaultdict(list)
        for d in self.kb.types.values():
            if self._accepted_base(d) != name:
                continue
            for f in d.fields:
                if (not accepted(f.confidence) or f.offset < start or f.offset + f.size > t.size
                        or any(f.offset < o.offset + o.size and o.offset < f.offset + f.size for o in own)):
                    continue
                groups[f.offset].append((f, d.name))
        chosen = []
        for off, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            votes = defaultdict(list)
            for f, cls in items:
                votes[(sanitize_identifier(f.name), ghidra_to_cpp_type(f.type) if f.type else "", f.size)].append((f, cls))
            best = max(votes.values(), key=lambda v: (len(v), max(f.confidence for f, _ in v)))
            f = best[0][0]
            if any(f.offset < c.offset + c.size and c.offset < f.offset + f.size for c, _ in chosen):
                continue
            chosen.append((f, sorted({cls for _, cls in items})))
        chosen.sort(key=lambda fc: fc[0].offset)
        self._hoist_cache[name] = chosen
        return chosen

    def _own_fields(self, name: str) -> list:
        """(field, note) pairs this class declares: its accepted fields plus hoisted ones."""
        t = self.kb.types.get(name)
        if t is None:
            return []
        out = [(f, "") for f in t.fields if accepted(f.confidence)]
        out += [(f, f"shared by {', '.join(classes)}") for f, classes in self._hoisted(name)]
        return sorted(out, key=lambda fn: fn[0].offset)

    def _declared_end(self, name: str) -> int:
        """End of the last declared field, including inherited and hoisted ones."""
        t = self.kb.types.get(name)
        if t is None:
            return 0
        end = self._emitted_size(self._accepted_base(t)) if self._accepted_base(t) else 0
        for f, _ in self._own_fields(name):
            end = max(end, f.offset + f.size)
        return end

    def _emitted_size(self, name: str) -> int:
        """
        The size a class is emitted with. Normally its recovered size, but
        when a derived class owns fields inside this class's undeclared tail
        (fields the base itself never revealed), the base is emitted only up
        to its last declared field, so the derived fields land at their exact
        offsets after it.
        """
        t = self.kb.types.get(name)
        if t is None:
            return 0
        declared = self._declared_end(name)
        for other in self.kb.types.values():
            if self._accepted_base(other) == name and any(
                    accepted(f.confidence) and declared <= f.offset < t.size for f in other.fields):
                return declared
        return max(t.size, declared)

    def _layout_lines(self, name: str, t, base: str) -> list:
        if t is None:
            return ["    // layout not reconstructed"]
        lines = ["", "    // data members - offsets recovered from the binary"]
        cur = self._emitted_size(base) if base else 0
        for f, note in self._own_fields(name):
            if f.offset < cur:
                continue
            if f.offset > cur:
                lines.append(f"    uint8_t _pad_{cur:x}[{f.offset - cur:#x}];")
            lines.append(self._field_line(name, f) + (f"  ({note})" if note else ""))
            cur = f.offset + f.size
        size = self._emitted_size(name)
        if size > cur:
            lines.append(f"    uint8_t _pad_{cur:x}[{size - cur:#x}];")
        if size < t.size:
            lines.append(f"    // recovered size {t.size:#x}; bytes {size:#x}.. are laid out by derived classes")
        return lines

    def _field_line(self, owner: str, f) -> str:
        ctype = ghidra_to_cpp_type(f.type) if f.type else ""
        base, ptrs = split_type(ctype)
        note = f"// +{f.offset:#x}" + (f"  TODO: medium-confidence field ({f.confidence:.2f})"
                                       if needs_todo(f.confidence) else "")
        name = sanitize_identifier(f.name)
        known_size = (self.ptr if ptrs else PRIMITIVE_SIZES.get(base)
                      or (32 if base == "std::string" and self.ptr == 8 else None))
        by_value_class = (not ptrs and base in self.kb.types
                          and self._emit_rank.get(base, 1 << 30) < self._emit_rank.get(owner, 0)
                          and self.kb.types[base].size == f.size)
        if ctype and (known_size == f.size or by_value_class):
            return f"    {ctype} {name}; {note}"
        if ctype and ptrs:
            return f"    {ctype} {name}; {note}"
        return f"    uint8_t {name}[{f.size:#x}]; {note} ({f.type or 'unknown type'})"

    def _globals(self) -> list:
        """(name, type, address) for program globals referenced by in-scope functions."""
        seen, out, used = {}, [], set()
        fn_names = {s.name for s in self.sigs.values()}
        for addr in sorted(self.sigs):
            fn = self.ir.get(addr)
            for g in fn.globals if fn else []:
                if g.external or not g.address or is_imported_data(g.name) or g.address in seen:
                    continue
                rec = self.kb.globals.get(g.address)
                if rec and rec.name and accepted(rec.confidence):
                    name, ctype = rec.name, ghidra_to_cpp_type(rec.type or g.type)
                else:
                    name, ctype = g.name, ghidra_to_cpp_type(g.type) if g.type else "uint64_t"
                name = sanitize_identifier(name)
                if ctype == "void":
                    ctype = "uint64_t"
                base, n = name, 2
                while name in used or name in fn_names:
                    name, n = f"{base}_{n}", n + 1
                used.add(name)
                seen[g.address] = name
                out.append((name, ctype, g.address))
        return out

    def _functions_header(self) -> str:
        out = ["#pragma once", "#include \"types.h\"", "", "// Free functions", ""]
        for s in sorted((s for s in self.sigs.values() if not s.is_member), key=lambda s: s.address):
            if s.name != "main":  # main must not be declared
                out.append(f"{s.declaration()}  // {s.address}")
        out += ["", "// Globals", ""]
        for name, ctype, addr in self._globals():
            out.append(f"extern {_decl(ctype, name)};  // {addr}")
        return "\n".join(out) + "\n"

    # -- sources ---------------------------------------------------------------

    def write_sources(self, banner_of) -> dict:
        """
        `banner_of(addr)` -> (comment_lines, code, compiles) for every function
        with code. Returns {relative_file: [(start_line, end_line, addr)]}.
        """
        self.src_dir.mkdir(parents=True, exist_ok=True)
        for old in self.src_dir.glob("*.cpp"):
            old.unlink()
        groups = defaultdict(list)
        for addr, s in sorted(self.sigs.items()):
            groups[s.class_name if s.is_member else ""].append(s)

        line_map = {}
        for cls, sigs in sorted(groups.items()):
            fname = f"{cls}.cpp" if cls else "functions.cpp"
            lines = ["#include \"reconstructed.h\"", ""]
            spans = []
            for s in sigs:
                info = banner_of(s.address)
                if info is None:
                    continue
                banner, code, compiles = info
                lines.append("// " + "-" * 76)
                lines += [f"// {b}" for b in banner]
                lines.append("// " + "-" * 76)
                if not compiles:
                    lines.append("#if 0  // does not compile yet - see report.md")
                start = len(lines) + 1
                lines += code.splitlines()
                spans.append((start, len(lines), s.address))
                if not compiles:
                    lines.append("#endif")
                lines.append("")
            (self.src_dir / fname).write_text("\n".join(lines) + "\n", encoding="utf-8")
            line_map[f"src/{fname}"] = spans

        globals_ = self._globals()
        g_lines = ["#include \"reconstructed.h\"", ""]
        g_lines += [f"{_decl(ctype, name)}{{}};  // {addr}" for name, ctype, addr in globals_]
        (self.src_dir / "globals.cpp").write_text("\n".join(g_lines) + "\n", encoding="utf-8")
        (self.root / "function_map.json").write_text(json.dumps(line_map, indent=2), encoding="utf-8")
        return line_map

    def write_cmake(self):
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "CMakeLists.txt").write_text(f"""cmake_minimum_required(VERSION 3.16)
project({self.name}_reconstructed CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Reconstructed from {self.ir.program.name} ({self.ir.program.language}).
# Built as a static library: functions excluded from reconstruction (C
# runtime, standard library internals) are not defined here, so a full
# link is not expected to succeed.
file(GLOB RECON_SOURCES CONFIGURE_DEPENDS ${{CMAKE_CURRENT_SOURCE_DIR}}/src/*.cpp)
add_library({self.name}_reconstructed STATIC ${{RECON_SOURCES}})
target_include_directories({self.name}_reconstructed PUBLIC ${{CMAKE_CURRENT_SOURCE_DIR}}/include)
""", encoding="utf-8")


def _decl(ctype: str, name: str) -> str:
    return f"{ctype}{name}" if ctype.endswith("*") else f"{ctype} {name}"
