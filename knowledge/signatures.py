"""
The final C++ shape of every in-scope function — class, name, kind, return
type, parameters — decided once from Ghidra's facts plus the analyzer's
confidence-gated guesses. The header declaration, the code-reconstruction
prompt and the validator all read this same signature, so they cannot drift.

Names that came from symbols (Ghidra name_source other than DEFAULT, or our
own USER_DEFINED renames) are authoritative: the analyzer refines their
parameters and locals but never renames them.
"""

from dataclasses import dataclass, field

from ghidra_io.ir import FunctionIR
from knowledge.confidence import accepted, needs_todo, todo
from knowledge.models import FunctionRecord
from knowledge.naming import (
    ghidra_return_to_cpp, ghidra_to_cpp_type, sanitize_class_name, sanitize_identifier, split_qualified,
)

MEMBER_KINDS = ("method", "virtual", "constructor", "destructor", "static")
_RENAMABLE_SOURCES = ("DEFAULT", "USER_DEFINED")


@dataclass
class CppParam:
    type: str
    name: str

    def render(self) -> str:
        t = self.type
        return f"{t}{self.name}" if t.endswith(("*", "&")) else f"{t} {self.name}"


@dataclass
class CppSignature:
    address: str
    class_name: str
    name: str
    kind: str
    return_type: str
    params: list = field(default_factory=list)
    todos: list = field(default_factory=list)

    @property
    def is_member(self) -> bool:
        return bool(self.class_name) and self.kind in MEMBER_KINDS

    @property
    def qualified(self) -> str:
        return f"{self.class_name}::{self.name}" if self.is_member else self.name

    def _params(self) -> str:
        return ", ".join(p.render() for p in self.params)

    def _head(self, name: str) -> str:
        if self.kind in ("constructor", "destructor"):
            return f"{name}({self._params()})"
        sep = "" if self.return_type.endswith(("*", "&")) else " "
        return f"{self.return_type}{sep}{name}({self._params()})"

    def declaration(self) -> str:
        """
        Inside the class body (members) or at namespace scope (free
        functions). Never `virtual`: vtables are not reconstructed in V1, and
        a compiler-generated vptr would shift every recovered field offset
        (an observed vtable pointer is an explicit `vftable` field instead).
        """
        prefix = "static " if self.kind == "static" else ""
        return prefix + self._head(self.name) + ";"

    def definition_head(self) -> str:
        return self._head(self.qualified)

    def to_dict(self) -> dict:
        return {
            "address": self.address, "class": self.class_name, "name": self.name,
            "kind": self.kind, "return_type": self.return_type,
            "params": [{"type": p.type, "name": p.name} for p in self.params],
            "definition": self.definition_head(), "todos": self.todos,
        }


def name_is_renamable(fn: FunctionIR) -> bool:
    return fn.name_source in _RENAMABLE_SOURCES


def _ghidra_identity(fn: FunctionIR, analysis):
    cls = fn.namespace if fn.namespace_is_class else ""
    member = fn.name
    if not cls:
        return "", member, "free"
    last = split_qualified(cls)[-1]
    if analysis and analysis.method_kind in MEMBER_KINDS and analysis.method_kind != "free":
        kind = analysis.method_kind
    elif member.startswith("~"):
        kind = "destructor"
    elif sanitize_identifier(member) == sanitize_identifier(last):
        kind = "constructor"
    elif fn.parameters and fn.parameters[0].is_this:
        kind = "method"
    else:
        kind = "static"
    return cls, member, kind


def build_signature(rec: FunctionRecord, fn: FunctionIR) -> CppSignature:
    a = rec.analysis
    todos = []

    if a and accepted(a.name_confidence) and name_is_renamable(fn):
        parts = split_qualified(a.name) or [fn.name]
        member = parts[-1]
        cls = "::".join(parts[:-1]) or (a.class_name if a.is_method else "")
        kind = a.method_kind if cls else "free"
        if kind == "free" and cls:
            kind = "method"
        if needs_todo(a.name_confidence):
            todos.append(todo(f"name '{a.name}'", a.name_confidence))
    else:
        cls, member, kind = _ghidra_identity(fn, a)

    class_name = sanitize_class_name(cls) if cls else ""
    if kind in MEMBER_KINDS and not class_name:
        kind = "free"
    if kind == "constructor":
        name = class_name
    elif kind == "destructor":
        name = "~" + class_name
    else:
        name = sanitize_identifier(member.lstrip("~"), fallback=f"sub_{fn.address[2:]}")

    # -- parameters ---------------------------------------------------------
    guesses = {g.index: g for g in (a.params if a else [])}
    member_with_this = kind in MEMBER_KINDS and kind != "static"
    params, used = [], set()
    for p in sorted(fn.parameters, key=lambda p: p.index):
        g = guesses.get(p.index)
        role = g.role if g else ("this" if p.is_this else "return_slot" if p.hidden_return else "normal")
        if member_with_this and p.index == 0 and (role == "this" or p.is_this or p.name == "this"):
            continue
        if role == "return_slot" or (role == "this" and member_with_this):
            continue
        if g and g.name and accepted(g.confidence):
            pname, ptype = g.name, g.type or p.type
            if needs_todo(g.confidence):
                todos.append(todo(f"parameter '{g.name}'", g.confidence))
        else:
            pname, ptype = p.name, p.type
        pname = sanitize_identifier(pname, fallback=f"arg{p.index}")
        if pname == "this":
            pname = "self"
        base, n = pname, 2
        while pname in used:
            pname, n = f"{base}{n}", n + 1
        used.add(pname)
        params.append(CppParam(ghidra_to_cpp_type(ptype), pname))

    # -- return type --------------------------------------------------------
    if kind in ("constructor", "destructor"):
        ret = ""
    elif fn.name == "main" and not fn.namespace:
        ret = "int"
    elif a and a.return_type and accepted(a.return_confidence):
        ret = ghidra_to_cpp_type(a.return_type)
        if needs_todo(a.return_confidence):
            todos.append(todo(f"return type '{a.return_type}'", a.return_confidence))
    elif a and a.observed_return_type:
        ret = ghidra_to_cpp_type(a.observed_return_type)
        todos.append(f"TODO: return type '{ret}' is inferred from how callers use the result "
                     f"(the analysis said void)")
    else:
        ret = ghidra_return_to_cpp(fn.return_type)

    return CppSignature(fn.address, class_name, name, kind, ret, params, todos)


def assign_signatures(kb, ir) -> dict:
    """
    Signatures for every in-scope function, with collisions resolved: a
    duplicate constructor/destructor variant (compilers emit complete- and
    base-object copies with identical bodies) becomes an alias of the first
    and is not reconstructed separately; any other duplicate is suffixed.
    """
    sigs, seen = {}, {}
    for addr, rec in sorted(kb.functions.items()):
        if rec.excluded:
            continue
        fn = ir.get(addr)
        if fn is None:
            continue
        sig = build_signature(rec, fn)
        key = (sig.class_name, sig.name, tuple(p.type for p in sig.params))
        alias_of = ""
        if key in seen:
            if sig.kind in ("constructor", "destructor"):
                alias_of = seen[key]
            else:
                base, n = sig.name, 2
                while (sig.class_name, f"{base}_{n}", key[2]) in seen:
                    n += 1
                sig.name = f"{base}_{n}"
                key = (sig.class_name, sig.name, key[2])
        if rec.alias_of != alias_of:
            rec.alias_of = alias_of
            kb.save_function(rec)
        if alias_of:
            continue
        seen[key] = addr
        sigs[addr] = sig
    return sigs
