"""
Validator — never trust the LLM blindly.

Static validation compares a reconstructed function with Ghidra's facts about
the original: the definition and its signature, return semantics, calls,
branch structure, field and global accesses, string literals, and leftover
decompiler residue. Errors are fed back to the Code Reconstructor; warnings
are recorded in the knowledge base and the report.

Compilation (validation/compiler.py) is the second, independent check.
"""

import json
import re

from agents import cpp_text
from ghidra_io.ir import FunctionIR
from knowledge.confidence import accepted
from knowledge.filters import is_imported_data
from knowledge.models import Issue
from knowledge.naming import DECOMPILER_RESIDUE_RE, sanitize_class_name, sanitize_identifier


def _err(check, msg):
    return Issue(severity="error", check=check, message=msg)


def _warn(check, msg):
    return Issue(severity="warning", check=check, message=msg)


class Validator:
    def check(self, ctx, fn: FunctionIR, sig, code: str) -> list:
        issues = []
        d = cpp_text.extract_definition(code, sig.qualified, sig.name)
        if d is None:
            return [_err("definition", f"the output must contain exactly one definition of "
                                       f"`{sig.definition_head()}`")]
        body = code[d.start:d.end]

        issues += self._signature(sig, d)
        issues += self._returns(fn, sig, body)
        issues += self._calls(ctx, fn, sig, body)
        issues += self._branches(fn, body)
        issues += self._fields(ctx, fn, sig, body)
        issues += self._globals(ctx, fn, body)
        issues += self._strings(fn, body, ctx.ir0.get(fn.address))
        issues += self._residue(body)
        return issues

    # -- individual checks -------------------------------------------------------

    @staticmethod
    def _signature(sig, d) -> list:
        issues = []
        if d.name != sig.qualified:
            issues.append(_err("signature", f"the function must be defined as `{sig.qualified}`, not `{d.name}`"))
        if d.param_count != len(sig.params):
            issues.append(_err("parameters", f"`{sig.qualified}` takes {len(sig.params)} parameter(s) "
                                             f"({', '.join(p.render() for p in sig.params) or 'none'}), "
                                             f"the reconstruction has {d.param_count}"))
        if sig.kind not in ("constructor", "destructor"):
            want = re.sub(r"\s+", "", sig.return_type)
            got = re.sub(r"\s+", "", d.return_part)
            if want != got:
                issues.append(_err("return_type", f"return type must be `{sig.return_type}`, "
                                                  f"the reconstruction has `{d.return_part or '(none)'}`"))
        return issues

    @staticmethod
    def _returns(fn, sig, body: str) -> list:
        if sig.kind in ("constructor", "destructor"):
            return []
        has_value = cpp_text.returns_value(body)
        if sig.return_type == "void" and has_value:
            return [_err("return", "the function returns void but the reconstruction returns a value")]
        if sig.return_type != "void" and not has_value and cpp_text.returns_value(fn.decompiled):
            return [_err("return", f"the binary returns a value ({sig.return_type}) but the reconstruction "
                                   f"never does")]
        return []

    @staticmethod
    def _calls(ctx, fn, sig, body: str) -> list:
        issues = []
        called = cpp_text.called_names(body)
        words = cpp_text.identifiers(body)
        expected_names = set()
        for callee in fn.callees:
            rec = ctx.kb.functions.get(callee)
            if rec is None or rec.excluded:
                continue  # library/runtime callee: its standard equivalent is fine
            target = rec.alias_of or callee
            csig = ctx.signatures.get(target)
            if csig is None:
                name = sanitize_identifier(ctx.ir.get(callee).name if ctx.ir.get(callee) else callee)
                if name not in called:
                    issues.append(_warn("calls", f"the binary calls {name} ({callee}) here; it is not called"))
                continue
            expected_names.add(csig.name)
            if csig.kind in ("constructor", "destructor"):
                # Constructors run via `new T`, declarations, base initializers,
                # or member initializers (`board()`); destructors usually run
                # implicitly.
                if (csig.kind == "constructor" and csig.class_name not in words
                        and not Validator._member_constructed(ctx, fn, sig, callee, words)):
                    issues.append(_err("calls", f"the binary constructs a {csig.class_name} here "
                                                f"({csig.qualified} at {target}); the reconstruction never does"))
                continue
            if csig.name not in called and csig.qualified not in called:
                issues.append(_err("calls", f"the binary calls {csig.qualified} ({target}) here; "
                                            f"the reconstruction does not"))
        # Calls to program functions the binary doesn't make from here.
        if fn.stats.indirect_calls == 0:
            program_names = {s.name: s for s in ctx.signatures.values()
                             if s.kind not in ("constructor", "destructor")}
            for name in sorted(called & set(program_names)):
                if name not in expected_names and name != sig.name:
                    issues.append(_warn("calls", f"calls {name}, which the binary does not call from here"))
        return issues

    @staticmethod
    def _member_constructed(ctx, fn, sig, ctor_address: str, words: set) -> bool:
        """The constructor runs on `this + offset`, and the member at that offset is referenced."""
        layout = ctx.kb.types.get(sig.class_name) if sig.is_member else None
        if layout is None:
            return False
        for p in fn.arg_passes:
            if p.callee == ctor_address and p.arg == 0 and p.param == 0:
                f = layout.field_at(p.offset)
                if f is not None and f.name in words:
                    return True
        return False

    @staticmethod
    def _branches(fn, body: str) -> list:
        ghidra = cpp_text.decision_points(fn.decompiled)
        ours = cpp_text.decision_points(body)
        if ghidra >= 2 and ours < ghidra * 0.5:
            return [_err("branches", f"Ghidra's decompilation has {ghidra} decision points (if/loop/case/&&/||), "
                                     f"the reconstruction only {ours}; branches were likely dropped")]
        if ours > ghidra * 1.5 + 2:
            return [_warn("branches", f"the reconstruction has {ours} decision points vs {ghidra} in Ghidra's "
                                      f"output; check for invented conditions")]
        return []

    @staticmethod
    def _fields(ctx, fn, sig, body: str) -> list:
        """Proven accesses (through `this`, or a pointer typed as a known class) use the declared names."""
        words = cpp_text.identifiers(body)
        issues, seen = [], set()
        for a in fn.field_accesses:
            if a.param == 0 and sig.is_member:
                cls = sig.class_name
            elif a.param < 0 and a.type:
                cls = sanitize_class_name(a.type)
            else:
                continue
            t = ctx.kb.types.get(cls)
            if t is None or (cls, a.offset) in seen:
                continue
            seen.add((cls, a.offset))
            f = t.field_covering(a.offset)
            if f is None or not accepted(f.confidence) or _is_vtable_name(f.name):
                continue  # vtable stores are dropped on purpose (the compiler sets the vptr)
            if f.name not in words:
                issues.append(_warn("fields", f"the binary {a.access}s {cls}::{f.name} (+{a.offset:#x}) "
                                              f"but the reconstruction never references `{f.name}`"))
        own = ctx.kb.types.get(sig.class_name) if sig.is_member else None
        masked = cpp_text.mask(body)
        if own and own.fields and re.search(r"\bthis\s*\+\s*(0x[0-9a-fA-F]+|\d+)", masked):
            issues.append(_warn("fields", "raw `this + offset` arithmetic remains; use the declared field names"))
        return issues

    @staticmethod
    def _globals(ctx, fn, body: str) -> list:
        words = cpp_text.identifiers(body)
        issues = []
        for g in fn.globals:
            if g.external or not g.address or is_imported_data(g.name):
                continue
            rec = ctx.kb.globals.get(g.address)
            if rec is None or _is_vtable_name(rec.name) or _is_vtable_name(g.name):
                continue  # vtable addresses disappear along with the vtable stores
            if "char" in (rec.type or "") and not g.write:
                continue  # read-only character data: the code uses it as a literal
            if rec.name and accepted(rec.confidence):
                if sanitize_identifier(rec.name) not in words:
                    issues.append(_warn("globals", f"the binary accesses global {rec.name} ({g.address}); "
                                                   f"the reconstruction doesn't"))
        return issues

    @staticmethod
    def _strings(fn, body: str, fn0=None) -> list:
        # Literals come from Ghidra's defined string data AND from its decompiled
        # text: bytes Ghidra never defined as a string still print as "CLS".
        # Round 0 is included because a wrongly applied type can hide a literal
        # in later rounds. Short ones matter too: "CLS" -> "cls" changes a constant.
        probes = {}
        for s in fn.strings:
            if len(s) >= 2:
                probes.setdefault(json.dumps(s[:24])[1:-1], s)
        for source in (fn, fn0):
            if source is None:
                continue
            for lit in _C_STRING_RE.findall(cpp_text.mask(source.decompiled, strings=False)):
                if len(lit) >= 2:
                    probes.setdefault(lit[:24], lit)
        missing = []
        for escaped, original in probes.items():
            raw = original[:24]
            if escaped not in body and raw not in body:
                missing.append(original)
        if missing:
            shown = ", ".join(repr(s[:40]) for s in missing[:5])
            return [_warn("strings", f"string literal(s) used by the binary are missing: {shown}")]
        return []

    @staticmethod
    def _residue(body: str) -> list:
        found = sorted(set(m.group(0) for m in DECOMPILER_RESIDUE_RE.finditer(cpp_text.mask(body))))
        if found:
            return [_warn("residue", "decompiler artifacts remain: " + ", ".join(found[:8]))]
        return []


_C_STRING_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')


def _is_vtable_name(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in ("vftable", "vtable", "vtbl", "vptr", "vfptr"))


def errors(issues: list) -> list:
    return [i for i in issues if i.severity == "error"]
