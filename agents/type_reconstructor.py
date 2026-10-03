"""
Type Reconstructor — merges the evidence from every function that operates
on one object type into a class layout.

Candidate classes and their evidence are gathered deterministically (method
membership from the signatures, offsets from p-code, field guesses from the
analyzer). The LLM reconciles them into a layout, which is then normalized
against the observed accesses: unobserved offsets and size mismatches are
demoted below the apply threshold, overlaps resolved by confidence.
"""

import hashlib
import re
from collections import defaultdict

from pydantic import ValidationError

from agents.prompts import build_type_prompt, TYPE_SYSTEM
from knowledge.confidence import demoted
from knowledge.models import FieldDef, TypeRecord
from knowledge.naming import ghidra_to_cpp_type, sanitize_class_name, sanitize_identifier, split_type, type_size

_EMBEDDED_TYPES = ("std::string",)


class TypeReconstructor:
    def __init__(self, llm):
        self.llm = llm

    # -- candidate discovery (deterministic) -----------------------------------

    def candidates(self, ctx) -> dict:
        """
        class name -> {"members": [addr], "users": [(addr, param_index)], "from_symbols": bool}.
        A user with param_index -1 accesses the class through a pointer Ghidra
        types as pointing to it (e.g. a Piece * loaded from a board array).
        """
        cands = defaultdict(lambda: {"members": [], "users": [], "from_symbols": False})
        for addr, sig in ctx.signatures.items():
            if sig.is_member:
                c = cands[sig.class_name]
                c["members"].append(addr)
                fn = ctx.ir.get(addr)
                if fn is not None and fn.namespace_is_class and sanitize_class_name(fn.namespace) == sig.class_name:
                    c["from_symbols"] = True
        # Non-member functions whose analysis says a parameter points to a class.
        for addr, sig in ctx.signatures.items():
            rec = ctx.kb.functions.get(addr)
            if not rec or not rec.analysis:
                continue
            for f in rec.analysis.fields:
                if f.class_name and not (sig.is_member and f.param == 0):
                    name = sanitize_class_name(f.class_name)
                    if (addr, f.param) not in cands[name]["users"]:
                        cands[name]["users"].append((addr, f.param))
        cands = {k: v for k, v in cands.items() if v["members"] or len(v["users"]) >= 1}
        # Accesses through typed pointers (known only once a layout has been applied
        # to Ghidra) add evidence to existing candidates; they never create one, so
        # Ghidra's own structures (PE headers in CRT code, ...) can't become classes.
        for addr in ctx.signatures:
            fn = ctx.ir.get(addr)
            for a in (fn.field_accesses if fn else []):
                name = sanitize_class_name(a.type) if a.param < 0 and a.type else ""
                if name in cands and (addr, -1) not in cands[name]["users"]:
                    cands[name]["users"].append((addr, -1))
        return cands

    def evidence(self, ctx, class_name: str, cand: dict) -> dict:
        items = []
        for addr in cand["members"]:
            items.append(self._fn_evidence(ctx, addr, 0, class_name, member=True))
        for addr, param in cand["users"]:
            items.append(self._fn_evidence(ctx, addr, param, class_name, member=False))
        # Round 0 only: later exports just echo back the layouts this pipeline applied,
        # which would both mislabel our own guesses as Ghidra's and churn the evidence hash.
        ghidra_struct = ""
        for c in ctx.ir0.classes:
            if sanitize_class_name(c.name) == class_name and c.fields:
                ghidra_struct = "\n".join(f"  +{f.offset:#x} {f.type} {f.name} (size {f.size})" for f in c.fields)
        return {"functions": items, "ghidra_struct": ghidra_struct}

    def _fn_evidence(self, ctx, addr: str, param: int, class_name: str, member: bool) -> dict:
        fn = ctx.ir.get(addr)
        rec = ctx.kb.functions.get(addr)
        sig = ctx.signatures.get(addr)
        typed = param < 0   # accesses through a pointer typed as this class

        def relevant(param_index: int, cls: str) -> bool:
            if typed:
                return param_index < 0 and sanitize_class_name(cls) == class_name
            return param_index == param

        agg = defaultdict(lambda: {"read": 0, "write": 0, "sizes": set()})
        for a in fn.field_accesses:
            if relevant(a.param, a.type):
                agg[a.offset][a.access] += 1
                agg[a.offset]["sizes"].add(a.size)
        accesses = "\n".join(
            f"    +{off:#x} size {'/'.join(map(str, sorted(v['sizes'])))} "
            + ", ".join(f"{k} x{v[k]}" for k in ("read", "write") if v[k])
            for off, v in sorted(agg.items())
        )
        passes = "" if typed else "\n".join(sorted({
            f"    ptr+{p.offset:#x} -> arg {p.arg} of {ctx.name_of(p.callee)}"
            for p in fn.arg_passes if p.param == param
        }))
        fields = [f for f in (rec.analysis.fields if rec and rec.analysis else [])
                  if relevant(f.param, f.class_name)]
        guesses = "\n".join(
            f"    +{f.offset:#x} {f.type} {f.name} (confidence {f.confidence:.2f}) — {f.evidence}" for f in fields)
        if not sig:
            role = "?"
        elif member:
            role = sig.kind
        elif typed:
            role = f"accesses it through a {class_name} * it loads"
        else:
            role = f"uses it via parameter {param}"
        decompiled = ""
        if sig and sig.kind == "constructor":
            decompiled = "\n".join("    " + l for l in fn.decompiled.strip().splitlines()[:40])
            decompiled += self._allocation_sites(ctx, fn, class_name)
        return {
            "address": addr, "name": ctx.name_of(addr), "role": role,
            "summary": rec.analysis.summary if rec and rec.analysis else "",
            "accesses": accesses, "passes": passes, "guesses": guesses, "decompiled": decompiled,
            "observed": {off: v["sizes"] for off, v in agg.items()},
            "passed_offsets": set() if typed else {p.offset for p in fn.arg_passes if p.param == param},
            "guessed_offsets": {f.offset for f in fields},
        }

    @staticmethod
    def _allocation_sites(ctx, ctor_fn, class_name: str) -> str:
        """Caller lines around the constructor call — they show the allocation size."""
        out = []
        for caller in ctor_fn.callers[:4]:
            cfn = ctx.ir.get(caller)
            if cfn is None:
                continue
            lines = cfn.decompiled.splitlines()
            for i, line in enumerate(lines):
                if re.search(rf"\b{re.escape(ctor_fn.name)}\s*\(", line):
                    snippet = "\n".join("      " + l.strip() for l in lines[max(0, i - 2):i + 1])
                    out.append(f"\n    in caller {ctx.name_of(caller)}:\n{snippet}")
                    break
        return "".join(out)

    @staticmethod
    def evidence_hash(evidence: dict) -> str:
        h = hashlib.sha1()
        for item in evidence["functions"]:
            h.update("|".join([item["address"], item["accesses"], item["passes"], item["guesses"]]).encode())
        h.update(evidence["ghidra_struct"].encode())
        return h.hexdigest()[:16]

    # -- reconstruction ----------------------------------------------------------

    def reconstruct(self, ctx, class_name: str, cand: dict, evidence: dict, round_num: int,
                    valid_classes: set) -> TypeRecord:
        raw = self.llm.complete_json(
            TYPE_SYSTEM, build_type_prompt(ctx, class_name, evidence),
            tag=f"types_r{round_num}_{class_name}",
        )
        raw["name"] = class_name  # the candidate's identity is fixed by its members
        try:
            rec = TypeRecord.model_validate(raw)
        except ValidationError as exc:
            rec = TypeRecord(name=class_name, notes=f"type reconstructor output failed validation: {exc.errors()[:3]}")
        rec.members = sorted(cand["members"])
        rec.from_symbols = cand["from_symbols"]
        rec.round = round_num
        rec.evidence_hash = self.evidence_hash(evidence)
        class_sizes = {n: t.size for n, t in ctx.kb.types.items()}
        return normalize(rec, evidence, ctx.ir.program.pointer_size, class_sizes, valid_classes)


def normalize(rec: TypeRecord, evidence: dict, pointer_size: int, class_sizes: dict,
              valid_classes: set) -> TypeRecord:
    """Make a layout consistent with what the binary shows."""
    observed, passed, guessed = defaultdict(set), set(), set()
    for item in evidence["functions"]:
        for off, sizes in item["observed"].items():
            observed[off] |= set(sizes)
        passed |= item["passed_offsets"]
        guessed |= item["guessed_offsets"]

    notes = [rec.notes] if rec.notes else []
    fields = []
    for f in rec.fields:
        f.name = sanitize_identifier(f.name, fallback=f"field_{f.offset:x}")
        f.type = ghidra_to_cpp_type(f.type) if f.type else ""
        tsize = type_size(f.type, pointer_size, class_sizes) if f.type else 0
        if f.size <= 0:
            f.size = tsize or max(observed.get(f.offset, {0}) or {0})
        if f.size <= 0:
            notes.append(f"dropped {f.name}: unknown size")
            continue
        if f.offset < 0:
            notes.append(f"dropped {f.name}: negative offset")
            continue
        if f.offset not in observed and f.offset not in passed and f.offset not in guessed:
            f.confidence = demoted(f.confidence, 0.1)
            notes.append(f"{f.name} at +{f.offset:#x} is not backed by any observed access")
        base, ptrs = split_type(f.type)
        embedded = ptrs == 0 and (base in _EMBEDDED_TYPES or base in class_sizes or base in valid_classes)
        if (f.offset in observed and not embedded and f.size not in observed[f.offset]
                and f.size < max(observed[f.offset])):
            f.confidence = demoted(f.confidence, 0.05)
            notes.append(f"{f.name}: size {f.size} smaller than observed access {sorted(observed[f.offset])}")
        fields.append(f)

    # Resolve overlaps: the most confident field wins.
    chosen = []
    for f in sorted(fields, key=lambda f: (-f.confidence, f.offset)):
        if any(f.offset < g.offset + g.size and g.offset < f.offset + f.size for g in chosen):
            notes.append(f"dropped {f.name} at +{f.offset:#x}: overlaps a more confident field")
            continue
        chosen.append(f)
    chosen.sort(key=lambda f: f.offset)

    seen = set()
    for f in chosen:
        if f.name in seen:
            f.name = f"{f.name}_{f.offset:x}"
        seen.add(f.name)

    if rec.base_class:
        rec.base_class = sanitize_class_name(rec.base_class)
        if rec.base_class == rec.name or rec.base_class not in valid_classes:
            notes.append(f"ignored base class {rec.base_class}: not a reconstructed class")
            rec.base_class, rec.base_confidence = "", 0.0
    end = max((f.offset + f.size for f in chosen), default=0)
    rec.size = max(rec.size, end)
    rec.fields = [FieldDef.model_validate(f.model_dump()) for f in chosen]
    rec.same_as = [sanitize_class_name(s) for s in rec.same_as if s and sanitize_class_name(s) != rec.name]
    rec.notes = "; ".join(n for n in notes if n)
    return rec
