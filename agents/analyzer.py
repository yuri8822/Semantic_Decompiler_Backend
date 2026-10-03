"""
Analyzer — first LLM pass: understand a function, don't rewrite it.

The model's semantic annotation is grounded against Ghidra's facts before it
is stored: claims about offsets, parameters, locals or globals that Ghidra
never observed are dropped, and mismatched access sizes demote a field below
the apply threshold. The LLM proposes; the binary disposes.
"""

from pydantic import ValidationError

from agents.prompts import ANALYZER_SYSTEM, build_analyzer_prompt
from ghidra_io.ir import FunctionIR
from knowledge.confidence import demoted
from knowledge.models import FunctionAnalysis, to_int
from knowledge.naming import split_qualified, type_size


class Analyzer:
    def __init__(self, llm):
        self.llm = llm

    def analyze(self, ctx, fn: FunctionIR, rec, round_num: int) -> FunctionAnalysis:
        raw = self.llm.complete_json(
            ANALYZER_SYSTEM, build_analyzer_prompt(ctx, fn, rec, round_num),
            tag=f"analyze_r{round_num}_{fn.address}",
        )
        try:
            analysis = FunctionAnalysis.model_validate(raw)
        except ValidationError as exc:
            analysis = FunctionAnalysis(
                name=fn.full_name or fn.name, name_confidence=0.0,
                notes=[f"analyzer output failed validation: {exc.errors()[:3]}"],
            )
        analysis = ground(analysis, fn, ctx.ir.program.pointer_size)
        analysis.round = round_num
        analysis.provider = self.llm.provider
        analysis.ir_hash = fn.ir_hash()
        return analysis


def ground(a: FunctionAnalysis, fn: FunctionIR, pointer_size: int = 8) -> FunctionAnalysis:
    """Reconcile an analysis with what Ghidra actually observed."""
    notes = list(a.notes)

    if not a.name.strip():
        a.name, a.name_confidence = fn.full_name or fn.name, 0.0
    parts = split_qualified(a.name)
    if len(parts) > 1 and not a.class_name:
        a.class_name = "::".join(parts[:-1])
    if a.class_name and a.method_kind == "free":
        first = next((p for p in a.params if p.index == 0), None)
        a.method_kind = "method" if (first and first.role == "this") else "static"

    ir_params = {p.index for p in fn.parameters}
    dropped = [p.index for p in a.params if p.index not in ir_params]
    a.params = [p for p in a.params if p.index in ir_params]
    if dropped:
        notes.append(f"grounding: dropped guesses for nonexistent parameter indices {dropped}")

    ir_locals = {l.name for l in fn.locals}
    unknown_locals = [l.old_name for l in a.locals if l.old_name not in ir_locals]
    a.locals = [l for l in a.locals if l.old_name in ir_locals]
    if unknown_locals:
        notes.append(f"grounding: dropped renames of unknown locals {unknown_locals[:8]}")

    observed = {}
    for acc in fn.field_accesses:
        observed.setdefault((acc.param, acc.offset), set()).add(acc.size)
    passed = {(p.param, p.offset) for p in fn.arg_passes}
    kept = []
    for f in a.fields:
        key = (f.param, f.offset)
        if key not in observed and key not in passed:
            notes.append(f"grounding: dropped field {f.name} at param[{f.param}]+{f.offset:#x} (never accessed)")
            continue
        size = type_size(f.type, pointer_size)
        if size and key in observed and size not in observed[key]:
            notes.append(f"grounding: {f.name} ({f.type}, {size} bytes) at +{f.offset:#x} contradicts observed "
                         f"access sizes {sorted(observed[key])}; confidence capped")
            f.confidence = demoted(f.confidence, 0.05)
        kept.append(f)
    a.fields = kept

    ir_globals = {_norm_addr(g.address): g for g in fn.globals if g.address}
    grounded_globals = []
    for g in a.globals:
        addr = _norm_addr(g.address)
        if addr not in ir_globals:
            notes.append(f"grounding: dropped global {g.name} at {g.address} (not referenced here)")
            continue
        g.address = addr
        g.old_name = ir_globals[addr].name
        grounded_globals.append(g)
    a.globals = grounded_globals

    a.notes = notes
    return a


def _norm_addr(address: str) -> str:
    return f"{to_int(address if str(address).lower().startswith('0x') else '0x' + str(address)):#x}"
