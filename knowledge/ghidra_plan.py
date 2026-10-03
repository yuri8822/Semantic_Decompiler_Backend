"""
Turns the knowledge base into the plan ApplyKnowledge.java executes. Only
HIGH and MEDIUM confidence discoveries are included (MEDIUM ones carry a
TODO in the function's plate comment / the field comment); LOW ones are left
out entirely so a bad guess never reaches Ghidra.

The plan is idempotent against the current IR: anything Ghidra already
reflects (a name already applied in an earlier round) is omitted.
"""

from ghidra_io.ir import FunctionIR, ProgramIR
from knowledge.confidence import accepted, needs_todo, tier
from knowledge.filters import is_imported_data
from knowledge.naming import (
    cpp_to_ghidra_type, is_default_global_name, is_default_variable_name, sanitize_class_name,
    sanitize_identifier, split_qualified,
)
from knowledge.signatures import MEMBER_KINDS, name_is_renamable

COMMENT_TAG = "[semdec]"


def build_plan(kb, ir: ProgramIR) -> dict:
    known_classes = set(kb.types)
    ptr = ir.program.pointer_size
    plan = {"structs": [], "functions": [], "globals": []}

    for t in sorted(kb.types.values(), key=lambda t: t.name):
        if not accepted(t.confidence):
            continue
        fields = []
        for f in sorted(t.fields, key=lambda f: f.offset):
            if not accepted(f.confidence) or f.size <= 0:
                continue
            entry = {"offset": f.offset, "size": f.size, "name": sanitize_identifier(f.name)}
            gtype = cpp_to_ghidra_type(f.type, known_classes, ptr)
            if gtype:
                entry["type"] = gtype
            if needs_todo(f.confidence):
                entry["comment"] = f"TODO: medium-confidence field ({f.confidence:.2f})"
            fields.append(entry)
        plan["structs"].append({"name": t.name, "size": t.size, "fields": fields})

    for rec in kb.in_scope():
        fn = ir.get(rec.address)
        if fn is None or rec.analysis is None:
            continue
        entry = _function_entry(rec, fn, known_classes, ptr)
        if len(entry) > 1:
            plan["functions"].append(entry)

    current_names = {g.address: g.name for f in ir.functions for g in f.globals if g.address}
    current_types = {g.address: g.type for f in ir.functions for g in f.globals if g.address}
    for g in sorted(kb.globals.values(), key=lambda g: g.address):
        if not g.name or not accepted(g.confidence) or is_imported_data(g.ghidra_name):
            continue
        current = current_names.get(g.address, "")
        renamable = not current or is_default_global_name(current) or current == g.applied_name
        if current == g.name or not renamable:
            continue
        entry = {"address": g.address, "name": sanitize_identifier(g.name)}
        gtype = cpp_to_ghidra_type(g.type, known_classes, ptr) if g.type else None
        # Only type data Ghidra hasn't typed itself; never overwrite strings/arrays it defined.
        current_type = current_types.get(g.address, "")
        untyped = not current_type or current_type.startswith("undefined")
        if gtype and untyped and not _rendered_as_literal(ir, g, current or g.ghidra_name):
            entry["type"] = gtype
        plan["globals"].append(entry)

    return plan


def _function_entry(rec, fn: FunctionIR, known_classes, ptr) -> dict:
    a = rec.analysis
    entry = {"address": fn.address}

    # Name and owning class (a user rename beats even a symbol name).
    user_named = "name" in rec.overrides or "class_name" in rec.overrides
    if accepted(a.name_confidence) and (name_is_renamable(fn) or user_named):
        parts = split_qualified(a.name) or [fn.name]
        cls = "::".join(parts[:-1]) or (a.class_name if a.is_method else "")
        namespace = sanitize_class_name(cls) if cls else ""
        if a.method_kind == "constructor" and namespace:
            name = namespace
        elif a.method_kind == "destructor" and namespace:
            name = "~" + namespace
        else:
            name = sanitize_identifier(parts[-1].lstrip("~"))
        if name != fn.name or namespace != fn.namespace:
            entry["name"], entry["namespace"] = name, namespace
    else:
        namespace = fn.namespace if fn.namespace_is_class else ""

    # A method's first parameter is its object: switching to __thiscall makes
    # Ghidra type it as a pointer to the class structure.
    target_ns = entry.get("namespace", namespace)
    if (a.is_method and a.method_kind in MEMBER_KINDS and a.method_kind != "static"
            and accepted(a.name_confidence) and fn.parameters and target_ns
            and fn.calling_convention != "__thiscall"):
        first = next((p for p in a.params if p.index == 0), None)
        if first is None or first.role == "this":
            entry["thiscall"] = True
            entry["namespace"] = target_ns

    # Parameters.
    params = []
    for g in a.params:
        p = fn.param(g.index)
        if p is None or p.is_this or g.role != "normal" or not g.name or not accepted(g.confidence):
            continue
        new = sanitize_identifier(g.name)
        if new in ("this", p.name):
            continue
        user_set = str(g.index) in (rec.overrides.get("params") or {})
        if not (is_default_variable_name(p.name) or p.name == g.old_name or user_set):
            continue
        item = {"index": g.index, "old_name": p.name, "name": new}
        gtype = cpp_to_ghidra_type(g.type, known_classes, ptr) if g.type else None
        if gtype:
            item["type"] = gtype
        params.append(item)
    if params:
        entry["params"] = params

    # Locals — matched by the name the analyzer saw, which must still exist.
    locals_ = []
    current_locals = {l.name for l in fn.locals}
    for g in a.locals:
        if not accepted(g.confidence) or g.old_name not in current_locals:
            continue
        new = sanitize_identifier(g.name)
        if new == g.old_name or new in current_locals:
            continue
        item = {"old_name": g.old_name, "name": new}
        gtype = cpp_to_ghidra_type(g.type, known_classes, ptr) if g.type else None
        if gtype:
            item["type"] = gtype
        locals_.append(item)
    if locals_:
        entry["locals"] = locals_

    # Return type (constructors/destructors have none).
    if (a.return_type and accepted(a.return_confidence)
            and a.method_kind not in ("constructor", "destructor")):
        gtype = cpp_to_ghidra_type(a.return_type, known_classes, ptr)
        if gtype and gtype.replace(" ", "") != fn.return_type.replace(" ", ""):
            entry["return_type"] = gtype

    comment = plate_comment(a)
    if comment.strip() != (fn.comment or "").strip():
        entry["comment"] = comment
    return entry


def _rendered_as_literal(ir: ProgramIR, g, name: str) -> bool:
    """
    True when no referencing function's decompilation mentions the global by
    name: the decompiler prints its contents instead (e.g. system("CLS") for
    undefined bytes holding "CLS"). Such data is a character array, so a
    guessed type like `char *` would make Ghidra misread the bytes as a pointer.
    """
    texts = [ir.get(a).decompiled for a in g.referenced_by if ir.get(a)]
    return bool(texts) and not any(name in t for t in texts)


def plate_comment(a) -> str:
    lines = [f"{COMMENT_TAG} {a.summary}".rstrip()]
    lines.append(f"name: {a.name} (confidence {a.name_confidence:.2f}, {tier(a.name_confidence)})")
    if needs_todo(a.name_confidence):
        lines.append("TODO: medium-confidence name — verify")
    for p in a.params:
        if needs_todo(p.confidence) and p.role == "normal":
            lines.append(f"TODO: parameter {p.index} '{p.name}' is a medium-confidence guess ({p.confidence:.2f})")
    for e in a.evidence[:6]:
        lines.append(f"evidence: {e}")
    return "\n".join(lines)


def summarize_report(report: dict) -> dict:
    applied = report.get("applied", [])
    failed = report.get("failed", [])
    skipped = [a for a in applied if str(a.get("detail", "")).startswith("skipped:")]
    return {
        "applied": len(applied) - len(skipped),
        "skipped": len(skipped),
        "failed": len(failed),
        "failures": failed[:50],
    }
