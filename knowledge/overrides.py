"""
User overrides: human corrections layered on top of what the LLM agents found.

Every record keeps the LLM's own output separately (FunctionRecord.llm_analysis,
TypeRecord.llm, GlobalRecord.llm) next to the user's `overrides`. The effective
values that the rest of the pipeline reads (FunctionRecord.analysis,
TypeRecord.fields/base_class/size, GlobalRecord.name/type/confidence) are always
recomputed as "LLM output + overrides", so:

  - an override survives re-analysis and re-reconstruction (it is re-applied),
  - clearing an override restores exactly what the LLM said,
  - overridden values carry confidence 1.0, so they are always applied.

Stored override shapes:
  function: {name, class_name, method_kind, return_type, summary,
             params: {"<index>": {name, type, role}}, locals: {"<old name>": {name, type}}}
  type:     {base_class, size, fields: {"<offset>": {name, type, size} | {"remove": true}}}
  global:   {name, type}
"""

from knowledge.models import FieldDef, FunctionAnalysis, GlobalRecord, LocalGuess, ParamGuess, TypeRecord
from knowledge.naming import split_qualified, type_size

USER = 1.0
_TAG = "user override"


# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

def set_llm_analysis(rec, analysis: FunctionAnalysis):
    """Store a fresh LLM analysis and recompute the effective one."""
    _adopt_legacy(rec)
    rec.llm_analysis = analysis
    materialize_function(rec)


def materialize_function(rec):
    _adopt_legacy(rec)
    rec.analysis = merge_function(rec.llm_analysis, rec.overrides, rec.full_name or rec.ghidra_name)


def _adopt_legacy(rec):
    # Records written before overrides existed hold the LLM's analysis in `analysis`.
    if rec.llm_analysis is None and rec.analysis is not None and not rec.overrides:
        rec.llm_analysis = rec.analysis.model_copy(deep=True)


def merge_function(base, ov: dict, fallback_name: str):
    if not ov:
        return base.model_copy(deep=True) if base is not None else None
    a = base.model_copy(deep=True) if base is not None else FunctionAnalysis(name=fallback_name)

    if "class_name" in ov:
        a.class_name = ov["class_name"]
    if "method_kind" in ov:
        a.method_kind = ov["method_kind"]
    if "name" in ov:
        parts = split_qualified(ov["name"])
        if len(parts) > 1:
            if "class_name" not in ov:
                a.class_name = "::".join(parts[:-1])
            a.name = ov["name"]
        else:  # an unqualified name renames the member, keeping its class
            a.name = f"{a.class_name}::{ov['name']}" if a.class_name and a.method_kind != "free" else ov["name"]
        a.name_confidence = USER
    elif "class_name" in ov:
        member = split_qualified(a.name)[-1] if a.name else fallback_name
        a.name = f"{a.class_name}::{member}" if a.class_name else member
        a.name_confidence = max(a.name_confidence, USER)
    if a.class_name and a.method_kind == "free":
        a.method_kind = "method"
    if not a.class_name and a.method_kind != "free" and ("class_name" in ov or "name" in ov):
        a.method_kind = "free"

    if "return_type" in ov:
        a.return_type, a.return_confidence = ov["return_type"], USER
        a.contradictions, a.observed_return_type = [], ""
    if "summary" in ov:
        a.summary = ov["summary"]

    for idx, p in (ov.get("params") or {}).items():
        index = int(idx)
        g = next((x for x in a.params if x.index == index), None)
        if g is None:
            g = ParamGuess(index=index, role="normal")
            a.params.append(g)
        g.name = p.get("name", g.name)
        g.type = p.get("type", g.type)
        g.role = p.get("role", g.role)
        g.confidence = USER
    a.params.sort(key=lambda x: x.index)

    for old, l in (ov.get("locals") or {}).items():
        g = next((x for x in a.locals if x.old_name == old), None)
        if g is None:
            g = LocalGuess(old_name=old, name=l.get("name", old))
            a.locals.append(g)
        g.name = l.get("name", g.name)
        g.type = l.get("type", g.type)
        g.confidence = USER

    keys = sorted(k for k in ov if ov[k] not in (None, {}, []))
    a.evidence = [e for e in a.evidence if not e.startswith(_TAG)] + [f"{_TAG}: {', '.join(keys)}"]
    return a


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

def set_llm_type(rec: TypeRecord, existing: TypeRecord = None):
    """`rec` is fresh LLM output; carry over the user's overrides from the stored record."""
    rec.llm = _type_snapshot(rec)
    rec.overrides = dict(existing.overrides) if existing else {}
    materialize_type(rec)


def _type_snapshot(t: TypeRecord) -> dict:
    return {"fields": [f.model_dump() for f in t.fields], "base_class": t.base_class,
            "base_confidence": t.base_confidence, "size": t.size, "size_confidence": t.size_confidence,
            "confidence": t.confidence}


def materialize_type(t: TypeRecord, pointer_size: int = 8):
    if not t.llm:
        t.llm = _type_snapshot(t)
    base = t.llm
    fields = {f["offset"]: FieldDef.model_validate(f) for f in base.get("fields", [])}
    t.base_class, t.base_confidence = base.get("base_class", ""), base.get("base_confidence", 0.0)
    t.size, t.size_confidence = base.get("size", 0), base.get("size_confidence", 0.0)
    t.confidence = base.get("confidence", t.confidence)
    ov = t.overrides or {}
    if not ov:
        t.fields = sorted(fields.values(), key=lambda f: f.offset)
        return

    user_fields = []
    for off_s, o in (ov.get("fields") or {}).items():
        off = int(off_s)
        if o.get("remove"):
            fields.pop(off, None)
            continue
        old = fields.get(off)
        ftype = o.get("type", old.type if old else "")
        size = o.get("size") or (old.size if old else 0) or type_size(ftype, pointer_size) or 1
        user_fields.append(FieldDef(offset=off, size=size, name=o.get("name", old.name if old else f"field_{off:x}"),
                                    type=ftype, confidence=USER, evidence=[_TAG]))
    # The user's fields win over any LLM field they overlap.
    for uf in user_fields:
        for off in [o for o, f in fields.items()
                    if f.offset < uf.offset + uf.size and uf.offset < f.offset + max(1, f.size)]:
            fields.pop(off)
    for uf in user_fields:
        fields[uf.offset] = uf

    if "base_class" in ov:
        t.base_class, t.base_confidence = ov["base_class"], USER if ov["base_class"] else 0.0
    if "size" in ov:
        t.size, t.size_confidence = ov["size"], USER
    t.fields = sorted(fields.values(), key=lambda f: f.offset)
    t.size = max(t.size, max((f.offset + f.size for f in t.fields), default=0))
    t.confidence = max(t.confidence, 0.9)   # a layout the user corrected is trusted


# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

def set_llm_global(rec: GlobalRecord, name: str, type_: str, confidence: float):
    rec.llm = {"name": name, "type": type_, "confidence": confidence}
    materialize_global(rec)


def materialize_global(rec: GlobalRecord):
    if not rec.llm and rec.name:
        rec.llm = {"name": rec.name, "type": rec.type, "confidence": rec.confidence}
    base = rec.llm or {"name": "", "type": "", "confidence": 0.0}
    ov = rec.overrides or {}
    rec.name = ov.get("name", base["name"])
    rec.type = ov.get("type", base["type"])
    rec.confidence = USER if ov else base["confidence"]


def llm_global_confidence(rec: GlobalRecord) -> float:
    return (rec.llm or {}).get("confidence", rec.confidence if not rec.overrides else 0.0)
