"""
Human-in-the-loop edits: validated user overrides on functions, class layouts
and globals (see knowledge/overrides.py for how they layer over LLM output).

Request semantics, for every editable field: absent = leave as is, a value =
set the override, null = clear the override (back to the LLM's value).
Edits mark the workspace "edits_pending"; the next run applies them to Ghidra
and regenerates the affected code.
"""

import re
from typing import Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

from knowledge.models import to_int
from knowledge.overrides import materialize_function, materialize_global, materialize_type
from knowledge.naming import split_qualified

_IDENT_RE = re.compile(r"^~?[A-Za-z_]\w*$")
_TYPE_RE = re.compile(r"^[\w\s\*&:<>,\[\]]+$")
MethodKindValue = Literal["free", "method", "constructor", "destructor", "static", "virtual"]


class EditError(ValueError):
    pass


def _check_name(value: Optional[str], qualified: bool = False) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    parts = split_qualified(value) if qualified else [value]
    if not parts or not all(_IDENT_RE.match(p) for p in parts):
        raise ValueError(f"{value!r} is not a valid C++ {'(qualified) ' if qualified else ''}identifier")
    return value


def _check_type(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = " ".join(value.split())
    if not value or not _TYPE_RE.match(value):
        raise ValueError(f"{value!r} is not a valid C++ type")
    return value


class _Edit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    def changes(self) -> dict:
        """Only the fields the request actually contained (null included)."""
        return {k: getattr(self, k) for k in self.model_fields_set}


class ParamEdit(_Edit):
    index: int
    name: Optional[str] = None
    type: Optional[str] = None

    @field_validator("name")
    @classmethod
    def check_n(cls, v):
        return _check_name(v)

    @field_validator("type")
    @classmethod
    def check_t(cls, v):
        return _check_type(v)



class LocalEdit(_Edit):
    old_name: str
    name: Optional[str] = None
    type: Optional[str] = None

    @field_validator("name")
    @classmethod
    def check_n(cls, v):
        return _check_name(v)

    @field_validator("type")
    @classmethod
    def check_t(cls, v):
        return _check_type(v)



class FunctionEdit(_Edit):
    name: Optional[str] = Field(None, description="Qualified (Class::Method) or bare name.")
    class_name: Optional[str] = None
    method_kind: Optional[MethodKindValue] = None
    return_type: Optional[str] = None
    summary: Optional[str] = None
    params: Optional[list[ParamEdit]] = None
    locals: Optional[list[LocalEdit]] = None

    @field_validator("name")
    @classmethod
    def check_n(cls, v):
        return _check_name(v, qualified=True)

    @field_validator("class_name")
    @classmethod
    def check_c(cls, v):
        return _check_name(v, qualified=True) if v else v

    @field_validator("return_type")
    @classmethod
    def check_r(cls, v):
        return _check_type(v)



class FieldEdit(_Edit):
    offset: Union[int, str]
    name: Optional[str] = None
    type: Optional[str] = None
    size: Optional[int] = Field(None, ge=1, le=1 << 20)
    remove: bool = Field(False, description="Delete the field from the layout.")
    clear: bool = Field(False, description="Drop the user's override for this offset (back to the LLM's field).")

    @field_validator("offset")
    @classmethod
    def check_o(cls, v):
        return _offset(v)

    @field_validator("name")
    @classmethod
    def check_n(cls, v):
        return _check_name(v)

    @field_validator("type")
    @classmethod
    def check_t(cls, v):
        return _check_type(v)



class TypeEdit(_Edit):
    base_class: Optional[str] = None
    size: Optional[int] = Field(None, ge=0, le=1 << 24)
    fields: Optional[list[FieldEdit]] = None

    @field_validator("base_class")
    @classmethod
    def check_b(cls, v):
        return _check_name(v) if v else v



class GlobalEdit(_Edit):
    name: Optional[str] = None
    type: Optional[str] = None

    @field_validator("name")
    @classmethod
    def check_n(cls, v):
        return _check_name(v)

    @field_validator("type")
    @classmethod
    def check_t(cls, v):
        return _check_type(v)



class ResetRequest(_Edit):
    analysis: bool = Field(False, description="Discard the LLM analysis; the next run re-analyzes the function.")
    code: bool = Field(True, description="Discard the generated code; the next run rewrites it.")


def _offset(v) -> int:
    n = to_int(v) if isinstance(v, str) else int(v)
    if n < 0:
        raise ValueError("offsets cannot be negative")
    return n


def _apply_scalar(target: dict, key: str, value):
    if value is None:
        target.pop(key, None)
    else:
        target[key] = value


# ---------------------------------------------------------------------------
# Applying edits
# ---------------------------------------------------------------------------

def edit_function(kb, fn_ir, address: str, edit: FunctionEdit):
    rec = kb.functions.get(address)
    if rec is None:
        raise EditError(f"no function at {address}")
    materialize_function(rec)   # adopt a pre-overrides record's analysis as the LLM's before editing
    ov = {k: v for k, v in rec.overrides.items()}
    changes = edit.changes()
    for key in ("name", "class_name", "method_kind", "return_type", "summary"):
        if key in changes:
            _apply_scalar(ov, key, changes[key])

    if "params" in changes and edit.params is not None:
        params = dict(ov.get("params") or {})
        ir_params = {p.index: p for p in fn_ir.parameters} if fn_ir else {}
        for p in edit.params:
            if fn_ir is not None and p.index not in ir_params:
                raise EditError(f"the function has no parameter {p.index}")
            cur = dict(params.get(str(p.index)) or {})
            for k, v in p.changes().items():
                if k != "index":
                    _apply_scalar(cur, k, v)
            if cur and "name" not in cur:
                # A type alone needs a name to be used; keep the current effective one.
                g = next((x for x in (rec.analysis.params if rec.analysis else []) if x.index == p.index), None)
                cur["name"] = (g.name if g and g.name else None) or ir_params[p.index].name
            if cur:
                params[str(p.index)] = cur
            else:
                params.pop(str(p.index), None)
        _apply_scalar(ov, "params", params or None)

    if "locals" in changes and edit.locals is not None:
        locals_ = dict(ov.get("locals") or {})
        known = {l.name for l in fn_ir.locals} if fn_ir else set()
        known |= {l.old_name for l in (rec.llm_analysis.locals if rec.llm_analysis else [])}
        for l in edit.locals:
            if fn_ir is not None and l.old_name not in known:
                raise EditError(f"no local variable named {l.old_name!r}")
            cur = dict(locals_.get(l.old_name) or {})
            for k, v in l.changes().items():
                if k != "old_name":
                    _apply_scalar(cur, k, v)
            if cur:
                cur.setdefault("name", l.old_name)
                locals_[l.old_name] = cur
            else:
                locals_.pop(l.old_name, None)
        _apply_scalar(ov, "locals", locals_ or None)

    rec.overrides = ov
    materialize_function(rec)
    kb.save_function(rec)
    _mark_pending(kb)
    return rec


def clear_function_overrides(kb, address: str):
    rec = kb.functions.get(address)
    if rec is None:
        raise EditError(f"no function at {address}")
    materialize_function(rec)   # adopts a legacy analysis as the LLM's before clearing
    rec.overrides = {}
    materialize_function(rec)
    kb.save_function(rec)
    _mark_pending(kb)
    return rec


def reset_function(kb, address: str, req: ResetRequest):
    rec = kb.functions.get(address)
    if rec is None:
        raise EditError(f"no function at {address}")
    if req.analysis:
        rec.llm_analysis = None
        rec.analysis = None
        materialize_function(rec)   # overrides alone still give an effective analysis
    if req.code or req.analysis:
        rec.cpp, rec.cpp_ir_hash, rec.cpp_provider, rec.cpp_signature = "", "", "", ""
        rec.static_issues, rec.compile_status, rec.compile_errors = [], "unchecked", ""
    kb.save_function(rec)
    _mark_pending(kb)
    return rec


def edit_type(kb, name: str, edit: TypeEdit):
    t = kb.types.get(name)
    if t is None:
        raise EditError(f"no class named {name!r}")
    materialize_type(t)          # snapshot legacy LLM fields before overriding
    ov = {k: v for k, v in t.overrides.items()}
    changes = edit.changes()
    if "base_class" in changes:
        base = changes["base_class"]
        if base and base not in kb.types:
            raise EditError(f"no class named {base!r} to derive from")
        if base == name:
            raise EditError("a class cannot derive from itself")
        _apply_scalar(ov, "base_class", base if base is not None else None)
    if "size" in changes:
        _apply_scalar(ov, "size", changes["size"])
    if "fields" in changes and edit.fields is not None:
        fields = dict(ov.get("fields") or {})
        for f in edit.fields:
            key = str(f.offset)
            if f.clear:
                fields.pop(key, None)
            elif f.remove:
                fields[key] = {"remove": True}
            else:
                cur = {k: v for k, v in (fields.get(key) or {}).items() if k != "remove"}
                for k, v in f.changes().items():
                    if k in ("name", "type", "size"):
                        _apply_scalar(cur, k, v)
                if not cur.get("name") and not any(x.offset == f.offset for x in t.fields):
                    raise EditError(f"a new field at +{f.offset:#x} needs a name")
                fields[key] = cur
        _apply_scalar(ov, "fields", fields or None)
    t.overrides = ov
    materialize_type(t)
    kb.save_type(t)
    _mark_pending(kb)
    return t


def clear_type_overrides(kb, name: str):
    t = kb.types.get(name)
    if t is None:
        raise EditError(f"no class named {name!r}")
    materialize_type(t)
    t.overrides = {}
    materialize_type(t)
    kb.save_type(t)
    _mark_pending(kb)
    return t


def edit_global(kb, address: str, edit: GlobalEdit):
    g = kb.globals.get(address)
    if g is None:
        raise EditError(f"no global at {address}")
    materialize_global(g)
    ov = dict(g.overrides)
    for k, v in edit.changes().items():
        _apply_scalar(ov, k, v)
    g.overrides = ov
    materialize_global(g)
    kb.save_global(g)
    _mark_pending(kb)
    return g


def _mark_pending(kb):
    kb.meta["edits_pending"] = True
    kb.save_meta()


def override_counts(kb) -> dict:
    return {
        "functions": sum(1 for r in kb.functions.values() if r.overrides),
        "classes": sum(1 for t in kb.types.values() if t.overrides),
        "globals": sum(1 for g in kb.globals.values() if g.overrides),
    }
