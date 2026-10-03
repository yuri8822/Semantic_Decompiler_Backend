"""
Records stored in the knowledge base. Every discovery an agent makes carries
a confidence; knowledge/confidence.py decides what that confidence allows.

LLM output is validated into these models leniently (hex-string offsets,
percent confidences, missing fields) so one sloppy answer degrades to low
confidence instead of crashing a run.
"""

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


def to_int(value) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        s = value.strip().lower().lstrip("+")
        neg = s.startswith("-")
        s = s.lstrip("-")
        try:
            n = int(s, 16) if s.startswith("0x") else int(s)
        except ValueError:
            return 0
        return -n if neg else n
    return 0


def to_confidence(value) -> float:
    if isinstance(value, str):
        value = value.strip().rstrip("%")
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0
    if value > 1.0:
        value /= 100.0
    return max(0.0, min(1.0, value))


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class _Guess(_Model):
    confidence: float = 0.0

    @field_validator("confidence", mode="before")
    @classmethod
    def _conf(cls, v):
        return to_confidence(v)


# ---------------------------------------------------------------------------
# Analyzer output
# ---------------------------------------------------------------------------

ParamRole = Literal["normal", "this", "return_slot"]
MethodKind = Literal["free", "method", "constructor", "destructor", "static", "virtual"]


class ParamGuess(_Guess):
    index: int
    old_name: str = ""
    name: str = ""
    type: str = ""
    role: ParamRole = "normal"
    meaning: str = ""

    @field_validator("index", mode="before")
    @classmethod
    def _idx(cls, v):
        return to_int(v)

    @field_validator("role", mode="before")
    @classmethod
    def _role(cls, v):
        v = str(v or "normal").lower()
        return v if v in ("normal", "this", "return_slot") else "normal"


class LocalGuess(_Guess):
    old_name: str
    name: str
    type: str = ""


class FieldGuess(_Guess):
    param: int = 0
    class_name: str = ""
    offset: int
    name: str
    type: str = ""
    evidence: str = ""

    @field_validator("param", "offset", mode="before")
    @classmethod
    def _ints(cls, v):
        return to_int(v)


class GlobalGuess(_Guess):
    address: str
    old_name: str = ""
    name: str
    type: str = ""


class FunctionAnalysis(_Model):
    name: str
    name_confidence: float = 0.0
    class_name: str = ""
    method_kind: MethodKind = "free"
    summary: str = ""
    evidence: list[str] = []
    return_type: str = ""
    return_meaning: str = ""
    return_confidence: float = 0.0
    params: list[ParamGuess] = []
    locals: list[LocalGuess] = []
    fields: list[FieldGuess] = []
    globals: list[GlobalGuess] = []
    notes: list[str] = []
    # Set by deterministic cross-checks (knowledge/crosscheck.py), never by the LLM.
    contradictions: list[str] = []
    observed_return_type: str = ""   # what callers receive the result into
    # bookkeeping
    round: int = 0
    provider: str = ""
    ir_hash: str = ""

    @field_validator("name_confidence", "return_confidence", mode="before")
    @classmethod
    def _conf(cls, v):
        return to_confidence(v)

    @field_validator("method_kind", mode="before")
    @classmethod
    def _kind(cls, v):
        v = str(v or "free").lower()
        return v if v in ("free", "method", "constructor", "destructor", "static", "virtual") else "free"

    @field_validator("evidence", "notes", mode="before")
    @classmethod
    def _strlist(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return [str(x) for x in v]

    @property
    def is_method(self) -> bool:
        return bool(self.class_name) and self.method_kind != "free"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class Issue(_Model):
    severity: Literal["error", "warning"]
    check: str
    message: str


# ---------------------------------------------------------------------------
# Per-function record
# ---------------------------------------------------------------------------

class FunctionRecord(_Model):
    address: str
    ghidra_name: str            # name in the round-0 (raw) export
    full_name: str = ""
    excluded: str = ""          # non-empty: reason the function is out of scope
    alias_of: str = ""          # duplicate ctor/dtor variant of another address

    analysis: Optional[FunctionAnalysis] = None
    analysis_history: list[dict] = []
    needs_reanalysis: bool = False

    cpp: str = ""
    cpp_ir_hash: str = ""
    cpp_provider: str = ""
    cpp_signature: str = ""
    static_issues: list[Issue] = []
    static_fix_rounds: int = 0
    compile_status: Literal["unchecked", "ok", "error", "skipped"] = "unchecked"
    compile_errors: str = ""
    compile_fix_rounds: int = 0


# ---------------------------------------------------------------------------
# Types and globals
# ---------------------------------------------------------------------------

class FieldDef(_Guess):
    offset: int
    size: int = 0
    name: str
    type: str = ""
    evidence: list[str] = []

    @field_validator("offset", "size", mode="before")
    @classmethod
    def _ints(cls, v):
        return to_int(v)

    @field_validator("evidence", mode="before")
    @classmethod
    def _ev(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return [str(x) for x in v]


class TypeRecord(_Guess):
    name: str
    kind: Literal["class", "struct"] = "class"
    size: int = 0
    size_confidence: float = 0.0
    base_class: str = ""
    base_confidence: float = 0.0
    fields: list[FieldDef] = []
    members: list[str] = []        # addresses of member functions
    same_as: list[str] = []
    notes: str = ""
    from_symbols: bool = False     # the class name came from Ghidra symbols, not the LLM
    round: int = 0
    evidence_hash: str = ""        # skip re-reconstruction when the evidence hasn't changed

    @field_validator("size", mode="before")
    @classmethod
    def _size(cls, v):
        return to_int(v)

    @field_validator("size_confidence", "base_confidence", mode="before")
    @classmethod
    def _conf2(cls, v):
        return to_confidence(v)

    @field_validator("kind", mode="before")
    @classmethod
    def _kind(cls, v):
        return "struct" if str(v).lower() == "struct" else "class"

    def field_at(self, offset: int) -> Optional[FieldDef]:
        return next((f for f in self.fields if f.offset == offset), None)

    def field_covering(self, offset: int) -> Optional[FieldDef]:
        for f in self.fields:
            if f.offset <= offset < f.offset + max(1, f.size):
                return f
        return None


class GlobalRecord(_Guess):
    address: str
    ghidra_name: str
    name: str = ""
    type: str = ""
    applied_name: str = ""         # the name this pipeline last applied in Ghidra
    referenced_by: list[str] = Field(default_factory=list)
