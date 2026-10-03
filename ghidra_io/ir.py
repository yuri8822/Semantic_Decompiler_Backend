"""
Typed view of ExportProgram.java's JSON: the pipeline's intermediate
representation. One ProgramIR per Ghidra round; round 0 is the raw
auto-analysis, each later round reflects the knowledge applied back to Ghidra.
"""

import hashlib
import json
from functools import cached_property
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Param(_Model):
    index: int
    name: str
    type: str = ""
    storage: str = ""
    is_this: bool = False
    hidden_return: bool = False


class LocalVar(_Model):
    name: str
    type: str = ""
    storage: str = ""


class CallTarget(_Model):
    address: str = ""          # empty for external (imported) targets
    name: str
    external: bool = False
    library: str = ""


class GlobalRef(_Model):
    address: str = ""          # empty for external data (e.g. imported std::cout)
    name: str
    type: str = ""
    external: bool = False
    read: bool = True
    write: bool = False


class FieldAccess(_Model):
    """
    A load/store at `base + offset`, proven by p-code data flow. The base is
    parameter `param`, or (param == -1) a pointer Ghidra types as pointing to
    structure `type`, e.g. a `Piece *` loaded from a board array.
    """
    param: int
    param_name: str = ""
    type: str = ""             # structure the base points to ("" if untyped)
    offset: int
    size: int
    access: str                # "read" | "write"
    at: str = ""


class ArgPass(_Model):
    """`param + offset` passed as argument `arg` of a call to `callee`."""
    callee: str
    arg: int
    param: int
    param_name: str = ""
    offset: int = 0
    at: str = ""


class Stats(_Model):
    instructions: int = 0
    basic_blocks: int = 0
    cbranches: int = 0
    switches: int = 0
    calls: int = 0
    indirect_calls: int = 0
    loads: int = 0
    stores: int = 0
    returns: int = 0


class FunctionIR(_Model):
    address: str
    name: str
    full_name: str = ""
    namespace: str = ""
    namespace_is_class: bool = False
    name_source: str = "DEFAULT"
    signature_source: str = "DEFAULT"
    calling_convention: str = ""
    comment: str = ""
    body_size: int = 0
    signature: str = ""
    return_type: str = ""
    decompiled: str = ""
    decompile_error: str = ""
    parameters: list[Param] = []
    locals: list[LocalVar] = []
    assembly: list[str] = []
    callers: list[str] = []
    callees: list[str] = []
    calls: list[CallTarget] = []
    strings: list[str] = []
    globals: list[GlobalRef] = []
    types: list[str] = []
    field_accesses: list[FieldAccess] = []
    arg_passes: list[ArgPass] = []
    stats: Stats = Stats()

    @property
    def is_default_name(self) -> bool:
        return self.name_source == "DEFAULT"

    def ir_hash(self) -> str:
        """Identity of what the code reconstructor sees for this function."""
        h = hashlib.sha1()
        h.update(self.signature.encode("utf-8"))
        h.update(self.decompiled.encode("utf-8"))
        return h.hexdigest()[:16]

    def param(self, index: int):
        return next((p for p in self.parameters if p.index == index), None)

    def local(self, name: str):
        return next((l for l in self.locals if l.name == name), None)


class ProgramInfo(_Model):
    name: str = ""
    path: str = ""
    format: str = ""
    sha256: str = ""
    language: str = ""
    compiler: str = ""
    image_base: str = ""
    pointer_size: int = 8


class StringRef(_Model):
    address: str
    value: str


class ClassField(_Model):
    offset: int
    size: int
    name: str = ""
    type: str = ""


class ClassIR(_Model):
    name: str
    size: int = 0
    fields: list[ClassField] = []


IR_VERSION = 2   # ExportProgram.java's "version"; older exports lack typed field accesses


class ProgramIR(_Model):
    version: int = 1
    program: ProgramInfo = ProgramInfo()
    functions: list[FunctionIR] = []
    strings: list[StringRef] = []
    classes: list[ClassIR] = []

    @cached_property
    def by_address(self) -> dict:
        return {f.address: f for f in self.functions}

    def get(self, address: str):
        return self.by_address.get(address)


def load_ir(path: Path) -> ProgramIR:
    with open(path, encoding="utf-8") as fh:
        return ProgramIR.model_validate(json.load(fh))
