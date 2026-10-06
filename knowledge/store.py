"""
The project knowledge base: plain JSON files every agent reads and writes.

    workspace/<binary>/
        knowledge.json          run metadata, rounds, name map, statistics
        functions/<addr>.json   one FunctionRecord per function
        types/<Name>.json       one TypeRecord per reconstructed class/struct
        globals/<addr>.json     one GlobalRecord per referenced global
        strings/strings.json    program strings and who references them
        relationships/          calls, field accesses, this-pointer passing,
                                class membership (derived, rewritten on save)
        ghidra/                 IR exports, apply plans and reports per round
        logs/llm/               every prompt and response
        reconstructed/          the generated C++ project
"""

import json
import os
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from ghidra_io.ir import ProgramIR
from knowledge.models import FunctionRecord, GlobalRecord, TypeRecord


def _write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{threading.get_ident()}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(data, indent=2, ensure_ascii=False))
        # Force the bytes to disk before the rename: otherwise a power cut can
        # leave the renamed file full of zeros (seen on 2026-10-03).
        fh.flush()
        os.fsync(fh.fileno())
    # On Windows, replacing a file another thread is reading at that instant
    # (e.g. the API serving a live workspace) fails transiently; retry briefly.
    for attempt in range(20):
        try:
            tmp.replace(path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


def _read_text(path: Path) -> str:
    for attempt in range(20):
        try:
            return path.read_text(encoding="utf-8")
        except PermissionError:  # Windows: the file is being replaced right now
            if attempt == 19:
                raise
            time.sleep(0.05)


def _file_key(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


class KnowledgeBase:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.functions: dict[str, FunctionRecord] = {}
        self.types: dict[str, TypeRecord] = {}
        self.globals: dict[str, GlobalRecord] = {}
        self.meta: dict = {}
        self.corrupt: list[str] = []   # unreadable files skipped while loading (relative paths)
        self._lock = threading.RLock()

    # -- layout ---------------------------------------------------------------

    @property
    def ghidra_dir(self) -> Path:
        return self.root / "ghidra"

    @property
    def log_dir(self) -> Path:
        return self.root / "logs" / "llm"

    @property
    def reconstructed_dir(self) -> Path:
        return self.root / "reconstructed"

    def ir_path(self, round_num: int) -> Path:
        return self.ghidra_dir / f"round_{round_num}.json"

    def plan_path(self, round_num: int) -> Path:
        return self.ghidra_dir / f"plan_{round_num}.json"

    def report_path(self, round_num: int) -> Path:
        return self.ghidra_dir / f"report_{round_num}.json"

    # -- lifecycle ------------------------------------------------------------

    @classmethod
    def open(cls, root: Path, reset: bool = False) -> "KnowledgeBase":
        root = Path(root)
        if reset and root.exists():
            shutil.rmtree(root)
        kb = cls(root)
        kb._load()
        return kb

    def _load(self):
        """
        Unreadable files (e.g. zero-filled by a power cut mid-write) are skipped
        and listed in `self.corrupt` instead of making the whole workspace
        unloadable. A skipped function/global is simply re-created by the next
        run's scope stage and redone; a skipped type is reconstructed again.
        """
        meta_path = self.root / "knowledge.json"
        if meta_path.exists():
            try:
                self.meta = json.loads(_read_text(meta_path))
            except (ValueError, UnicodeDecodeError):
                self.corrupt.append("knowledge.json")
                self.meta = {}
        self.meta.setdefault("rounds", [])
        for folder, model, store, key in (("functions", FunctionRecord, self.functions, "address"),
                                          ("types", TypeRecord, self.types, "name"),
                                          ("globals", GlobalRecord, self.globals, "address")):
            for path in sorted((self.root / folder).glob("*.json")):
                try:
                    rec = model.model_validate_json(_read_text(path))
                except (ValueError, UnicodeDecodeError):   # pydantic's ValidationError is a ValueError
                    self.corrupt.append(f"{folder}/{path.name}")
                    continue
                store[getattr(rec, key)] = rec

    def quarantine_corrupt(self) -> list:
        """Move unreadable files into _corrupt/ (kept for inspection). Returns what was moved."""
        moved = []
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        for rel in self.corrupt:
            src = self.root / rel
            if not src.exists():
                continue
            dest = self.root / "_corrupt" / stamp / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            src.replace(dest)
            moved.append(rel)
        self.corrupt = []
        return moved

    # -- records --------------------------------------------------------------

    def save_function(self, rec: FunctionRecord):
        with self._lock:
            self.functions[rec.address] = rec
            _write_json(self.root / "functions" / f"{_file_key(rec.address)}.json", rec.model_dump())

    def save_type(self, rec: TypeRecord):
        with self._lock:
            self.types[rec.name] = rec
            _write_json(self.root / "types" / f"{_file_key(rec.name)}.json", rec.model_dump())

    def delete_type(self, name: str):
        with self._lock:
            self.types.pop(name, None)
            (self.root / "types" / f"{_file_key(name)}.json").unlink(missing_ok=True)

    def save_global(self, rec: GlobalRecord):
        with self._lock:
            self.globals[rec.address] = rec
            _write_json(self.root / "globals" / f"{_file_key(rec.address)}.json", rec.model_dump())

    def in_scope(self) -> list:
        """Records of functions to reconstruct (not excluded, not aliases), by address."""
        return [r for _, r in sorted(self.functions.items())
                if not r.excluded and not r.alias_of]

    # -- metadata -------------------------------------------------------------

    def save_meta(self):
        with self._lock:
            self.meta["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            _write_json(self.root / "knowledge.json", self.meta)

    @property
    def current_round(self) -> int:
        return self.meta.get("current_round", 0)

    def round_info(self, round_num: int) -> dict:
        for r in self.meta["rounds"]:
            if r["round"] == round_num:
                return r
        info = {"round": round_num}
        self.meta["rounds"].append(info)
        return info

    # -- derived tables -------------------------------------------------------

    def save_derived(self, ir: ProgramIR, name_of):
        """Rewrite strings/ and relationships/ from the current IR and names."""
        in_ir = ir.by_address
        calls = [
            {"from": f.address, "from_name": name_of(f.address), "to": c,
             "to_name": name_of(c) if c in in_ir else c}
            for f in ir.functions for c in f.callees
        ]
        field_accesses = {
            f.address: [a.model_dump() for a in f.field_accesses]
            for f in ir.functions if f.field_accesses
        }
        arg_passes = {
            f.address: [a.model_dump() for a in f.arg_passes]
            for f in ir.functions if f.arg_passes
        }
        members = {name: rec.members for name, rec in sorted(self.types.items())}
        rel = self.root / "relationships"
        _write_json(rel / "calls.json", calls)
        _write_json(rel / "field_accesses.json", field_accesses)
        _write_json(rel / "this_passing.json", arg_passes)
        _write_json(rel / "class_members.json", members)

        referenced = {}
        for f in ir.functions:
            for s in f.strings:
                referenced.setdefault(s, []).append(f.address)
        _write_json(self.root / "strings" / "strings.json", [
            {"address": s.address, "value": s.value, "referenced_by": referenced.get(s.value, [])}
            for s in ir.strings
        ])
