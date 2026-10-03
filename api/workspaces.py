"""
Read-only views over workspaces (workspace/<binary>/), shaped for a UI:
summaries for list screens, full detail for one function/class, the Ghidra
rounds, the generated project files and the LLM traffic logs.

Everything is read straight from the knowledge-base files the pipeline
writes, so a view is never stale relative to a run in progress.
"""

import json
import re
import shutil
from functools import lru_cache
from pathlib import Path

from agents.cpp_text import decision_points
from ghidra_io.ir import ProgramIR, load_ir
from knowledge.confidence import tier
from knowledge.signatures import assign_signatures
from knowledge.store import KnowledgeBase

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_LOG_RE = re.compile(r"^(?P<n>\d{5})_(?P<tag>.+)\.txt$")


class NotFound(LookupError):
    pass


@lru_cache(maxsize=16)
def _load_ir_cached(path: str, mtime: float) -> ProgramIR:
    return load_ir(Path(path))


def _ir(path: Path) -> ProgramIR:
    if not path.exists():
        raise NotFound(f"no IR at {path.name}")
    return _load_ir_cached(str(path), path.stat().st_mtime)


class Workspaces:
    def __init__(self, root_getter):
        self._root_getter = root_getter   # the workspace root can change with the settings

    @property
    def root(self) -> Path:
        return Path(self._root_getter())

    # -- lookup -------------------------------------------------------------------

    def path(self, name: str) -> Path:
        if not _NAME_RE.match(name) or name.startswith("_"):
            raise NotFound(f"invalid workspace name {name!r}")
        p = self.root / name
        if not (p / "knowledge.json").exists() and not (p / "functions").exists():
            raise NotFound(f"no workspace named {name!r}")
        return p

    def kb(self, name: str) -> KnowledgeBase:
        return KnowledgeBase.open(self.path(name))

    def current_ir(self, kb: KnowledgeBase) -> ProgramIR:
        r = kb.current_round
        p = kb.ir_path(r)
        return _ir(p if p.exists() else kb.ir_path(0))

    def signatures(self, kb: KnowledgeBase, ir: ProgramIR) -> dict:
        return assign_signatures(kb, ir, persist=False)   # reads never write over a running pipeline

    # -- workspaces -----------------------------------------------------------------

    def list(self) -> list:
        if not self.root.exists():
            return []
        out = []
        for p in sorted(self.root.iterdir()):
            if p.is_dir() and not p.name.startswith("_") and (p / "knowledge.json").exists():
                try:
                    out.append(self.summary(p.name))
                except (OSError, ValueError, NotFound):
                    continue
        return out

    def summary(self, name: str) -> dict:
        kb = self.kb(name)
        recs = list(kb.functions.values())
        in_scope = [r for r in recs if not r.excluded and not r.alias_of]
        analyzed = [r for r in in_scope if r.analysis]
        with_code = [r for r in in_scope if r.cpp]
        tiers = {"high": 0, "medium": 0, "low": 0}
        for r in analyzed:
            tiers[tier(r.analysis.name_confidence)] += 1
        m = kb.meta
        return {
            "name": name,
            "binary": m.get("binary", ""),
            "program": m.get("program", {}),
            "updated_at": m.get("updated_at", ""),
            "current_round": m.get("current_round", 0),
            "analysis_round_done": m.get("analysis_round_done", 0),
            "build": m.get("build", {}).get("status", ""),
            "counts": {
                "functions": len(recs), "in_scope": len(in_scope),
                "excluded": sum(1 for r in recs if r.excluded), "aliases": sum(1 for r in recs if r.alias_of),
                "analyzed": len(analyzed), "reconstructed": len(with_code),
                "compile_ok": sum(r.compile_status == "ok" for r in with_code),
                "compile_errors": sum(r.compile_status == "error" for r in in_scope),
                "validator_errors": sum(any(i.severity == "error" for i in r.static_issues) for r in with_code),
                "needs_reanalysis": sum(r.needs_reanalysis for r in in_scope),
                "classes": len(kb.types), "globals": len(kb.globals),
            },
            "name_confidence": tiers,
        }

    def detail(self, name: str) -> dict:
        kb = self.kb(name)
        return {**self.summary(name), "meta": kb.meta}

    def delete(self, name: str):
        shutil.rmtree(self.path(name))

    # -- functions -----------------------------------------------------------------

    def functions(self, name: str) -> list:
        kb = self.kb(name)
        ir = self.current_ir(kb)
        sigs = self.signatures(kb, ir)
        out = []
        for addr, r in sorted(kb.functions.items()):
            a = r.analysis
            sig = sigs.get(addr)
            fn = ir.get(addr)
            out.append({
                "address": addr,
                "name": sig.qualified if sig else (r.full_name or r.ghidra_name),
                "ghidra_name": r.full_name or r.ghidra_name,
                "excluded": r.excluded,
                "alias_of": r.alias_of,
                "summary": a.summary if a else "",
                "name_confidence": a.name_confidence if a else None,
                "tier": tier(a.name_confidence) if a else None,
                "analysis_round": a.round if a else 0,
                "needs_reanalysis": r.needs_reanalysis,
                "contradictions": len(a.contradictions) if a else 0,
                "has_code": bool(r.cpp),
                "compile_status": r.compile_status,
                "validator_errors": sum(i.severity == "error" for i in r.static_issues),
                "validator_warnings": sum(i.severity == "warning" for i in r.static_issues),
                "instructions": fn.stats.instructions if fn else 0,
                "class": sig.class_name if sig and sig.is_member else "",
            })
        return out

    def function(self, name: str, address: str) -> dict:
        kb = self.kb(name)
        address = _norm_address(address)
        rec = kb.functions.get(address)
        if rec is None:
            raise NotFound(f"no function at {address}")
        ir = self.current_ir(kb)
        ir0 = _ir(kb.ir_path(0))
        sigs = self.signatures(kb, ir)
        fn, fn0 = ir.get(address), ir0.get(address)
        sig = sigs.get(address)

        def neighbour(a):
            s = sigs.get(a)
            r = kb.functions.get(a)
            f = ir.get(a)
            return {"address": a, "name": s.qualified if s else (f.full_name if f else a),
                    "excluded": bool(r and r.excluded),
                    "summary": r.analysis.summary if r and r.analysis else ""}

        return {
            "record": rec.model_dump(),
            "signature": sig.to_dict() if sig else None,
            "ghidra": {
                "round": kb.current_round,
                "signature": fn.signature if fn else "",
                "decompiled": fn.decompiled if fn else "",
                "decompiled_round0": fn0.decompiled if fn0 else "",
                "assembly": fn.assembly if fn else [],
                "parameters": [p.model_dump() for p in fn.parameters] if fn else [],
                "locals": [l.model_dump() for l in fn.locals] if fn else [],
                "field_accesses": [x.model_dump() for x in fn.field_accesses] if fn else [],
                "arg_passes": [x.model_dump() for x in fn.arg_passes] if fn else [],
                "strings": fn.strings if fn else [],
                "globals": [g.model_dump() for g in fn.globals] if fn else [],
                "calls": [c.model_dump() for c in fn.calls] if fn else [],
                "stats": fn.stats.model_dump() if fn else {},
                "decision_points": decision_points(fn.decompiled) if fn else 0,
            },
            "callers": [neighbour(a) for a in (fn.callers if fn else [])],
            "callees": [neighbour(a) for a in (fn.callees if fn else [])],
        }

    # -- types, globals, strings, relationships -------------------------------------

    def types(self, name: str) -> list:
        kb = self.kb(name)
        return [{"name": t.name, "kind": t.kind, "size": t.size, "confidence": t.confidence,
                 "tier": tier(t.confidence), "base_class": t.base_class, "fields": len(t.fields),
                 "members": len(t.members), "round": t.round, "from_symbols": t.from_symbols}
                for t in sorted(kb.types.values(), key=lambda t: t.name)]

    def type(self, name: str, type_name: str) -> dict:
        kb = self.kb(name)
        t = kb.types.get(type_name)
        if t is None:
            raise NotFound(f"no class {type_name!r}")
        ir = self.current_ir(kb)
        sigs = self.signatures(kb, ir)
        d = t.model_dump()
        d["fields"] = [{**f.model_dump(), "tier": tier(f.confidence)} for f in t.fields]
        d["methods"] = [{"address": a, "name": sigs[a].qualified if a in sigs else a,
                         "declaration": sigs[a].declaration() if a in sigs else ""} for a in t.members]
        return d

    def globals(self, name: str) -> list:
        kb = self.kb(name)
        return [{**g.model_dump(), "tier": tier(g.confidence)}
                for g in sorted(kb.globals.values(), key=lambda g: g.address)]

    def strings(self, name: str) -> list:
        return self._json(name, "strings/strings.json", default=[])

    def relationships(self, name: str, kind: str) -> object:
        if kind not in ("calls", "field_accesses", "this_passing", "class_members"):
            raise NotFound(f"unknown relationship table {kind!r}")
        return self._json(name, f"relationships/{kind}.json", default=[] if kind == "calls" else {})

    def report(self, name: str) -> str:
        p = self.path(name) / "report.md"
        if not p.exists():
            raise NotFound("no report yet (the run has not finished)")
        return p.read_text(encoding="utf-8")

    # -- Ghidra rounds ----------------------------------------------------------------

    def rounds(self, name: str) -> list:
        kb = self.kb(name)
        out = [{"round": 0, "ir": kb.ir_path(0).exists()}]
        for r in sorted(kb.meta.get("rounds", []), key=lambda r: r["round"]):
            out.append({**r, "ir": kb.ir_path(r["round"]).exists(),
                        "has_plan": kb.plan_path(r["round"]).exists(),
                        "has_report": kb.report_path(r["round"]).exists()})
        return out

    def round_file(self, name: str, kind: str, round_num: int) -> dict:
        kb = self.kb(name)
        paths = {"plan": kb.plan_path, "report": kb.report_path}
        if kind not in paths:
            raise NotFound(f"unknown round file {kind!r}")
        p = paths[kind](round_num)
        if not p.exists():
            raise NotFound(f"no {kind} for round {round_num}")
        return json.loads(p.read_text(encoding="utf-8"))

    # -- reconstructed project files -------------------------------------------------

    def files(self, name: str) -> list:
        root = self.path(name) / "reconstructed"
        if not root.exists():
            return []
        out = []
        for p in sorted(root.rglob("*")):
            rel = p.relative_to(root).as_posix()
            if p.is_file() and not rel.startswith(("build/", "check/")):
                out.append({"path": rel, "size": p.stat().st_size})
        return out

    def file(self, name: str, rel: str) -> str:
        root = (self.path(name) / "reconstructed").resolve()
        p = (root / rel).resolve()
        if root not in p.parents or not p.is_file():
            raise NotFound(f"no file {rel!r}")
        return p.read_text(encoding="utf-8", errors="replace")

    # -- LLM logs -------------------------------------------------------------------

    def logs(self, name: str, address: str = "", agent: str = "") -> list:
        d = self.path(name) / "logs" / "llm"
        if not d.exists():
            return []
        address = _norm_address(address) if address else ""
        prefixes = {"analyzer": ("analyze_",), "type_reconstructor": ("types_",),
                    "code_reconstructor": ("code_", "fix_")}.get(agent, ())
        out = []
        for p in sorted(d.glob("*.txt")):
            m = _LOG_RE.match(p.name)
            if not m:
                continue
            tag = m.group("tag")
            if address and not tag.endswith("_" + address) and f"_{address}-" not in tag:
                continue
            if prefixes and not tag.startswith(prefixes):
                continue
            out.append({"name": p.name, "n": int(m.group("n")), "tag": tag, "size": p.stat().st_size,
                        "error": _is_error_log(p)})
        return out

    def log(self, name: str, log_name: str) -> dict:
        if not _LOG_RE.match(log_name):
            raise NotFound(f"invalid log name {log_name!r}")
        p = self.path(name) / "logs" / "llm" / log_name
        if not p.exists():
            raise NotFound(f"no log {log_name!r}")
        text = p.read_text(encoding="utf-8", errors="replace")
        parts = re.split(r"^=== (PROVIDER: .*|SYSTEM|USER|RESPONSE)$", text, flags=re.MULTILINE)
        out = {"name": log_name, "provider": "", "system": "", "user": "", "response": ""}
        for header, body in zip(parts[1::2], parts[2::2]):
            if header.startswith("PROVIDER:"):
                out["provider"] = header.split(":", 1)[1].strip()
            else:
                out[header.lower()] = body.strip("\n")
        return out

    # -- helpers -------------------------------------------------------------------

    def _json(self, name: str, rel: str, default):
        p = self.path(name) / rel
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default


def _norm_address(address: str) -> str:
    try:
        return f"{int(address, 16):#x}"
    except ValueError:
        raise NotFound(f"invalid address {address!r}")


def _is_error_log(p: Path) -> bool:
    with open(p, "rb") as fh:
        fh.seek(max(0, p.stat().st_size - 400))
        return b"<<error:" in fh.read()
