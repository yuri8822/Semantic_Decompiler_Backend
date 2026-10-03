"""
The reconstruction pipeline:

    EXE ─► Ghidra import + auto-analysis ─► IR (round 0)
         ┌──────────────────────────────────────────────────────────────┐
         │ round r:  Analyzer (bottom-up through the call graph)        │
         │           Type Reconstructor (per class)                      │
         │           confidence-gated plan ─► Ghidra apply ─► IR (r)     │
         │           LOW-confidence functions queue for round r+1        │
         └──────────────────────────────────────────────────────────────┘
         ─► Code Reconstructor ◄─► Validator (static checks, compiler)
         ─► reconstructed/ (include, src, CMakeLists.txt) ─► CMake build ─► report

Every stage persists to the knowledge base and is resumable: rerunning picks
up where the last run stopped; restart=True starts from scratch.

The pipeline never prints. It reports through `on_event(event)` with plain
dicts (see EVENT TYPES below); reporting.ConsoleReporter renders them for the
CLI, the API streams them to the browser.

EVENT TYPES
    run_started   {binary, workspace, settings}
    stage         {stage, round, title}               a stage begins
    progress      {stage, round, done, total, item, ok, error}
    message       {level: info|warning|error, text}
    llm_call      {agent, provider, tag, seconds, ok, error, log}
    ghidra_output {line}
    stage_done    {stage, round, summary}
    run_finished  {status: done|cancelled|failed, summary, error}
"""

import contextvars
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import settings as settings_mod
from agents.analyzer import Analyzer
from agents.code_reconstructor import CodeReconstructor
from agents.context import Context
from agents.crosscheck import check_return_values
from agents.type_reconstructor import TypeReconstructor
from agents.validator import Validator, errors
from ghidra_io.ir import ProgramIR, load_ir
from ghidra_io.runner import GhidraRunner
from knowledge.callgraph import bottom_up_levels
from knowledge.confidence import analysis_needs_another_pass, tier
from knowledge.filters import exclusion_reason, is_imported_data
from knowledge.ghidra_plan import build_plan, summarize_report
from knowledge.models import FunctionRecord, GlobalRecord
from knowledge.naming import sanitize_identifier
from knowledge.signatures import assign_signatures
from knowledge.store import KnowledgeBase
from llm.client import LLMClient, TrafficLog
from llm.providers import missing_api_key
from output.compiler import Compiler, first_error
from output.project import ProjectWriter
from output.report import write_report
from settings import Settings

AGENTS = ("analyzer", "type_reconstructor", "code_reconstructor")


class Cancelled(Exception):
    pass


class ConfigurationError(ValueError):
    pass


def matches(token: str, address: str, names: tuple) -> bool:
    """A scope token: an address (0x..., any case/leading zeros) or a (qualified) name."""
    token = token.strip()
    if not token:
        return False
    if token.lower().startswith("0x"):
        try:
            return int(token, 16) == int(address, 16)
        except ValueError:
            return False
    return token in names or sanitize_identifier(token) in {sanitize_identifier(n) for n in names if n}


class Pipeline:
    def __init__(self, binary: Path, settings: Settings = None, restart: bool = False, on_event=None,
                 llm=None, runner=None, verbose: bool = False):
        self.binary = Path(binary)
        self.stem = self.binary.stem
        self.settings = settings or settings_mod.load()
        self.on_event = on_event or (lambda event: None)
        self.restart = restart
        self.kb = KnowledgeBase.open(self.settings.path(self.settings.workspace_dir) / self.stem, reset=restart)

        if llm is not None:  # one client for every agent (tests, embedding)
            self.clients = {agent: llm for agent in AGENTS}
        else:
            self.clients = self._make_clients()
        self.runner = runner or GhidraRunner(self.binary, self.settings, verbose=verbose,
                                             on_line=lambda line: self._emit("ghidra_output", line=line))
        self.analyzer = Analyzer(self.clients["analyzer"])
        self.typer = TypeReconstructor(self.clients["type_reconstructor"])
        self.coder = CodeReconstructor(self.clients["code_reconstructor"])
        self.validator = Validator()

        self.failures = []
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self.scope = []
        self.ir0 = None

    def _make_clients(self) -> dict:
        s = self.settings.llm
        providers = {agent: s.provider_for(agent) for agent in AGENTS}
        missing = {p: missing_api_key(p) for p in set(providers.values()) if missing_api_key(p)}
        if missing:
            raise ConfigurationError("missing API key(s): " + ", ".join(
                f"{var} (for {p})" for p, var in sorted(missing.items())) + " — add them to .env")
        log = TrafficLog(self.kb.log_dir) if s.log_traffic else None
        clients = {}
        for agent, provider in providers.items():
            clients[agent] = LLMClient(provider, s, log=log,
                                       on_call=lambda info, a=agent: self._emit("llm_call", agent=a, **info))
        return clients

    # =========================================================================

    def cancel(self):
        """Stop as soon as possible: in-flight LLM calls finish, queued work is dropped, Ghidra is killed."""
        self._cancel.set()
        if hasattr(self.runner, "cancel"):
            self.runner.cancel()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def run(self) -> dict:
        with settings_mod.use(self.settings):
            self._emit("run_started", binary=str(self.binary), workspace=str(self.kb.root),
                       settings=self.settings.model_dump())
            try:
                summary = self._run()
            except Cancelled:
                self._emit("run_finished", status="cancelled", summary={}, error="")
                raise
            except BaseException as exc:
                if self.cancelled:  # e.g. Ghidra killed by cancel()
                    self._emit("run_finished", status="cancelled", summary={}, error="")
                    raise Cancelled() from exc
                self._emit("run_finished", status="failed", summary={}, error=f"{type(exc).__name__}: {exc}")
                raise
            self._emit("run_finished", status="done", summary=summary, error="")
            return summary

    def _run(self) -> dict:
        self.kb.meta["settings"] = self.settings.model_dump()
        ir0, ir = self.stage_ghidra()
        self.ir0 = ir0
        self._checkpoint()
        self.seed(ir0)
        ir = self.stage_analysis(ir)
        sigs = assign_signatures(self.kb, ir)
        compiler = None
        if self.settings.code.enabled:
            sigs, compiler = self.stage_code(ir)
        build = self.stage_project(ir, sigs, compiler)
        report = write_report(self.kb, ir, sigs, build, self.failures)
        return self._summary(sigs, build, report)

    # -- 1. Ghidra ---------------------------------------------------------------

    def stage_ghidra(self):
        self._stage("ghidra", "Ghidra headless analysis")
        ir0_path = self.kb.ir_path(0)
        if ir0_path.exists():
            self._info(f"reusing {ir0_path}")
        else:
            self.runner.import_and_export(ir0_path)
            # A fresh import discards everything previously applied in Ghidra.
            self.kb.meta["rounds"] = []
            self.kb.meta["current_round"] = 0
            self._info(f"exported {ir0_path}")
        ir0 = load_ir(ir0_path)
        self.kb.meta.update({"binary": str(self.binary), "program": ir0.program.model_dump()})
        current = self.kb.current_round
        ir = load_ir(self.kb.ir_path(current)) if current and self.kb.ir_path(current).exists() else ir0
        summary = {"functions": len(ir0.functions), "strings": len(ir0.strings),
                   "language": ir0.program.language, "current_round": current}
        self._stage_done("ghidra", summary)
        return ir0, ir

    def seed(self, ir0: ProgramIR):
        """Function and global records from the raw round-0 export (names there are Ghidra's own)."""
        self._stage("scope", "Selecting functions to reconstruct")
        sc = self.settings.scope
        for fn in ir0.functions:
            names = (fn.name, fn.full_name)
            rec = self.kb.functions.get(fn.address)
            if rec is None:
                rec = FunctionRecord(address=fn.address, ghidra_name=fn.name, full_name=fn.full_name)
            reason = exclusion_reason(fn)
            if any(matches(t, fn.address, names) for t in sc.include):
                reason = ""
            if any(matches(t, fn.address, names) for t in sc.exclude):
                reason = "excluded by settings (scope.exclude)"
            if rec.excluded != reason or fn.address not in self.kb.functions:
                rec.excluded = reason
                self.kb.save_function(rec)
        in_scope = {r.address for r in self.kb.in_scope()}
        for fn in ir0.functions:
            if fn.address not in in_scope:
                continue
            for g in fn.globals:
                if g.external or not g.address or is_imported_data(g.name):
                    continue
                rec = self.kb.globals.get(g.address) or GlobalRecord(address=g.address, ghidra_name=g.name)
                if fn.address not in rec.referenced_by:
                    rec.referenced_by.append(fn.address)
                    self.kb.save_global(rec)
        scope = sorted(in_scope)
        if sc.only:
            scope = [a for a in scope if any(matches(t, a, (ir0.get(a).name, ir0.get(a).full_name))
                                             for t in sc.only)]
        if sc.limit:
            scope = scope[:sc.limit]
        self.scope = scope
        excluded = sum(1 for r in self.kb.functions.values() if r.excluded)
        self.kb.save_meta()
        self._stage_done("scope", {"in_scope": len(in_scope), "excluded": excluded, "processing": len(scope)})

    # -- 2-4. Analysis rounds ------------------------------------------------------

    def stage_analysis(self, ir: ProgramIR) -> ProgramIR:
        a_cfg = self.settings.analysis
        done = self.kb.meta.get("analysis_round_done", 0)
        for r in range(1, a_cfg.rounds + 1):
            if r <= done:
                continue
            self._checkpoint()
            self._cross_check()   # earlier rounds' results may contradict the binary
            targets = [a for a in self.scope if self._needs_analysis(a, r)]
            if r > 1 and not targets:
                self._info(f"round {r}: nothing left at low confidence")
                break
            self._stage("analysis", f"Analyzer — round {r}: {len(targets)} function(s)", r)
            levels = bottom_up_levels({a: ir.get(a).callees for a in self.scope if ir.get(a)})
            target_set = set(targets)
            self._run_levels([[a for a in lv if a in target_set] for lv in levels],
                             lambda a, ctx: self._analyze_one(a, ctx, r), ir, "analysis", r)
            self._cross_check()   # before anything from this round reaches Ghidra
            self._stage_done("analysis", {"analyzed": len(targets)}, r)

            if a_cfg.reconstruct_types:
                self._checkpoint()
                self._stage("types", "Type Reconstructor", r)
                self._reconstruct_types(ir, r)

            if a_cfg.apply_to_ghidra:
                self._checkpoint()
                self._stage("apply", "Applying knowledge to Ghidra and re-decompiling", r)
                ir = self._apply(ir, r)

            low = [a for a in self.scope if analysis_needs_another_pass(self.kb.functions[a].analysis)]
            for a in self.scope:
                rec = self.kb.functions[a]
                if rec.needs_reanalysis != (a in low):
                    rec.needs_reanalysis = a in low
                    self.kb.save_function(rec)
            self.kb.meta["analysis_round_done"] = r
            self.kb.save_meta()
            self._info(f"{len(low)} function(s) still low-confidence after round {r}")
        return ir

    def _cross_check(self):
        if not self.settings.analysis.return_value_crosscheck:
            return
        flagged = check_return_values(self.kb, self.ir0, self.scope)
        for a in flagged:
            rec = self.kb.functions[a]
            if rec.analysis.contradictions:
                self._warn(f"{rec.analysis.name}: {rec.analysis.contradictions[0]}")

    def _needs_analysis(self, address: str, round_num: int) -> bool:
        a = self.kb.functions[address].analysis
        if a is None:
            return True
        return round_num > 1 and a.round < round_num and analysis_needs_another_pass(a)

    def _analyze_one(self, address: str, ctx: Context, round_num: int):
        rec = self.kb.functions[address]
        fn = ctx.ir.get(address)
        analysis = self.analyzer.analyze(ctx, fn, rec, round_num)
        if rec.analysis:
            prev = rec.analysis
            rec.analysis_history.append({"round": prev.round, "name": prev.name,
                                         "name_confidence": prev.name_confidence, "summary": prev.summary})
        rec.analysis = analysis
        self.kb.save_function(rec)
        for g in analysis.globals:
            grec = self.kb.globals.get(g.address)
            if grec and (g.confidence > grec.confidence or not grec.name):
                grec.name, grec.type, grec.confidence = g.name, g.type, g.confidence
                self.kb.save_global(grec)

    def _reconstruct_types(self, ir: ProgramIR, round_num: int):
        sigs = assign_signatures(self.kb, ir)
        ctx = Context(self.kb, ir, sigs, ir0=self.ir0)
        cands = self.typer.candidates(ctx)
        valid = set(cands) | set(self.kb.types)
        work = []
        for name, cand in sorted(cands.items()):
            ev = self.typer.evidence(ctx, name, cand)
            has_evidence = any(i["accesses"] or i["guesses"] or i["passes"] for i in ev["functions"])
            existing = self.kb.types.get(name)
            if not has_evidence or (existing and existing.evidence_hash == self.typer.evidence_hash(ev)):
                if existing and sorted(cand["members"]) != existing.members:
                    existing.members = sorted(cand["members"])
                    self.kb.save_type(existing)
                continue
            work.append((name, cand, ev))

        def one(item, _ctx):
            name, cand, ev = item
            rec = self.typer.reconstruct(ctx, name, cand, ev, round_num, valid)
            member_names = {s.name for s in sigs.values() if s.class_name == name}
            for f in rec.fields:
                if f.name in member_names or f.name == name:
                    f.name = "m_" + f.name
            self.kb.save_type(rec)

        self._run_items(work, one, ctx, "types", round_num, key=lambda w: w[0])
        self._stage_done("types", {"reconstructed": len(work), "unchanged": len(cands) - len(work),
                                   "known": len(self.kb.types)}, round_num)

    def _apply(self, ir: ProgramIR, round_num: int) -> ProgramIR:
        plan = build_plan(self.kb, ir)
        plan_path, report_path, out_path = (self.kb.plan_path(round_num), self.kb.report_path(round_num),
                                            self.kb.ir_path(round_num))
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        counts = {k: len(v) for k, v in plan.items()}
        self._info(f"plan: {counts['functions']} function(s), {counts['structs']} struct(s), "
                   f"{counts['globals']} global(s)")
        self.runner.apply_and_export(plan_path, report_path, out_path)
        summary = summarize_report(json.loads(report_path.read_text(encoding="utf-8")))
        failed_targets = {f.get("target") for f in summary["failures"]}
        for g in plan["globals"]:
            if g["address"] not in failed_targets and g["address"] in self.kb.globals:
                grec = self.kb.globals[g["address"]]
                grec.applied_name = g["name"]
                self.kb.save_global(grec)
        info = self.kb.round_info(round_num)
        info.update({"ir": str(out_path), "plan": counts, **{k: summary[k] for k in ("applied", "skipped", "failed")}})
        self.kb.meta["current_round"] = round_num
        self.kb.save_meta()
        for f in summary["failures"][:5]:
            self._warn(f"Ghidra could not apply {f.get('kind')} {f.get('target')}: {f.get('error')}")
        new_ir = load_ir(out_path)
        sigs = assign_signatures(self.kb, new_ir)
        self.kb.save_derived(new_ir, Context(self.kb, new_ir, sigs, ir0=self.ir0).name_of)
        self._stage_done("apply", {"plan": counts, "applied": summary["applied"], "skipped": summary["skipped"],
                                   "failed": summary["failed"]}, round_num)
        return new_ir

    # -- 5. Code reconstruction + validation ------------------------------------

    def stage_code(self, ir: ProgramIR):
        self._checkpoint()
        self._stage("code", "Code Reconstructor + Validator")
        sigs = assign_signatures(self.kb, ir)
        ctx = Context(self.kb, ir, sigs, ir0=self.ir0)
        writer = ProjectWriter(self.kb.reconstructed_dir, self.kb, ir, sigs, self.stem)
        writer.write_headers()
        writer.write_cmake()
        self.kb.meta["name_map"] = {a: s.qualified for a, s in sorted(sigs.items())}
        self.kb.save_meta()

        compiler = None
        if self.settings.compiler.enabled:
            compiler = Compiler(self.kb.reconstructed_dir, self.settings.compiler)
            if not compiler.available:
                self._warn(f"{self.settings.compiler.cxx} not found on PATH — compile validation skipped")
                compiler = None
        if compiler:
            ok, out = compiler.check_header()
            if not ok:
                self._error("generated headers do not compile — compile validation skipped; "
                            "see reconstructed/check/header_errors.txt")
                (self.kb.reconstructed_dir / "check" / "header_errors.txt").write_text(out, encoding="utf-8")
                self.kb.meta["header_errors"] = out[:4000]
                compiler = None
            else:
                self.kb.meta.pop("header_errors", None)

        targets = [a for a in self.scope if a in sigs]
        self._run_items(targets, lambda a, c: self._code_one(a, c, compiler), ctx, "code")
        recs = [self.kb.functions[a] for a in targets]
        self._stage_done("code", {"functions": len(targets),
                                  "compile_ok": sum(r.compile_status == "ok" for r in recs),
                                  "compile_errors": sum(r.compile_status == "error" for r in recs),
                                  "validator_errors": sum(bool(errors(r.static_issues)) for r in recs)})
        return sigs, compiler

    def _code_key(self, ctx: Context, fn, sig) -> str:
        h = hashlib.sha1()
        h.update(fn.ir_hash().encode())
        h.update(sig.definition_head().encode())
        if sig.class_name:
            h.update(ctx.class_layout(sig.class_name).encode())
        for callee in fn.callees:   # callee signatures are part of the prompt
            csig = ctx.signatures.get(callee)
            if csig:
                h.update(csig.definition_head().encode())
        return h.hexdigest()[:16]

    def _code_one(self, address: str, ctx: Context, compiler):
        c_cfg = self.settings.code
        provider = self.coder.llm.provider
        rec = self.kb.functions[address]
        fn = ctx.ir.get(address)
        sig = ctx.signatures[address]
        key = self._code_key(ctx, fn, sig)
        fresh = not (rec.cpp and rec.cpp_ir_hash == key and rec.cpp_provider == provider)

        code = self.coder.write(ctx, fn, sig, rec) if fresh else rec.cpp
        issues = self.validator.check(ctx, fn, sig, code)
        static_rounds = 0
        while fresh and errors(issues) and static_rounds < c_cfg.max_static_fix_rounds and not self.cancelled:
            code = self.coder.fix(ctx, fn, sig, rec, code, issues, tag=f"fix_static{static_rounds + 1}")
            issues = self.validator.check(ctx, fn, sig, code)
            static_rounds += 1

        def compile_check():
            # An empty or definition-less answer compiles trivially; it must not count.
            if any(i.check == "definition" for i in issues):
                return False, f"no definition of `{sig.definition_head()}` was produced"
            return compiler.check_function(address, code)

        status, diag, compile_rounds = "unchecked", "", 0
        if compiler:
            ok, diag = compile_check()
            while not ok and compile_rounds < c_cfg.max_compile_fix_rounds and not self.cancelled:
                code = self.coder.fix(ctx, fn, sig, rec, code, errors(issues), diag,
                                      tag=f"fix_compile{compile_rounds + 1}")
                issues = self.validator.check(ctx, fn, sig, code)
                ok, diag = compile_check()
                compile_rounds += 1
            status = "ok" if ok else "error"
        elif any(i.check == "definition" for i in issues):
            status, diag = "error", f"no definition of `{sig.definition_head()}` was produced"

        rec.cpp, rec.cpp_ir_hash, rec.cpp_provider = code, key, provider
        rec.cpp_signature = sig.definition_head()
        rec.static_issues = issues
        rec.static_fix_rounds = static_rounds if fresh else rec.static_fix_rounds
        rec.compile_status, rec.compile_errors = status, (diag if status == "error" else "")
        rec.compile_fix_rounds = compile_rounds
        self.kb.save_function(rec)

    # -- 6. Project -------------------------------------------------------------

    def stage_project(self, ir: ProgramIR, sigs: dict, compiler) -> dict:
        self._checkpoint()
        self._stage("project", "Writing and building the reconstructed project")
        writer = ProjectWriter(self.kb.reconstructed_dir, self.kb, ir, sigs, self.stem)

        def banner_of(addr):
            rec = self.kb.functions.get(addr)
            if rec is None or not rec.cpp:
                return None
            sig = sigs[addr]
            a = rec.analysis
            lines = [f"{addr}  {sig.qualified}"]
            if a:
                lines.append(a.summary[:150])
                lines.append(f"name confidence {a.name_confidence:.2f} ({tier(a.name_confidence)})")
            errs = [i for i in rec.static_issues if i.severity == "error"]
            warns = [i for i in rec.static_issues if i.severity == "warning"]
            lines.append(f"validation: {len(errs)} error(s), {len(warns)} warning(s); compile: {rec.compile_status}")
            lines += [f"  {i.severity}: {i.message[:140]}" for i in (errs + warns)[:4]]
            if rec.compile_status == "error":
                lines.append("  compiler: " + first_error(rec.compile_errors)[:140])
            return lines, rec.cpp, rec.compile_status != "error"

        writer.write_headers()
        writer.write_cmake()
        line_map = writer.write_sources(banner_of)
        build = {"status": "skipped", "log": ""}
        if compiler and compiler.cmake:
            ok, log = compiler.build()
            build = {"status": "ok" if ok else "error", "log": log}
            (self.kb.reconstructed_dir / "build.log").write_text(log, encoding="utf-8")
            if not ok:
                self._error("CMake build failed — see reconstructed/build.log")
        build["files"] = sorted(line_map)
        self.kb.meta["build"] = {"status": build["status"]}
        self.kb.save_derived(ir, Context(self.kb, ir, sigs, ir0=self.ir0).name_of)
        self.kb.save_meta()
        self._stage_done("project", {"build": build["status"], "files": build["files"]})
        return build

    # -- events ------------------------------------------------------------------

    def _emit(self, type_: str, **data):
        event = {"type": type_, "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **data}
        try:
            self.on_event(event)
        except Exception:
            pass  # a broken listener must never break a run

    def _stage(self, stage: str, title: str, round_num: int = 0):
        self._emit("stage", stage=stage, round=round_num, title=title)

    def _stage_done(self, stage: str, summary: dict, round_num: int = 0):
        self._emit("stage_done", stage=stage, round=round_num, summary=summary)

    def _info(self, text: str):
        self._emit("message", level="info", text=text)

    def _warn(self, text: str):
        self._emit("message", level="warning", text=text)

    def _error(self, text: str):
        self._emit("message", level="error", text=text)

    # -- execution ---------------------------------------------------------------

    def _checkpoint(self):
        if self.cancelled:
            raise Cancelled()

    def _submit(self, pool, fn, *args):
        # Worker threads don't inherit context variables; carry the run's settings over.
        return pool.submit(contextvars.copy_context().run, fn, *args)

    def _run_levels(self, levels: list, work, ir: ProgramIR, stage: str, round_num: int = 0):
        """Run `work(address, ctx)` level by level; signatures refresh between levels."""
        total = sum(len(lv) for lv in levels)
        if not total:
            return
        state = {"done": 0, "total": total}
        with ThreadPoolExecutor(self.settings.llm.concurrency) as pool:
            for level in levels:
                if not level:
                    continue
                self._checkpoint()
                ctx = Context(self.kb, ir, assign_signatures(self.kb, ir), ir0=self.ir0)
                self._drain({self._submit(pool, work, a, ctx): a for a in level}, stage, round_num, state)

    def _run_items(self, items: list, work, ctx: Context, stage: str, round_num: int = 0, key=lambda x: x):
        if not items:
            return
        state = {"done": 0, "total": len(items)}
        with ThreadPoolExecutor(self.settings.llm.concurrency) as pool:
            self._drain({self._submit(pool, work, item, ctx): key(item) for item in items}, stage, round_num, state)

    def _drain(self, futures: dict, stage: str, round_num: int, state: dict):
        for fut in as_completed(futures):
            label = futures[fut]
            error = ""
            if fut.cancelled():
                continue
            try:
                fut.result()
            except Exception as exc:  # one item's failure must not stop the run
                error = f"{type(exc).__name__}: {exc}"
                with self._lock:
                    self.failures.append({"item": label, "error": error})
            state["done"] += 1
            self._emit("progress", stage=stage, round=round_num, done=state["done"], total=state["total"],
                       item=label, ok=not error, error=error)
            if self.cancelled:
                for f in futures:
                    f.cancel()
        self._checkpoint()

    def _summary(self, sigs: dict, build: dict, report: Path) -> dict:
        recs = [self.kb.functions[a] for a in self.scope if a in sigs]
        with_code = [r for r in recs if r.cpp]
        tiers = {"high": 0, "medium": 0, "low": 0}
        for r in recs:
            if r.analysis:
                tiers[tier(r.analysis.name_confidence)] += 1
        return {
            "functions": len(recs),
            "reconstructed": len(with_code),
            "name_confidence": tiers,
            "compile_ok": sum(r.compile_status == "ok" for r in with_code),
            "compile_errors": sum(r.compile_status == "error" for r in with_code),
            "validator_errors": sum(bool(errors(r.static_issues)) for r in with_code),
            "build": build["status"],
            "failures": len(self.failures),
            "project": str(self.kb.reconstructed_dir),
            "report": str(report),
            "workspace": str(self.kb.root),
        }
