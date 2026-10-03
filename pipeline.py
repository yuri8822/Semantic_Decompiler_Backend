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
up where the last run stopped; --restart starts from scratch.
"""

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from agents.analyzer import Analyzer
from agents.code_reconstructor import CodeReconstructor
from agents.context import Context
from agents.crosscheck import check_return_values
from agents.type_reconstructor import TypeReconstructor
from agents.validator import Validator, errors
from config import (
    ANALYSIS_ROUNDS, LLM_CONCURRENCY, MAX_COMPILE_FIX_ROUNDS, MAX_STATIC_FIX_ROUNDS, WORKSPACE_DIR,
)
from ghidra_io.ir import ProgramIR, load_ir
from ghidra_io.runner import GhidraRunner
from knowledge.callgraph import bottom_up_levels
from knowledge.confidence import analysis_needs_another_pass, tier
from knowledge.filters import exclusion_reason, is_imported_data
from knowledge.ghidra_plan import build_plan, summarize_report
from knowledge.models import FunctionRecord, GlobalRecord
from knowledge.signatures import assign_signatures
from knowledge.store import KnowledgeBase
from llm.client import LLMClient
from output.compiler import Compiler, first_error
from output.project import ProjectWriter
from output.report import write_report


class Pipeline:
    def __init__(self, binary: Path, provider: str, ollama_model: str = None, restart: bool = False,
                 limit: int = 0, rounds: int = ANALYSIS_ROUNDS, apply_to_ghidra: bool = True,
                 compile_check: bool = True, concurrency: int = LLM_CONCURRENCY, verbose: bool = False,
                 workspace: Path = WORKSPACE_DIR, llm=None, runner=None, console: Console = None):
        self.binary = Path(binary)
        self.stem = self.binary.stem
        self.console = console or Console()
        self.kb = KnowledgeBase.open(Path(workspace) / self.stem, reset=restart)
        self.provider = provider.lower()
        self.llm = llm or LLMClient(self.provider, ollama_model, log_dir=self.kb.log_dir)
        self.runner = runner or GhidraRunner(self.binary, verbose=verbose)
        self.limit = limit
        self.rounds = max(1, rounds)
        self.apply_to_ghidra = apply_to_ghidra
        self.compile_check = compile_check
        self.concurrency = max(1, concurrency)
        self.analyzer = Analyzer(self.llm)
        self.typer = TypeReconstructor(self.llm)
        self.coder = CodeReconstructor(self.llm)
        self.validator = Validator()
        self.failures = []
        self._failures_lock = threading.Lock()
        self.scope = []
        self.ir0 = None

    # =========================================================================

    def run(self) -> Path:
        ir0, ir = self.stage_ghidra()
        self.ir0 = ir0
        self.seed(ir0)
        ir = self.stage_analysis(ir)
        sigs, compiler = self.stage_code(ir)
        build = self.stage_project(ir, sigs, compiler)
        report = write_report(self.kb, ir, sigs, build, self.failures)
        self._summary(sigs, build, report)
        return self.kb.reconstructed_dir

    # -- 1. Ghidra ---------------------------------------------------------------

    def stage_ghidra(self):
        self._stage("1", "Ghidra headless analysis")
        ir0_path = self.kb.ir_path(0)
        if ir0_path.exists():
            self.console.print(f"  [dim]reusing {ir0_path}[/dim]")
        else:
            self.runner.import_and_export(ir0_path)
            # A fresh import discards everything previously applied in Ghidra.
            self.kb.meta["rounds"] = []
            self.kb.meta["current_round"] = 0
            self.console.print(f"  [green]✓[/green] exported {ir0_path}")
        ir0 = load_ir(ir0_path)
        self.kb.meta.update({"binary": str(self.binary), "program": ir0.program.model_dump()})
        current = self.kb.current_round
        ir = load_ir(self.kb.ir_path(current)) if current and self.kb.ir_path(current).exists() else ir0
        self.console.print(f"  {len(ir0.functions)} functions, {len(ir0.strings)} strings, "
                           f"{ir0.program.language}; current IR: round {current}")
        return ir0, ir

    def seed(self, ir0: ProgramIR):
        """Function and global records from the raw round-0 export (names there are Ghidra's own)."""
        for fn in ir0.functions:
            rec = self.kb.functions.get(fn.address)
            if rec is None:
                rec = FunctionRecord(address=fn.address, ghidra_name=fn.name, full_name=fn.full_name)
            reason = exclusion_reason(fn)
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
        self.scope = sorted(in_scope)
        if self.limit:
            self.scope = self.scope[:self.limit]
        excluded = sum(1 for r in self.kb.functions.values() if r.excluded)
        self.console.print(f"  {len(in_scope)} functions in scope, {excluded} excluded as library/runtime code"
                           + (f"; processing the first {len(self.scope)} (--limit)" if self.limit else ""))
        self.kb.save_meta()

    # -- 2-4. Analysis rounds ------------------------------------------------------

    def stage_analysis(self, ir: ProgramIR) -> ProgramIR:
        done = self.kb.meta.get("analysis_round_done", 0)
        for r in range(1, self.rounds + 1):
            if r <= done:
                continue
            self._cross_check()   # earlier rounds' results may contradict the binary
            targets = [a for a in self.scope if self._needs_analysis(a, r)]
            if r > 1 and not targets:
                self.console.print(f"\n[bold][round {r}][/bold] nothing left at low confidence — done")
                break
            self._stage(f"2.{r}", f"Analyzer — round {r}: {len(targets)} function(s)")
            levels = bottom_up_levels({a: ir.get(a).callees for a in self.scope if ir.get(a)})
            target_set = set(targets)
            self._run_levels([[a for a in lv if a in target_set] for lv in levels],
                             lambda a, ctx: self._analyze_one(a, ctx, r), ir, "analyzing")
            self._cross_check()   # before anything from this round reaches Ghidra

            self._stage(f"3.{r}", "Type Reconstructor")
            self._reconstruct_types(ir, r)

            if self.apply_to_ghidra:
                self._stage(f"4.{r}", "Applying knowledge to Ghidra and re-decompiling")
                ir = self._apply(ir, r)

            low = [a for a in self.scope if analysis_needs_another_pass(self.kb.functions[a].analysis)]
            for a in self.scope:
                rec = self.kb.functions[a]
                if rec.needs_reanalysis != (a in low):
                    rec.needs_reanalysis = a in low
                    self.kb.save_function(rec)
            self.kb.meta["analysis_round_done"] = r
            self.kb.save_meta()
            self.console.print(f"  {len(low)} function(s) still low-confidence after round {r}")
        return ir

    def _cross_check(self):
        flagged = check_return_values(self.kb, self.ir0, self.scope)
        contradicted = [a for a in flagged if self.kb.functions[a].analysis.contradictions]
        for a in contradicted:
            rec = self.kb.functions[a]
            self.console.print(f"  [yellow]![/yellow] {rec.analysis.name}: {rec.analysis.contradictions[0][:160]}")

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
        if not work:
            self.console.print("  no class evidence changed")
            return

        def one(item, _ctx):
            name, cand, ev = item
            rec = self.typer.reconstruct(ctx, name, cand, ev, round_num, valid)
            member_names = {s.name for s in sigs.values() if s.class_name == name}
            for f in rec.fields:
                if f.name in member_names or f.name == name:
                    f.name = "m_" + f.name
            self.kb.save_type(rec)

        self._run_items(work, one, ctx, "reconstructing classes", key=lambda w: w[0])
        self.console.print(f"  {len(work)} class layout(s) reconstructed; {len(self.kb.types)} known")

    def _apply(self, ir: ProgramIR, round_num: int) -> ProgramIR:
        plan = build_plan(self.kb, ir)
        plan_path, report_path, out_path = (self.kb.plan_path(round_num), self.kb.report_path(round_num),
                                            self.kb.ir_path(round_num))
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        counts = {k: len(v) for k, v in plan.items()}
        self.console.print(f"  plan: {counts['functions']} function(s), {counts['structs']} struct(s), "
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
        self.console.print(f"  [green]✓[/green] applied {summary['applied']}, skipped {summary['skipped']}, "
                           f"failed {summary['failed']} — re-exported {out_path.name}")
        for f in summary["failures"][:5]:
            self.console.print(f"    [yellow]![/yellow] {f.get('kind')} {f.get('target')}: {f.get('error')}")
        new_ir = load_ir(out_path)
        sigs = assign_signatures(self.kb, new_ir)
        self.kb.save_derived(new_ir, Context(self.kb, new_ir, sigs, ir0=self.ir0).name_of)
        return new_ir

    # -- 5. Code reconstruction + validation ------------------------------------

    def stage_code(self, ir: ProgramIR):
        self._stage("5", "Code Reconstructor + Validator")
        sigs = assign_signatures(self.kb, ir)
        ctx = Context(self.kb, ir, sigs, ir0=self.ir0)
        writer = ProjectWriter(self.kb.reconstructed_dir, self.kb, ir, sigs, self.stem)
        writer.write_headers()
        writer.write_cmake()
        self.kb.meta["name_map"] = {a: s.qualified for a, s in sorted(sigs.items())}
        self.kb.save_meta()

        compiler = Compiler(self.kb.reconstructed_dir) if self.compile_check else None
        if compiler and not compiler.available:
            self.console.print("  [yellow]![/yellow] no C++ compiler on PATH — compile validation skipped")
            compiler = None
        if compiler:
            ok, out = compiler.check_header()
            if not ok:
                self.console.print("  [red]generated headers do not compile[/red] — compile validation "
                                   "skipped; see reconstructed/check/header_errors.txt")
                (self.kb.reconstructed_dir / "check" / "header_errors.txt").write_text(out, encoding="utf-8")
                self.kb.meta["header_errors"] = out[:4000]
                compiler = None
            else:
                self.kb.meta.pop("header_errors", None)

        targets = [a for a in self.scope if a in sigs]
        self._run_items(targets, lambda a, c: self._code_one(a, c, compiler), ctx, "reconstructing code")
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
        rec = self.kb.functions[address]
        fn = ctx.ir.get(address)
        sig = ctx.signatures[address]
        key = self._code_key(ctx, fn, sig)
        fresh = not (rec.cpp and rec.cpp_ir_hash == key and rec.cpp_provider == self.provider)

        code = self.coder.write(ctx, fn, sig, rec) if fresh else rec.cpp
        issues = self.validator.check(ctx, fn, sig, code)
        static_rounds = 0
        while fresh and errors(issues) and static_rounds < MAX_STATIC_FIX_ROUNDS:
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
            while not ok and compile_rounds < MAX_COMPILE_FIX_ROUNDS:
                code = self.coder.fix(ctx, fn, sig, rec, code, errors(issues), diag,
                                      tag=f"fix_compile{compile_rounds + 1}")
                issues = self.validator.check(ctx, fn, sig, code)
                ok, diag = compile_check()
                compile_rounds += 1
            status = "ok" if ok else "error"
        elif any(i.check == "definition" for i in issues):
            status, diag = "error", f"no definition of `{sig.definition_head()}` was produced"

        rec.cpp, rec.cpp_ir_hash, rec.cpp_provider = code, key, self.provider
        rec.cpp_signature = sig.definition_head()
        rec.static_issues = issues
        rec.static_fix_rounds = static_rounds if fresh else rec.static_fix_rounds
        rec.compile_status, rec.compile_errors = status, (diag if status == "error" else "")
        rec.compile_fix_rounds = compile_rounds
        self.kb.save_function(rec)

    # -- 6. Project -------------------------------------------------------------

    def stage_project(self, ir: ProgramIR, sigs: dict, compiler) -> dict:
        self._stage("6", "Writing and building the reconstructed project")
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
        line_map = writer.write_sources(banner_of)
        build = {"status": "skipped", "log": ""}
        if compiler and compiler.cmake:
            ok, log = compiler.build()
            build = {"status": "ok" if ok else "error", "log": log}
            (self.kb.reconstructed_dir / "build.log").write_text(log, encoding="utf-8")
            self.console.print(f"  CMake build: {'[green]ok[/green]' if ok else '[red]failed[/red] (see build.log)'}")
        build["files"] = sorted(line_map)
        self.kb.meta["build"] = {"status": build["status"]}
        self.kb.save_derived(ir, Context(self.kb, ir, sigs, ir0=self.ir0).name_of)
        self.kb.save_meta()
        return build

    # -- helpers ---------------------------------------------------------------

    def _stage(self, num: str, title: str):
        self.console.print(f"\n[bold][{num}][/bold] {title}")

    def _progress(self):
        return Progress(SpinnerColumn(), TextColumn("{task.description:<28}"), BarColumn(),
                        MofNCompleteColumn(), TimeElapsedColumn(), console=self.console, transient=False)

    def _run_levels(self, levels: list, work, ir: ProgramIR, desc: str):
        """Run `work(address, ctx)` level by level; signatures refresh between levels."""
        total = sum(len(lv) for lv in levels)
        if not total:
            return
        with self._progress() as progress, ThreadPoolExecutor(self.concurrency) as pool:
            task = progress.add_task(desc, total=total)
            for level in levels:
                if not level:
                    continue
                ctx = Context(self.kb, ir, assign_signatures(self.kb, ir), ir0=self.ir0)
                self._drain(pool, {pool.submit(work, a, ctx): a for a in level}, progress, task)

    def _run_items(self, items: list, work, ctx: Context, desc: str, key=lambda x: x):
        if not items:
            return
        with self._progress() as progress, ThreadPoolExecutor(self.concurrency) as pool:
            task = progress.add_task(desc, total=len(items))
            self._drain(pool, {pool.submit(work, item, ctx): key(item) for item in items}, progress, task)

    def _drain(self, pool, futures: dict, progress, task):
        for fut in as_completed(futures):
            label = futures[fut]
            try:
                fut.result()
            except Exception as exc:  # one function's failure must not stop the run
                with self._failures_lock:
                    self.failures.append({"item": label, "error": f"{type(exc).__name__}: {exc}"})
                progress.console.print(f"  [yellow]![/yellow] {label}: {type(exc).__name__}: {str(exc)[:200]}")
            progress.advance(task)

    def _summary(self, sigs: dict, build: dict, report: Path):
        recs = [self.kb.functions[a] for a in self.scope if a in sigs]
        with_code = [r for r in recs if r.cpp]
        ok = sum(r.compile_status == "ok" for r in with_code)
        bad = sum(r.compile_status == "error" for r in with_code)
        static_err = sum(bool(errors(r.static_issues)) for r in with_code)
        tiers = {"high": 0, "medium": 0, "low": 0}
        for r in recs:
            if r.analysis:
                tiers[tier(r.analysis.name_confidence)] += 1
        self.console.print(
            f"\n[bold green]Done.[/bold green] {len(with_code)}/{len(recs)} functions reconstructed — "
            f"names: {tiers['high']} high / {tiers['medium']} medium / {tiers['low']} low confidence; "
            f"compile: {ok} ok, {bad} failing; {static_err} with unresolved validator errors; "
            f"project build: {build['status']}"
        )
        self.console.print(f"  project: [bold]{self.kb.reconstructed_dir}[/bold]")
        self.console.print(f"  report:  [bold]{report}[/bold]")
        self.console.print(f"  knowledge base: {self.kb.root}")
