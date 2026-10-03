"""
Drives Ghidra's headless analyzer.

Two operations, both ending in a fresh IR export (ExportProgram.java):

  import_and_export   import the binary, run auto-analysis, export round 0
  apply_and_export    re-open the analyzed program (no re-analysis), apply a
                      knowledge plan (ApplyKnowledge.java), save, re-export

The second is the feedback loop: renames and types applied to the program
make Ghidra's own decompiler produce better pseudocode for the next round.
"""

import os
import subprocess
from pathlib import Path

from settings import Settings


class GhidraError(RuntimeError):
    pass


class GhidraRunner:
    """`on_line(text)` (optional) receives every line of Ghidra's output as it arrives."""

    def __init__(self, binary: Path, settings: Settings, verbose: bool = False, on_line=None):
        self.binary = Path(binary).resolve()
        self.verbose = verbose
        self.on_line = on_line
        self.headless = Path(settings.ghidra.headless)
        self.project_dir = settings.path(settings.ghidra.project_dir)
        self.project_name = settings.ghidra.project_name
        self.script_dir = settings.path(settings.ghidra.script_dir)
        self._proc = None

    @property
    def program_name(self) -> str:
        # analyzeHeadless names the imported program after the file.
        return self.binary.name

    def import_and_export(self, out_json: Path) -> Path:
        if not self.binary.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary}")
        out_json = Path(out_json).resolve()
        self._run(
            ["-import", str(self.binary), "-overwrite"],
            [["ExportProgram.java", str(out_json)]],
            expect=[out_json],
        )
        return out_json

    def apply_and_export(self, plan_json: Path, report_json: Path, out_json: Path) -> Path:
        plan_json, report_json, out_json = (Path(p).resolve() for p in (plan_json, report_json, out_json))
        self._run(
            ["-process", self.program_name, "-noanalysis"],
            [["ApplyKnowledge.java", str(plan_json), str(report_json)],
             ["ExportProgram.java", str(out_json)]],
            expect=[report_json, out_json],
        )
        return out_json

    def cancel(self):
        """Stop a running headless analysis (the launcher and the JVM it started)."""
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            proc.kill()

    def _run(self, mode_args: list, post_scripts: list, expect: list) -> str:
        if not self.headless.exists():
            raise FileNotFoundError(
                f"analyzeHeadless not found at {self.headless}. Set ghidra.headless in the settings."
            )
        self.project_dir.mkdir(parents=True, exist_ok=True)
        # Headless exits 0 even when a post-script throws, so a stale output
        # from an earlier run must never be mistaken for this run's.
        for path in expect:
            Path(path).unlink(missing_ok=True)

        cmd = [str(self.headless), str(self.project_dir), self.project_name, *mode_args,
               "-scriptPath", str(self.script_dir)]
        for script in post_scripts:
            cmd += ["-postScript", *script]

        lines = []
        self._proc = proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        try:
            for line in proc.stdout:
                lines.append(line)
                if self.verbose:
                    print(line, end="")
                if self.on_line:
                    self.on_line(line.rstrip("\n"))
            proc.wait()
        finally:
            self._proc = None
        output = "".join(lines)

        script_failed = "SCRIPT ERROR" in output
        missing = [str(p) for p in expect if not Path(p).exists()]
        if proc.returncode != 0 or script_failed or missing:
            reason = (f"exit code {proc.returncode}" if proc.returncode != 0
                      else "script error" if script_failed
                      else f"missing output {', '.join(missing)}")
            raise GhidraError(f"Ghidra headless failed ({reason}). Last output:\n{output[-4000:]}")
        return output
