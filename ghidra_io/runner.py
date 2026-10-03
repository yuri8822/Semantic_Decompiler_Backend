"""
Drives Ghidra's headless analyzer.

Two operations, both ending in a fresh IR export (ExportProgram.java):

  import_and_export   import the binary, run auto-analysis, export round 0
  apply_and_export    re-open the analyzed program (no re-analysis), apply a
                      knowledge plan (ApplyKnowledge.java), save, re-export

The second is the feedback loop: renames and types applied to the program
make Ghidra's own decompiler produce better pseudocode for the next round.
"""

import subprocess
from pathlib import Path

from config import GHIDRA_HEADLESS, GHIDRA_PROJECT_DIR, GHIDRA_PROJECT_NAME, GHIDRA_SCRIPT_DIR


class GhidraError(RuntimeError):
    pass


class GhidraRunner:
    def __init__(self, binary: Path, verbose: bool = False):
        self.binary = Path(binary).resolve()
        self.verbose = verbose

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

    def _run(self, mode_args: list, post_scripts: list, expect: list) -> str:
        headless = Path(GHIDRA_HEADLESS)
        if not headless.exists():
            raise FileNotFoundError(
                f"analyzeHeadless not found at {headless}. Set GHIDRA_HEADLESS or edit config.py."
            )
        GHIDRA_PROJECT_DIR.mkdir(parents=True, exist_ok=True)
        # Headless exits 0 even when a post-script throws, so a stale output
        # from an earlier run must never be mistaken for this run's.
        for path in expect:
            Path(path).unlink(missing_ok=True)

        cmd = [str(headless), str(GHIDRA_PROJECT_DIR), GHIDRA_PROJECT_NAME, *mode_args,
               "-scriptPath", str(GHIDRA_SCRIPT_DIR)]
        for script in post_scripts:
            cmd += ["-postScript", *script]

        lines = []
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        for line in proc.stdout:
            lines.append(line)
            if self.verbose:
                print(line, end="")
        proc.wait()
        output = "".join(lines)

        script_failed = "SCRIPT ERROR" in output
        missing = [str(p) for p in expect if not Path(p).exists()]
        if proc.returncode != 0 or script_failed or missing:
            reason = (f"exit code {proc.returncode}" if proc.returncode != 0
                      else "script error" if script_failed
                      else f"missing output {', '.join(missing)}")
            raise GhidraError(f"Ghidra headless failed ({reason}). Last output:\n{output[-4000:]}")
        return output
