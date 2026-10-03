"""
Compilation checks for the reconstructed project.

Each function is syntax-checked on its own against the generated headers
(precise error attribution, parallelizable); the finished project is then
built with CMake. Compiler output is fed back to the Code Reconstructor.
"""

import re
import shutil
import subprocess
from pathlib import Path

_DIAG_RE = re.compile(r"^(?P<file>.*?):(?P<line>\d+):(?:(?P<col>\d+):)?\s*(?P<sev>error|fatal error|warning|note):"
                      r"\s*(?P<msg>.*)$")


class Compiler:
    def __init__(self, project_dir: Path, compiler_settings):
        self.project_dir = Path(project_dir)
        self.cfg = compiler_settings
        self.cxx = shutil.which(compiler_settings.cxx)
        self.cmake = shutil.which(compiler_settings.cmake)

    @property
    def available(self) -> bool:
        return self.cxx is not None

    def _syntax_check(self, source: Path) -> tuple:
        cmd = [self.cxx, f"-std=c++{self.cfg.cxx_standard}", "-fsyntax-only", "-fmax-errors=25", "-w",
               "-I", str(self.project_dir / "include"), str(source)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                  timeout=self.cfg.timeout_seconds)
        except subprocess.TimeoutExpired:
            return False, "compiler timed out"
        return proc.returncode == 0, (proc.stdout + proc.stderr).strip()

    def check_header(self) -> tuple:
        check_dir = self.project_dir / "check"
        check_dir.mkdir(parents=True, exist_ok=True)
        src = check_dir / "_header.cpp"
        src.write_text('#include "reconstructed.h"\n', encoding="utf-8")
        return self._syntax_check(src)

    def check_function(self, address: str, code: str) -> tuple:
        """(ok, diagnostics) for one function compiled against the project headers."""
        check_dir = self.project_dir / "check"
        check_dir.mkdir(parents=True, exist_ok=True)
        src = check_dir / f"{address}.cpp"
        src.write_text('#include "reconstructed.h"\n\n' + code + "\n", encoding="utf-8")
        ok, output = self._syntax_check(src)
        return ok, _clean(output, src, line_offset=2)

    def build(self) -> tuple:
        """Configure and build the project with CMake. (ok, log)."""
        if self.cmake is None:
            return False, f"{self.cfg.cmake} not found on PATH"
        build_dir = self.project_dir / "build"
        configure = [self.cmake, "-S", str(self.project_dir), "-B", str(build_dir)]
        if shutil.which("ninja"):
            configure += ["-G", "Ninja"]
        if self.cxx:
            configure += [f"-DCMAKE_CXX_COMPILER={self.cxx}"]
        log = []
        for cmd in (configure, [self.cmake, "--build", str(build_dir)]):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                      timeout=self.cfg.timeout_seconds * 10)
            except subprocess.TimeoutExpired:
                return False, "\n".join(log + ["cmake timed out"])
            log.append(proc.stdout + proc.stderr)
            if proc.returncode != 0:
                return False, "\n".join(log)
        return True, "\n".join(log)


def _clean(output: str, src: Path, line_offset: int) -> str:
    """Rewrite diagnostics for the function file to be relative to the function's own text."""
    lines = []
    for line in output.splitlines():
        m = _DIAG_RE.match(line)
        if m and Path(m.group("file")).name == src.name:
            n = max(1, int(m.group("line")) - line_offset)
            lines.append(f"function.cpp:{n}: {m.group('sev')}: {m.group('msg')}")
        elif m:
            lines.append(f"{Path(m.group('file')).name}:{m.group('line')}: {m.group('sev')}: {m.group('msg')}")
        elif line.strip() and not line.startswith("In file included") and "In function" not in line:
            lines.append(line)
    return "\n".join(lines[:60])


def first_error(diagnostics: str) -> str:
    for line in diagnostics.splitlines():
        if ": error:" in line or "fatal error" in line:
            return line
    return diagnostics.splitlines()[0] if diagnostics else ""
