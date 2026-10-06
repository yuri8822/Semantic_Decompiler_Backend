"""
Launches and supervises a local llama.cpp server for the `llamacpp` provider.

The server is configured by the `llamacpp_server` settings group and listens
where `llm.llamacpp.base_url` points, which must be this machine. One server
per backend process (`SERVER`): it outlives individual runs, since loading a
model takes a while, and is stopped when the backend exits. On Windows it is
also tied to the backend through a job object, so it dies with the backend
even when the backend's window is simply closed.

A server someone started by hand on the same port is used as-is ("external").
"""

import atexit
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_SPLIT_PART_RE = re.compile(r"-(\d{5})-of-\d{5}\.gguf$", re.IGNORECASE)
_LOG_TAIL_BYTES = 64 * 1024


class LlamaServerError(RuntimeError):
    pass


# -- configuration helpers -----------------------------------------------------------

def endpoint(base_url: str):
    """(host, port) of `base_url` if it is on this machine, else None."""
    try:
        u = urlparse(base_url)
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        return None
    if (u.hostname or "").lower() not in LOCAL_HOSTS:
        return None
    return ("127.0.0.1" if u.hostname == "localhost" else u.hostname), port


def find_executable(name: str):
    """Full path of the llama.cpp executable, or None if it isn't installed."""
    name = (name or "").strip().strip('"')
    if not name:
        return None
    p = Path(os.path.expandvars(name)).expanduser()
    if p.is_file():
        return str(p)
    return shutil.which(name)


def split_args(text: str) -> list:
    """Split extra arguments like a command line; double quotes group, backslashes stay (Windows paths)."""
    return [t[1:-1] if len(t) > 1 and t[0] == t[-1] == '"' else t for t in shlex.split(text or "", posix=False)]


def build_command(exe: str, cfg, host: str, port: int) -> list:
    # The unified `llama` CLI serves with `llama serve ...`; llama-server takes the flags directly.
    cmd = [exe] + (["serve"] if Path(exe).stem.lower() == "llama" else [])
    cmd += ["--model", model_file(cfg), "--host", host, "--port", str(port),
            "-ngl", str(cfg.gpu_layers), "-c", str(cfg.context_size), "-np", str(cfg.parallel),
            "--reasoning", cfg.thinking]
    if cfg.thinking != "off":
        cmd += ["--reasoning-budget", str(cfg.reasoning_budget)]
    # Thoughts go to reasoning_content, never content, so a reasoning trace
    # can't end up inside the generated C++.
    cmd += ["--reasoning-format", "deepseek"]
    return cmd + split_args(cfg.extra_args)


def model_file(cfg) -> str:
    return os.path.expandvars(os.path.expanduser(cfg.model_path.strip().strip('"')))


# -- finding models -------------------------------------------------------------------

def model_dirs(cfg) -> list:
    """Folders searched for .gguf files: the configured ones, then the common download caches."""
    home = Path.home()
    hf_home = Path(os.environ.get("HF_HOME") or home / ".cache" / "huggingface")
    dirs = [Path(os.path.expandvars(d)).expanduser() for d in cfg.model_dirs if d.strip()]
    dirs += [Path(os.environ.get("HF_HUB_CACHE") or hf_home / "hub"),
             Path(os.environ.get("LLAMA_CACHE") or home / ".cache" / "llama.cpp"),
             home / ".lmstudio" / "models", home / ".cache" / "lm-studio" / "models"]
    out, seen = [], set()
    for d in dirs:
        key = os.path.normcase(str(d))
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def find_models(cfg) -> list:
    """Every servable .gguf in `model_dirs`: skips vision projectors and all but the first part of split models."""
    found, seen = [], set()
    for d in model_dirs(cfg):
        if not d.is_dir():
            continue
        for p in d.rglob("*.gguf"):
            name = p.name.lower()
            m = _SPLIT_PART_RE.search(name)
            if "mmproj" in name or (m and int(m.group(1)) != 1):
                continue
            try:
                key = os.path.normcase(str(p.resolve()))
                size = p.stat().st_size
            except OSError:
                continue
            if key in seen:
                continue
            seen.add(key)
            found.append({"path": str(p), "name": p.name, "repo": _repo_name(p, d), "size": size,
                          "folder": str(d)})
    return sorted(found, key=lambda m: (m["repo"].lower(), m["name"].lower()))


def _repo_name(path: Path, root: Path) -> str:
    """'Org/Repo' for the HuggingFace cache layout (models--Org--Repo/snapshots/...), else the parent folder."""
    for part in path.relative_to(root).parts:
        if part.startswith("models--"):
            return part[len("models--"):].replace("--", "/")
    rel = path.parent.relative_to(root)
    return str(rel).replace("\\", "/") if str(rel) != "." else ""


# -- probing ---------------------------------------------------------------------------

def _health(host: str, port: int, timeout: float = 0.8):
    """'ready' (model loaded), 'loading', 'other' (something else answers), or None (nothing listening)."""
    h = f"[{host}]" if ":" in host else host
    try:
        urllib.request.urlopen(f"http://{h}:{port}/health", timeout=timeout).close()
        return "ready"
    except urllib.error.HTTPError as exc:
        return "loading" if exc.code == 503 else "other"
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log_tail(path, lines: int = 40) -> str:
    if not path or not Path(path).exists():
        return ""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        fh.seek(max(0, fh.tell() - _LOG_TAIL_BYTES))
        text = fh.read().decode("utf-8", errors="replace")
    return "\n".join(text.splitlines()[-lines:])


# -- Windows: the server dies with the backend ---------------------------------------

_job_handle = None


def _tie_to_this_process(proc: subprocess.Popen):
    """Put `proc` in a job object that kills it when this process exits (Windows only; best effort)."""
    global _job_handle
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        k32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
        k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)

        if _job_handle is None:
            class Basic(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                            ("SchedulingClass", wintypes.DWORD)]

            class Extended(ctypes.Structure):
                _fields_ = [("Basic", Basic), ("IoInfo", ctypes.c_uint64 * 6),
                            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

            job = k32.CreateJobObjectW(None, None)
            info = Extended()
            info.Basic.LimitFlags = 0x2000   # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not job or not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
                return                        # 9 = JobObjectExtendedLimitInformation
            _job_handle = job                 # never closed: the OS closes it when we exit
        k32.AssignProcessToJobObject(_job_handle, int(proc._handle))
    except Exception:
        pass   # the atexit stop still covers a normal exit


# -- the server -------------------------------------------------------------------------

class LlamaServer:
    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._command = []
        self._started_at = ""
        self._log_path = None
        self._stopped = False   # stopped on purpose: its exit code (taskkill's 1) isn't a crash
        self._atexit = False

    def _problems(self, s) -> list:
        cfg = s.llamacpp_server
        problems = []
        if endpoint(s.llm.llamacpp.base_url) is None:
            problems.append(f"the llama.cpp base URL ({s.llm.llamacpp.base_url}) isn't on this machine, "
                            "so the backend can't launch a server for it")
        if not find_executable(cfg.executable):
            problems.append(f"`{cfg.executable}` was not found: install llama.cpp, or set the executable to "
                            "the full path of llama.exe / llama-server.exe")
        if not cfg.model_path.strip():
            problems.append("no model file chosen")
        elif not Path(model_file(cfg)).is_file():
            problems.append(f"model file not found: {model_file(cfg)}")
        return problems

    def _command_for(self, s) -> list:
        host, port = endpoint(s.llm.llamacpp.base_url)
        return build_command(find_executable(s.llamacpp_server.executable), s.llamacpp_server, host, port)

    def status(self, s) -> dict:
        ep = endpoint(s.llm.llamacpp.base_url)
        health = _health(*ep) if ep else None
        with self._lock:
            proc, command, started, log_path = self._proc, list(self._command), self._started_at, self._log_path
            stopped = self._stopped
        running = proc is not None and proc.poll() is None
        if running:
            state = "ready" if health == "ready" else "loading"
        elif health in ("ready", "loading"):
            state = "external"
        elif proc is not None and not stopped:
            state = "exited"   # it ended by itself: a crash, or a bad option
        else:
            state = "stopped"

        problems = self._problems(s)
        if health == "other" and not running:
            problems.insert(0, f"port {ep[1]} is in use by another program")
        stale = False
        if running and not problems:
            stale = self._command_for(s) != command
        cfg = s.llamacpp_server
        return {
            "state": state,
            "ready": health == "ready",
            "pid": proc.pid if running else None,
            "exit_code": proc.returncode if state == "exited" else None,
            "started_at": started if proc is not None else "",
            "command": command,
            "stale": stale,   # running, but the settings have changed since it started
            "executable": find_executable(cfg.executable) or "",
            "installed": bool(find_executable(cfg.executable)),
            "model_path": model_file(cfg) if cfg.model_path.strip() else "",
            "model_exists": bool(cfg.model_path.strip()) and Path(model_file(cfg)).is_file(),
            "base_url": s.llm.llamacpp.base_url,
            "auto_start": cfg.auto_start,
            "can_start": not problems and state in ("stopped", "exited"),
            "problem": problems[0] if problems else "",
            "log_tail": _log_tail(log_path),
        }

    def start(self, s, log_path: Path) -> dict:
        problems = self._problems(s)
        if problems:
            raise LlamaServerError(problems[0])
        host, port = endpoint(s.llm.llamacpp.base_url)
        with self._lock:
            if self._proc is None or self._proc.poll() is not None:
                self._launch(s, host, port, Path(log_path))
        return self.status(s)

    def _launch(self, s, host: str, port: int, log_path: Path):
        """Start the process; the caller holds the lock."""
        health = _health(host, port)
        if health is not None:
            raise LlamaServerError(f"something is already listening on port {port}"
                                   + (" (a llama.cpp server started elsewhere)" if health != "other" else ""))
        command = self._command_for(s)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        flags = 0
        if sys.platform == "win32":   # no console window; Ctrl+C in the backend's window doesn't reach it
            flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        with open(log_path, "wb") as log:
            log.write(("> " + subprocess.list2cmdline(command) + "\n\n").encode("utf-8"))
            log.flush()
            try:
                proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                        stderr=subprocess.STDOUT, creationflags=flags)
            except OSError as exc:
                raise LlamaServerError(f"could not launch {command[0]}: {exc}")
        _tie_to_this_process(proc)
        self._proc, self._command, self._started_at, self._log_path = proc, command, _now(), log_path
        self._stopped = False
        if not self._atexit:
            atexit.register(self.stop)
            self._atexit = True

    def stop(self) -> bool:
        """Stop the server this backend started. False if there was none running."""
        with self._lock:
            proc = self._proc
            if proc is None or proc.poll() is not None:
                return False
            self._stopped = True
            if sys.platform == "win32":
                # /T: `llama serve` may run the actual server as a child process.
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                proc.terminate()
            try:
                proc.wait(15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
            return True

    # -- used by runs -------------------------------------------------------------------

    def launch_if_needed(self, s, log_path: Path) -> bool:
        """
        Make sure a server is up or on its way: True if this call launched one.
        Raises LlamaServerError if none is up and auto-start is off or impossible.
        """
        if self.status(s)["state"] in ("ready", "loading", "external"):
            return False
        problem = self.run_problem(s)
        if problem:
            raise LlamaServerError(problem)
        self.start(s, log_path)
        return True

    def run_problem(self, s) -> str:
        """Why a run using llama.cpp couldn't get a server right now, or '' if it can."""
        st = self.status(s)
        if st["state"] in ("ready", "loading", "external"):
            return ""
        if not s.llamacpp_server.auto_start:
            return (f"no llama.cpp server is answering at {s.llm.llamacpp.base_url}; start it on the Local model "
                    "page, or turn on its automatic start")
        return f"llama.cpp can't be started: {st['problem']}" if st["problem"] else ""

    def wait_ready(self, s, cancelled=lambda: False, poll: float = 1.0):
        """Block until the model has loaded. Raises LlamaServerError if the server exits or the timeout passes."""
        deadline = time.monotonic() + s.llamacpp_server.load_timeout_seconds
        while True:
            st = self.status(s)
            if st["ready"]:
                return
            if st["state"] in ("exited", "stopped"):
                tail = "\n".join(st["log_tail"].splitlines()[-8:])
                code = f" with code {st['exit_code']}" if st["exit_code"] is not None else ""
                raise LlamaServerError(f"the llama.cpp server stopped{code} before the model loaded"
                                       + (f":\n{tail}" if tail else ""))
            if time.monotonic() > deadline:
                raise LlamaServerError(f"the model didn't load within {s.llamacpp_server.load_timeout_seconds}s "
                                       "(raise llama.cpp server > load timeout)")
            if cancelled():
                return
            time.sleep(poll)


SERVER = LlamaServer()


def log_path_for(s) -> Path:
    return s.path(s.workspace_dir) / "_llamacpp" / "server.log"


def run_needs_server(s, agents) -> bool:
    return any(s.llm.provider_for(a) == "llamacpp" for a in agents)
