"""
HTTP API over the pipeline (localhost). Interactive docs at /docs.

    Settings     GET  /api/settings/schema       JSON Schema of every option (drives a UI form)
                 GET  /api/settings              saved defaults (settings.json over built-ins)
                 GET  /api/settings/defaults     built-in defaults
                 PUT  /api/settings              replace saved defaults (full object)
                 PATCH /api/settings             merge a partial object into saved defaults
                 POST /api/settings/resolve      preview: saved defaults + per-run overrides
    System       GET  /api/health                Ghidra/compiler/CMake availability, API keys present
                 GET  /api/providers             LLM providers: model, usable now (key set / local server up)
    llama.cpp    GET  /api/llamacpp              the local server the backend launches: state, command, log tail
                 POST /api/llamacpp/start        launch it with the saved llamacpp_server settings
                 POST /api/llamacpp/stop         stop it
                 GET  /api/llamacpp/models       .gguf files found in the usual download folders
    Binaries     GET  /api/binaries              executables in binaries/ and TestBinaries/
                 POST /api/binaries              upload an executable into binaries/
    Jobs         POST /api/jobs                  queue a run {binary, restart, settings: {...overrides}}
                 GET  /api/jobs                  all jobs, newest first
                 GET  /api/jobs/{id}             one job (add ?events=true for its event list)
                 POST /api/jobs/{id}/cancel      cancel a queued or running job
                 GET  /api/jobs/{id}/events      live event stream (Server-Sent Events, resumable)
                 GET  /api/jobs/{id}/events/list JSON page of events (?after=N&limit=M)
    Workspaces   GET  /api/workspaces[/{name}]   summaries / detail;  DELETE to remove one
                 GET  .../{name}/functions[/{address}]
                 GET  .../{name}/types[/{class}]  .../globals  .../strings
                 GET  .../{name}/relationships/{calls|field_accesses|this_passing|class_members}
                 GET  .../{name}/rounds  .../rounds/{round}/{plan|report}
                 GET  .../{name}/files[/{path}]   generated C++ project
                 GET  .../{name}/logs[/{file}]    LLM prompts and responses (?address=&agent=)
                 GET  .../{name}/report           report.md
    Edits        PATCH  .../{name}/functions/{address}           override name/class/kind/return/params/locals
                 DELETE .../{name}/functions/{address}/overrides back to the LLM's analysis
                 POST   .../{name}/functions/{address}/reset     redo analysis and/or code on the next run
                 PATCH  .../{name}/types/{class}   DELETE .../types/{class}/overrides
                 PATCH  .../{name}/globals/{address}
                 POST   .../{name}/apply           queue a resume run that applies the edits
                 (absent field = unchanged, value = override, null = clear the override;
                  edits are refused with 409 while a job runs on the workspace)
"""

import json
import os
import re
import shutil
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field, ValidationError

import settings as settings_mod
from api import edits
from api.edits import EditError, FunctionEdit, GlobalEdit, ResetRequest, TypeEdit
from api.jobs import FINISHED, JobManager
from api.workspaces import NotFound, Workspaces
from llm import llamacpp_server
from llm.providers import API_KEY_VARS
from settings import PROJECT_ROOT, PROVIDERS, LLMSettings, Settings

UPLOAD_DIR = PROJECT_ROOT / "binaries"
BINARY_DIRS = (UPLOAD_DIR, PROJECT_ROOT / "TestBinaries")
_UPLOAD_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


class JobRequest(BaseModel):
    binary: str = Field(..., description="Path to the executable (as returned by /api/binaries, or any local path).")
    restart: bool = Field(False, description="Discard this binary's workspace and start over.")
    settings: dict = Field({}, description="Partial settings overriding the saved defaults for this run only.")


def create_app(jobs: JobManager = None, settings_file: Path = settings_mod.SETTINGS_FILE) -> FastAPI:
    """`settings_file` holds the saved defaults (tests point it elsewhere)."""

    def load_saved() -> Settings:
        return settings_mod.load(settings_file)

    def workspace_root() -> Path:
        s = load_saved()
        return s.path(s.workspace_dir)

    app = FastAPI(title="Semantic Decompiler API", version="1.0",
                  description="Ghidra + LLM agents: binary -> readable, compilable C++.")
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?",
        allow_methods=["*"], allow_headers=["*"],
    )
    jobs = jobs or JobManager(workspace_root() / "_jobs", defaults_loader=load_saved)
    ws = Workspaces(workspace_root, binary_dirs=BINARY_DIRS)
    app.state.jobs = jobs

    @app.exception_handler(NotFound)
    async def _not_found(request: Request, exc: NotFound):
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(ValidationError)
    async def _invalid(request: Request, exc: ValidationError):
        return JSONResponse({"detail": json.loads(exc.json())}, status_code=422)

    # -- settings ---------------------------------------------------------------------

    @app.get("/api/settings/schema")
    def settings_schema():
        return Settings.model_json_schema()

    @app.get("/api/settings")
    def get_settings():
        return load_saved().model_dump()

    @app.get("/api/settings/defaults")
    def default_settings():
        return Settings().model_dump()

    @app.put("/api/settings")
    def put_settings(body: dict):
        s = Settings.model_validate(body)
        settings_mod.save(s, settings_file)
        return s.model_dump()

    @app.patch("/api/settings")
    def patch_settings(body: dict):
        s = load_saved().with_overrides(body)
        settings_mod.save(s, settings_file)
        return s.model_dump()

    @app.post("/api/settings/resolve")
    def resolve_settings(body: dict):
        return load_saved().with_overrides(body).model_dump()

    # -- system -------------------------------------------------------------------------

    @app.get("/api/health")
    def health():
        s = load_saved()
        return {
            "ok": True,
            "ghidra": {"headless": s.ghidra.headless, "found": Path(s.ghidra.headless).exists()},
            "compiler": {"cxx": s.compiler.cxx, "found": shutil.which(s.compiler.cxx) is not None},
            "cmake": {"cmake": s.compiler.cmake, "found": shutil.which(s.compiler.cmake) is not None},
            "providers": [{"name": p, "api_key_var": API_KEY_VARS.get(p, ""),
                           "api_key_present": bool(os.environ.get(API_KEY_VARS[p])) if p in API_KEY_VARS else None}
                          for p in PROVIDERS],
            "workspace_root": str(workspace_root()),
            "running_job": next((j.id for j in jobs.jobs.values() if j.status == "running"), None),
        }

    @app.get("/api/providers")
    def providers():
        """Every LLM provider, its model, and whether it can be used right now."""
        s = load_saved()

        def status(p: str) -> dict:
            cfg = getattr(s.llm, p)
            key_var = API_KEY_VARS.get(p, "")
            local = not key_var
            key_present = bool(os.environ.get(key_var)) if key_var else None
            reachable = _reachable(cfg.base_url) if local else None
            model = cfg.model_heavy if p == "anthropic" else cfg.model
            auto_start = False
            if p == "llamacpp":   # the backend can launch it on demand
                problem = "" if reachable else jobs.llama.run_problem(s)
                auto_start = not reachable and not problem
                if s.llamacpp_server.model_path.strip():
                    model = Path(llamacpp_server.model_file(s.llamacpp_server)).name
            elif local:
                problem = "" if reachable else f"no server answering at {cfg.base_url}"
            else:
                problem = "" if key_present else f"{key_var} is not set in the backend's .env"
            return {
                "name": p,
                "label": LLMSettings.model_fields[p].title or p,
                "model": model,
                "local": local,
                "api_key_var": key_var,
                "api_key_present": key_present,
                "reachable": reachable,
                "auto_start": auto_start,   # not running, but starts when a run needs it
                "usable": not problem,
                "problem": problem,
            }

        with ThreadPoolExecutor(len(PROVIDERS)) as pool:   # local probes run concurrently
            items = list(pool.map(status, PROVIDERS))
        return {
            "default": s.llm.provider,
            "agents": {a: getattr(s.llm, f"{a}_provider") for a in ("analyzer", "type_reconstructor",
                                                                   "code_reconstructor")},
            "providers": items,
        }

    # -- local llama.cpp server -------------------------------------------------------

    @app.get("/api/llamacpp")
    def llamacpp_status():
        return jobs.llama.status(load_saved())

    @app.post("/api/llamacpp/start")
    def llamacpp_start():
        s = load_saved()
        try:
            return jobs.llama.start(s, llamacpp_server.log_path_for(s))
        except llamacpp_server.LlamaServerError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/llamacpp/stop")
    def llamacpp_stop():
        jobs.llama.stop()
        return jobs.llama.status(load_saved())

    @app.get("/api/llamacpp/models")
    def llamacpp_models():
        cfg = load_saved().llamacpp_server
        return {"models": llamacpp_server.find_models(cfg),
                "searched": [str(d) for d in llamacpp_server.model_dirs(cfg)]}

    # -- binaries -----------------------------------------------------------------------

    @app.get("/api/binaries")
    def list_binaries():
        names = {w["name"] for w in ws.list()}
        out = []
        for d in BINARY_DIRS:
            if d.exists():
                for p in sorted(d.iterdir()):
                    if p.is_file():
                        out.append({"path": str(p), "name": p.name, "size": p.stat().st_size,
                                    "folder": d.name, "workspace": p.stem if p.stem in names else None})
        return out

    @app.post("/api/binaries", status_code=201)
    def upload_binary(file: UploadFile = File(...)):
        name = _UPLOAD_NAME_RE.sub("_", Path(file.filename or "upload.bin").name)
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        dest = UPLOAD_DIR / name
        with open(dest, "wb") as fh:
            shutil.copyfileobj(file.file, fh)
        return {"path": str(dest), "name": name, "size": dest.stat().st_size}

    # -- jobs -----------------------------------------------------------------------------

    @app.post("/api/jobs", status_code=201)
    def submit_job(req: JobRequest):
        try:
            job = jobs.submit(req.binary, req.settings, req.restart)
        except ValidationError:
            raise
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return job.to_dict()

    @app.get("/api/jobs")
    def list_jobs():
        return [j.to_dict() for j in jobs.list()]

    def _job(job_id: str):
        job = jobs.jobs.get(job_id)
        if job is None:
            raise NotFound(f"no job {job_id!r}")
        return job

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str, events: bool = False):
        job = _job(job_id)
        d = job.to_dict(events=events)
        d["settings"] = job.settings
        return d

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_job(job_id: str):
        _job(job_id)
        return jobs.cancel(job_id).to_dict()

    @app.get("/api/jobs/{job_id}/events/list")
    def job_events(job_id: str, after: int = Query(0, ge=0), limit: int = Query(1000, ge=1, le=100000),
                   types: Optional[str] = Query(None, description="comma-separated event types to keep")):
        job = _job(job_id)
        events = job.events[after:]
        if types:
            keep = set(types.split(","))
            events = [e for e in events if e["type"] in keep]
        return events[:limit]

    @app.get("/api/jobs/{job_id}/events")
    def stream_events(job_id: str, request: Request, after: int = Query(0, ge=0)):
        """
        Server-Sent Events. Each message's data is one event (JSON, with `seq` and
        `type`); the stream ends with {"type": "stream_end"} once the job has
        finished. Reconnecting with Last-Event-ID (EventSource does this
        automatically) or ?after=N resumes without gaps or repeats.
        """
        job = _job(job_id)
        last_id = request.headers.get("last-event-id")
        start = int(last_id) + 1 if last_id and last_id.isdigit() else after

        def gen():
            seq = start
            yield "retry: 3000\n\n"
            while True:
                batch = job.wait_events(seq)
                for e in batch:
                    yield f"id: {e['seq']}\ndata: {json.dumps(e)}\n\n"
                    seq = e["seq"] + 1
                if job.status in FINISHED and seq >= len(job.events):
                    yield f"data: {json.dumps({'type': 'stream_end', 'status': job.status})}\n\n"
                    return
                if not batch:
                    yield ": keep-alive\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # -- workspaces -----------------------------------------------------------------------

    @app.get("/api/workspaces")
    def list_workspaces():
        return ws.list()

    @app.get("/api/workspaces/{name}")
    def get_workspace(name: str):
        return ws.detail(name)

    @app.delete("/api/workspaces/{name}", status_code=204)
    def delete_workspace(name: str):
        ws.path(name)
        if jobs.workspace_busy(name):
            raise HTTPException(409, f"workspace '{name}' has a queued or running job")
        ws.delete(name)

    @app.get("/api/workspaces/{name}/functions")
    def list_functions(name: str):
        return ws.functions(name)

    @app.get("/api/workspaces/{name}/functions/{address}")
    def get_function(name: str, address: str):
        return ws.function(name, address)

    @app.get("/api/workspaces/{name}/types")
    def list_types(name: str):
        return ws.types(name)

    @app.get("/api/workspaces/{name}/types/{type_name}")
    def get_type(name: str, type_name: str):
        return ws.type(name, type_name)

    @app.get("/api/workspaces/{name}/globals")
    def list_globals(name: str):
        return ws.globals(name)

    @app.get("/api/workspaces/{name}/strings")
    def list_strings(name: str):
        return ws.strings(name)

    @app.get("/api/workspaces/{name}/relationships/{kind}")
    def relationships(name: str, kind: str):
        return ws.relationships(name, kind)

    @app.get("/api/workspaces/{name}/rounds")
    def rounds(name: str):
        return ws.rounds(name)

    @app.get("/api/workspaces/{name}/rounds/{round_num}/{kind}")
    def round_file(name: str, round_num: int, kind: str):
        return ws.round_file(name, kind, round_num)

    @app.get("/api/workspaces/{name}/files")
    def project_files(name: str):
        return ws.files(name)

    @app.get("/api/workspaces/{name}/files/{path:path}", response_class=PlainTextResponse)
    def project_file(name: str, path: str):
        return ws.file(name, path)

    @app.get("/api/workspaces/{name}/logs")
    def logs(name: str, address: str = "", agent: str = ""):
        return ws.logs(name, address, agent)

    @app.get("/api/workspaces/{name}/logs/{log_name}")
    def log(name: str, log_name: str):
        return ws.log(name, log_name)

    @app.get("/api/workspaces/{name}/report", response_class=PlainTextResponse)
    def report(name: str):
        return ws.report(name)

    # -- edits (human in the loop) -----------------------------------------------

    def _writable_kb(name: str):
        ws.path(name)
        if jobs.workspace_busy(name):
            raise HTTPException(409, f"workspace '{name}' has a queued or running job; edit it when the job ends")
        return ws.kb(name)

    def _edit(fn):
        try:
            return fn()
        except EditError as exc:
            raise HTTPException(400, str(exc))

    @app.patch("/api/workspaces/{name}/functions/{address}")
    def edit_function(name: str, address: str, body: FunctionEdit):
        kb = _writable_kb(name)
        addr = _norm_address(address)
        _edit(lambda: edits.edit_function(kb, ws.current_ir(kb).get(addr), addr, body))
        return ws.function(name, addr)

    @app.delete("/api/workspaces/{name}/functions/{address}/overrides")
    def clear_function_edits(name: str, address: str):
        kb = _writable_kb(name)
        addr = _norm_address(address)
        _edit(lambda: edits.clear_function_overrides(kb, addr))
        return ws.function(name, addr)

    @app.post("/api/workspaces/{name}/functions/{address}/reset")
    def reset_function(name: str, address: str, body: ResetRequest):
        kb = _writable_kb(name)
        addr = _norm_address(address)
        _edit(lambda: edits.reset_function(kb, addr, body))
        return ws.function(name, addr)

    @app.patch("/api/workspaces/{name}/types/{type_name}")
    def edit_type(name: str, type_name: str, body: TypeEdit):
        kb = _writable_kb(name)
        _edit(lambda: edits.edit_type(kb, type_name, body))
        return ws.type(name, type_name)

    @app.delete("/api/workspaces/{name}/types/{type_name}/overrides")
    def clear_type_edits(name: str, type_name: str):
        kb = _writable_kb(name)
        _edit(lambda: edits.clear_type_overrides(kb, type_name))
        return ws.type(name, type_name)

    @app.patch("/api/workspaces/{name}/globals/{address}")
    def edit_global(name: str, address: str, body: GlobalEdit):
        kb = _writable_kb(name)
        addr = _norm_address(address)
        g = _edit(lambda: edits.edit_global(kb, addr, body))
        return g.model_dump()

    @app.post("/api/workspaces/{name}/apply", status_code=201)
    def apply_edits(name: str, body: dict = None):
        """Queue a resume run for this workspace: applies pending edits and regenerates affected code."""
        binary, found = ws.resolve_binary(ws.kb(name).meta.get("binary", ""))
        if not found:
            raise HTTPException(400, f"the binary for '{name}' was not found ({binary}); upload it first")
        try:
            job = jobs.submit(binary, (body or {}).get("settings", {}), restart=False)
        except ValidationError:
            raise
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return job.to_dict()

    return app


def _reachable(base_url: str, timeout: float = 0.8) -> bool:
    """Does an OpenAI-compatible local server answer at `base_url`? Any HTTP reply counts."""
    try:
        urllib.request.urlopen(base_url.rstrip("/") + "/models", timeout=timeout).close()
        return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _norm_address(address: str) -> str:
    try:
        return f"{int(address, 16):#x}"
    except ValueError:
        raise NotFound(f"invalid address {address!r}")
