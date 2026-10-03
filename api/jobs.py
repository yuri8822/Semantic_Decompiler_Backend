"""
Job queue for pipeline runs.

Jobs run one at a time on a background thread: Ghidra locks its project, so
two runs can't share it. Every job's metadata and event stream are persisted
under <workspace root>/_jobs/, so history (and live streams) survive a
server restart; a job that was running when the server stopped is marked
"interrupted" and can simply be resubmitted (the pipeline resumes).
"""

import json
import queue
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import settings as settings_mod
from llm.providers import missing_api_key
from pipeline import AGENTS, Cancelled, Pipeline

QUEUED, RUNNING, DONE, FAILED, CANCELLED, INTERRUPTED = (
    "queued", "running", "done", "failed", "cancelled", "interrupted")
FINISHED = (DONE, FAILED, CANCELLED, INTERRUPTED)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Job:
    def __init__(self, id: str, binary: str, restart: bool, overrides: dict, settings: dict, jobs_dir: Path):
        self.id = id
        self.binary = binary
        self.workspace = Path(binary).stem
        self.restart = restart
        self.overrides = overrides
        self.settings = settings
        self.status = QUEUED
        self.created_at = _now()
        self.started_at = ""
        self.finished_at = ""
        self.summary = {}
        self.error = ""
        self.events = []
        self.pipeline = None
        self._jobs_dir = jobs_dir
        self._cond = threading.Condition()

    # -- persistence --------------------------------------------------------------

    @property
    def meta_path(self) -> Path:
        return self._jobs_dir / f"{self.id}.json"

    @property
    def events_path(self) -> Path:
        return self._jobs_dir / f"{self.id}.events.jsonl"

    def to_dict(self, events: bool = False) -> dict:
        d = {k: getattr(self, k) for k in ("id", "binary", "workspace", "restart", "overrides", "status",
                                           "created_at", "started_at", "finished_at", "summary", "error")}
        d["event_count"] = len(self.events)
        d["progress"] = self.progress()
        if events:
            d["events"] = self.events
        return d

    def save(self):
        self._jobs_dir.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        data["settings"] = self.settings
        tmp = self.meta_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.meta_path)

    @classmethod
    def load(cls, meta_path: Path) -> "Job":
        d = json.loads(meta_path.read_text(encoding="utf-8"))
        job = cls(d["id"], d["binary"], d.get("restart", False), d.get("overrides", {}), d.get("settings", {}),
                  meta_path.parent)
        for k in ("status", "created_at", "started_at", "finished_at", "summary", "error"):
            setattr(job, k, d.get(k, getattr(job, k)))
        if job.events_path.exists():
            with open(job.events_path, encoding="utf-8") as fh:
                job.events = [json.loads(line) for line in fh if line.strip()]
        return job

    # -- events ---------------------------------------------------------------------

    def add_event(self, event: dict):
        with self._cond:
            event = {"seq": len(self.events), **event}
            self.events.append(event)
            with open(self.events_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event) + "\n")
            self._cond.notify_all()

    def wait_events(self, after: int, timeout: float = 15.0) -> list:
        """Events with seq >= after; blocks up to `timeout` for new ones while the job is live."""
        with self._cond:
            if len(self.events) <= after and self.status not in FINISHED:
                self._cond.wait(timeout)
            return self.events[after:]

    def notify(self):
        with self._cond:
            self._cond.notify_all()

    def progress(self) -> dict:
        """Latest stage and progress counters, for list views."""
        stage, prog = {}, {}
        for e in reversed(self.events):
            if not prog and e["type"] == "progress":
                prog = {"stage": e["stage"], "round": e["round"], "done": e["done"], "total": e["total"]}
            if e["type"] == "stage":
                stage = {"stage": e["stage"], "round": e["round"], "title": e["title"]}
                break
        if prog and stage and (prog["stage"], prog["round"]) != (stage["stage"], stage["round"]):
            prog = {}
        return {**stage, **({"done": prog["done"], "total": prog["total"]} if prog else {})}


class JobManager:
    def __init__(self, jobs_dir: Path, pipeline_factory=None, defaults_loader=settings_mod.load):
        self.jobs_dir = Path(jobs_dir)
        self.defaults_loader = defaults_loader   # saved defaults that per-run overrides apply to
        self.jobs: dict[str, Job] = {}
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._lock = threading.Lock()
        # Overridable for tests: (job, settings) -> Pipeline
        self.pipeline_factory = pipeline_factory or (
            lambda job, s: Pipeline(job.binary, s, restart=job.restart, on_event=job.add_event))
        self._load()
        self._worker = threading.Thread(target=self._work, name="semdec-jobs", daemon=True)
        self._worker.start()

    def _load(self):
        if not self.jobs_dir.exists():
            return
        for meta in sorted(self.jobs_dir.glob("*.json")):
            try:
                job = Job.load(meta)
            except (OSError, ValueError, KeyError):
                continue
            if job.status in (QUEUED, RUNNING):
                job.status, job.finished_at = INTERRUPTED, job.finished_at or _now()
                job.error = job.error or "the server stopped before this job finished; resubmit to resume"
                job.save()
            self.jobs[job.id] = job

    # -- public API -------------------------------------------------------------------

    def submit(self, binary: str, overrides: dict, restart: bool) -> Job:
        """Validate and queue a run. Raises ValueError on bad input."""
        path = Path(binary).expanduser()
        if not path.is_file():
            raise ValueError(f"binary not found: {binary}")
        run_settings = self.defaults_loader().with_overrides(overrides or {})   # ValueError if invalid
        providers = {run_settings.llm.provider_for(agent) for agent in AGENTS}
        missing = sorted(f"{missing_api_key(p)} (for {p})" for p in providers if missing_api_key(p))
        if missing:
            raise ValueError("missing API key(s): " + ", ".join(missing) + " — add them to .env")
        job = Job(uuid.uuid4().hex[:12], str(path.resolve()), restart, overrides or {},
                  run_settings.model_dump(), self.jobs_dir)
        with self._lock:
            busy = [j for j in self.jobs.values() if j.workspace == job.workspace and j.status in (QUEUED, RUNNING)]
            if busy:
                raise ValueError(f"workspace '{job.workspace}' already has a {busy[0].status} job ({busy[0].id})")
            self.jobs[job.id] = job
            job.save()
        self._queue.put(job.id)
        return job

    def cancel(self, job_id: str) -> Job:
        job = self.jobs[job_id]
        if job.status == QUEUED:
            job.status, job.finished_at = CANCELLED, _now()
            job.save()
            job.notify()
        elif job.status == RUNNING and job.pipeline is not None:
            job.pipeline.cancel()
        return job

    def list(self) -> list:
        return sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True)

    def workspace_busy(self, name: str) -> bool:
        return any(j.workspace == name and j.status in (QUEUED, RUNNING) for j in self.jobs.values())

    # -- worker ------------------------------------------------------------------------

    def _work(self):
        while True:
            job = self.jobs.get(self._queue.get())
            if job is None or job.status != QUEUED:
                continue
            self._run(job)

    def _run(self, job: Job):
        job.status, job.started_at = RUNNING, _now()
        job.save()
        try:
            run_settings = settings_mod.Settings.model_validate(job.settings)
            job.pipeline = self.pipeline_factory(job, run_settings)
            job.summary = job.pipeline.run()
            job.status = DONE
        except Cancelled:
            job.status = CANCELLED
        except Exception as exc:  # reported on the job; the worker must keep serving the queue
            job.status, job.error = FAILED, f"{type(exc).__name__}: {exc}"
            if not job.events or job.events[-1]["type"] != "run_finished":
                job.add_event({"type": "run_finished", "time": _now(), "status": "failed",
                               "summary": {}, "error": job.error})
        finally:
            job.pipeline = None
            job.finished_at = _now()
            job.save()
            job.notify()
