"""HTTP API tests: real FastAPI app and job queue, fake LLM and Ghidra, isolated settings and workspace."""

import json
import time

import pytest
from fastapi.testclient import TestClient

import settings as settings_mod
from api.app import create_app
from api.jobs import JobManager
from pipeline import Pipeline
from tests.conftest import FIXTURE
from tests.fakes import FakeLLM, FakeRunner


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps({"workspace_dir": str(tmp_path / "ws"),
                                         "compiler": {"enabled": False}}))
    binary = tmp_path / "Chess.exe"
    binary.write_bytes(b"MZ")

    def factory(job, s):
        return Pipeline(job.binary, s, restart=job.restart, on_event=job.add_event,
                        llm=FakeLLM(), runner=FakeRunner(FIXTURE))

    jobs = JobManager(tmp_path / "ws" / "_jobs", pipeline_factory=factory,
                      defaults_loader=lambda: settings_mod.load(settings_file))
    client = TestClient(create_app(jobs=jobs, settings_file=settings_file))
    return client, binary, settings_file


def wait_for(client, job_id, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] not in ("queued", "running"):
            return job
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def test_settings_endpoints(api):
    client, _, settings_file = api
    schema = client.get("/api/settings/schema").json()
    assert "llm" in schema["properties"] and "$defs" in schema
    assert client.get("/api/settings").json()["compiler"]["enabled"] is False

    r = client.patch("/api/settings", json={"analysis": {"rounds": 3}, "llm": {"concurrency": 2}})
    assert r.status_code == 200 and r.json()["analysis"]["rounds"] == 3
    saved = json.loads(settings_file.read_text())
    assert saved["analysis"] == {"rounds": 3} and "ghidra" not in saved   # only differences are stored

    bad = client.patch("/api/settings", json={"confidence": {"medium": 0.9, "high": 0.8}})
    assert bad.status_code == 422
    assert client.patch("/api/settings", json={"llm": {"concurrency": 0}}).status_code == 422
    assert client.patch("/api/settings", json={"llm": {"nonsense": 1}}).status_code == 422

    preview = client.post("/api/settings/resolve", json={"scope": {"limit": 5}}).json()
    assert preview["scope"]["limit"] == 5 and preview["analysis"]["rounds"] == 3
    assert client.get("/api/settings").json()["scope"]["limit"] == 0      # preview didn't save


def test_health(api):
    client, _, _ = api
    h = client.get("/api/health").json()
    assert h["ok"] and {p["name"] for p in h["providers"]} >= {"deepseek", "anthropic"}
    assert next(p for p in h["providers"] if p["name"] == "deepseek")["api_key_present"] is True


def test_providers(api, monkeypatch):
    client, _, _ = api
    monkeypatch.delenv("XIAOMI_API_KEY", raising=False)
    monkeypatch.setattr("api.app._reachable", lambda url, timeout=0.8: "11434" in url)   # ollama up, llama.cpp down
    client.patch("/api/settings", json={"llm": {"llamacpp": {"base_url": "http://localhost:1/v1"}}})
    r = client.get("/api/providers").json()
    by = {p["name"]: p for p in r["providers"]}
    assert r["default"] == "deepseek" and set(r["agents"]) == {"analyzer", "type_reconstructor", "code_reconstructor"}
    assert by["deepseek"]["usable"] and by["deepseek"]["model"] and by["deepseek"]["label"] == "DeepSeek"
    assert not by["xiaomi"]["usable"] and "XIAOMI_API_KEY" in by["xiaomi"]["problem"]
    assert by["ollama"]["local"] and by["ollama"]["usable"]
    assert not by["llamacpp"]["usable"] and "no model file chosen" in by["llamacpp"]["problem"]
    assert by["anthropic"]["model"].startswith("claude-")


def test_job_lifecycle_and_workspace_views(api):
    client, binary, _ = api
    r = client.post("/api/jobs", json={"binary": str(binary),
                                       "settings": {"analysis": {"rounds": 1}, "scope": {"limit": 6}}})
    assert r.status_code == 201, r.text
    job_id = r.json()["id"]

    # The SSE stream replays from the start and ends once the job finishes.
    with client.stream("GET", f"/api/jobs/{job_id}/events") as stream:
        events = []
        for line in stream.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
                if events[-1]["type"] == "stream_end":
                    break
    assert events[0]["type"] == "run_started" and events[-1] == {"type": "stream_end", "status": "done"}
    assert [e["seq"] for e in events[:-1]] == list(range(len(events) - 1))

    job = wait_for(client, job_id)
    assert job["status"] == "done" and job["summary"]["functions"] == 6
    page = client.get(f"/api/jobs/{job_id}/events/list", params={"after": 2, "limit": 3, "types": "stage"}).json()
    assert page and all(e["type"] == "stage" and e["seq"] >= 2 for e in page)

    workspaces = client.get("/api/workspaces").json()
    assert [w["name"] for w in workspaces] == ["Chess"]
    assert workspaces[0]["counts"]["analyzed"] == 6
    assert workspaces[0]["binary"] == str(binary.resolve()) and workspaces[0]["binary_found"] is True

    functions = client.get("/api/workspaces/Chess/functions").json()
    analyzed = [f for f in functions if f["tier"]]
    assert len(analyzed) == 6 and all(f["has_code"] for f in analyzed)
    detail = client.get(f"/api/workspaces/Chess/functions/{analyzed[0]['address'].upper().replace('X', 'x')}").json()
    assert detail["record"]["analysis"] and detail["signature"]["definition"]
    assert detail["ghidra"]["decompiled"] and "callers" in detail
    assert client.get("/api/workspaces/Chess/functions/0xdeadbeef").status_code == 404

    types = client.get("/api/workspaces/Chess/types").json()
    if types:
        t = client.get(f"/api/workspaces/Chess/types/{types[0]['name']}").json()
        assert "fields" in t and "methods" in t
    assert isinstance(client.get("/api/workspaces/Chess/globals").json(), list)
    assert client.get("/api/workspaces/Chess/relationships/calls").status_code == 200
    assert client.get("/api/workspaces/Chess/relationships/bogus").status_code == 404
    assert client.get("/api/workspaces/Chess/rounds").json()[0]["round"] == 0
    assert client.get("/api/workspaces/Chess/rounds/1/plan").json()["functions"] is not None

    files = {f["path"] for f in client.get("/api/workspaces/Chess/files").json()}
    assert {"CMakeLists.txt", "include/types.h"} <= files
    assert "pragma once" in client.get("/api/workspaces/Chess/files/include/types.h").text
    assert client.get("/api/workspaces/Chess/files/../../settings.json").status_code == 404
    assert "Reconstruction report" in client.get("/api/workspaces/Chess/report").text
    assert client.get("/api/workspaces/..%2F..").status_code == 404

    assert client.delete("/api/workspaces/Chess").status_code == 204
    assert client.get("/api/workspaces").json() == []


def test_job_validation(api, monkeypatch):
    client, binary, _ = api
    assert client.post("/api/jobs", json={"binary": "nope.exe"}).status_code == 400
    bad = client.post("/api/jobs", json={"binary": str(binary), "settings": {"analysis": {"rounds": 0}}})
    assert bad.status_code == 422
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    r = client.post("/api/jobs", json={"binary": str(binary),
                                       "settings": {"llm": {"code_reconstructor_provider": "anthropic"}}})
    assert r.status_code == 400 and "ANTHROPIC_API_KEY" in r.json()["detail"]
    assert client.get("/api/jobs/missing").status_code == 404


def test_cancel_running_job(api, tmp_path):
    client, binary, _ = api
    import threading
    started = threading.Event()
    release = threading.Event()

    class SlowLLM(FakeLLM):
        def complete_json(self, *a, **k):
            started.set()
            release.wait(10)
            return super().complete_json(*a, **k)

    jobs = client.app.state.jobs
    jobs.pipeline_factory = lambda job, s: Pipeline(job.binary, s, on_event=job.add_event, llm=SlowLLM(),
                                                    runner=FakeRunner(FIXTURE))
    job_id = client.post("/api/jobs", json={"binary": str(binary), "settings": {"llm": {"concurrency": 1}}}).json()["id"]
    assert started.wait(10)
    # A second job for the same workspace is refused while this one runs.
    assert client.post("/api/jobs", json={"binary": str(binary)}).status_code == 400
    assert client.post(f"/api/jobs/{job_id}/cancel").status_code == 200
    release.set()
    job = wait_for(client, job_id)
    assert job["status"] == "cancelled"
    assert client.get(f"/api/jobs/{job_id}", params={"events": True}).json()["events"][-1]["status"] == "cancelled"
