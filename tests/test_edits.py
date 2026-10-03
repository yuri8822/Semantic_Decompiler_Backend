"""Human-in-the-loop edits: overrides layered on LLM output, through the API and a pipeline run."""

import json
import time

import pytest
from fastapi.testclient import TestClient

import settings as settings_mod
from api.app import create_app
from api.jobs import JobManager
from knowledge.filters import exclusion_reason
from knowledge.models import FieldDef, FunctionAnalysis, FunctionRecord, GlobalRecord, TypeRecord
from knowledge.overrides import materialize_function, materialize_type, set_llm_analysis, set_llm_type
from knowledge.signatures import assign_signatures
from pipeline import Pipeline
from tests.conftest import FIXTURE
from tests.fakes import FakeLLM, FakeRunner


def _rec(analysis=None):
    return FunctionRecord(address="0x140002a10", ghidra_name="Move", full_name="Rook::Move",
                          analysis=analysis)


def test_overrides_survive_reanalysis_and_clear_restores_llm():
    llm1 = FunctionAnalysis(name="Rook::Move", name_confidence=0.9, class_name="Rook", method_kind="method",
                            return_type="bool", return_confidence=0.7,
                            params=[{"index": 1, "name": "col", "type": "int", "confidence": 0.8}])
    rec = _rec(llm1)                      # legacy shape: analysis only
    materialize_function(rec)             # adopts it as the LLM's analysis (what the edit API does first)
    rec.overrides = {"name": "TryMove", "params": {"1": {"name": "fromCol"}}, "return_type": "int"}
    materialize_function(rec)
    a = rec.analysis
    assert a.name == "Rook::TryMove" and a.name_confidence == 1.0       # bare name keeps the class
    assert a.return_type == "int" and a.return_confidence == 1.0
    assert next(p for p in a.params if p.index == 1).name == "fromCol"
    assert rec.llm_analysis.name == "Rook::Move"                         # the LLM's view is kept

    llm2 = llm1.model_copy(update={"summary": "round 2", "return_type": "void"})
    set_llm_analysis(rec, llm2)                                         # re-analysis
    assert rec.analysis.name == "Rook::TryMove" and rec.analysis.return_type == "int"
    assert rec.analysis.summary == "round 2"

    rec.overrides = {}
    materialize_function(rec)
    assert rec.analysis.name == "Rook::Move" and rec.analysis.return_type == "void"


def test_type_overrides_win_over_llm_fields_and_survive_reconstruction():
    t = TypeRecord(name="Piece", size=0x18, confidence=0.5, fields=[
        FieldDef(offset=0x10, size=1, name="field_0x10", type="bool", confidence=0.55),
        FieldDef(offset=0x14, size=4, name="field_0x14", type="int", confidence=0.6)])
    t.overrides = {"fields": {"20": {"name": "team"}, "16": {"remove": True}, "8": {"name": "x", "type": "int"}}}
    materialize_type(t)
    by_off = {f.offset: f for f in t.fields}
    assert by_off[0x14].name == "team" and by_off[0x14].type == "int" and by_off[0x14].confidence == 1.0
    assert 0x10 not in by_off and by_off[8].size == 4
    assert t.confidence >= 0.9                                           # a corrected layout is applied

    fresh = TypeRecord(name="Piece", size=0x18, confidence=0.7,
                       fields=[FieldDef(offset=0x14, size=4, name="value", type="int", confidence=0.8)])
    set_llm_type(fresh, existing=t)
    assert {f.offset: f.name for f in fresh.fields} == {8: "x", 0x14: "team"}


def test_user_rename_beats_a_symbol_name(chess_ir, kb):
    for fn in chess_ir.functions:
        kb.save_function(FunctionRecord(address=fn.address, ghidra_name=fn.name, full_name=fn.full_name,
                                        excluded=exclusion_reason(fn)))
    move = next(f for f in chess_ir.functions if f.full_name == "Rook::Move")
    rec = kb.functions[move.address]
    rec.overrides = {"name": "Rook::TryMove"}
    materialize_function(rec)
    assert assign_signatures(kb, chess_ir)[move.address].qualified == "Rook::TryMove"


# -- API ------------------------------------------------------------------------------

@pytest.fixture
def edit_api(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps({"workspace_dir": str(tmp_path / "ws"), "compiler": {"enabled": False},
                                         "analysis": {"rounds": 1}}))
    binary = tmp_path / "Chess.exe"
    binary.write_bytes(b"MZ")
    runner = FakeRunner(FIXTURE)

    def factory(job, s):
        return Pipeline(job.binary, s, restart=job.restart, on_event=job.add_event, llm=FakeLLM(), runner=runner)

    jobs = JobManager(tmp_path / "ws" / "_jobs", pipeline_factory=factory,
                      defaults_loader=lambda: settings_mod.load(settings_file))
    client = TestClient(create_app(jobs=jobs, settings_file=settings_file))
    job = client.post("/api/jobs", json={"binary": str(binary), "settings": {"scope": {"limit": 8}}}).json()
    _wait(client, job["id"])
    return client, runner


def _wait(client, job_id):
    for _ in range(300):
        j = client.get(f"/api/jobs/{job_id}").json()
        if j["status"] not in ("queued", "running"):
            return j
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_edit_function_via_api_then_apply(edit_api):
    client, runner = edit_api
    fns = client.get("/api/workspaces/Chess/functions").json()
    move = next(f for f in fns if f["ghidra_name"] == "Rook::Move")
    addr = move["address"]

    r = client.patch(f"/api/workspaces/Chess/functions/{addr}",
                     json={"name": "Rook::TryMove", "return_type": "bool", "params": [{"index": 1, "name": "fromCol"}]})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["signature"]["definition"].startswith("bool Rook::TryMove(int fromCol")
    assert d["record"]["overrides"]["name"] == "Rook::TryMove"
    assert d["record"]["llm_analysis"]["name"] == "Rook::Move"
    summary = client.get("/api/workspaces/Chess").json()
    assert summary["edits_pending"] is True and summary["overrides"]["functions"] == 1
    assert next(f for f in client.get("/api/workspaces/Chess/functions").json() if f["address"] == addr)["edited"]

    # Invalid edits are rejected with a reason.
    assert client.patch(f"/api/workspaces/Chess/functions/{addr}", json={"name": "not valid!"}).status_code == 422
    assert client.patch(f"/api/workspaces/Chess/functions/{addr}",
                        json={"params": [{"index": 9, "name": "x"}]}).status_code == 400
    assert client.patch(f"/api/workspaces/Chess/functions/{addr}", json={"bogus": 1}).status_code == 422

    # Apply: a resume run pushes the rename to Ghidra and regenerates the code.
    plans_before = len(runner.plans)
    job = client.post("/api/workspaces/Chess/apply", json={}).json()
    assert _wait(client, job["id"])["status"] == "done"
    plan = runner.plans[-1]
    assert len(runner.plans) > plans_before
    entry = next(e for e in plan["functions"] if e["address"] == addr)
    assert entry["name"] == "TryMove" and entry["namespace"] == "Rook"
    after = client.get(f"/api/workspaces/Chess/functions/{addr}").json()
    assert after["record"]["cpp"].startswith("bool Rook::TryMove(")
    assert client.get("/api/workspaces/Chess").json()["edits_pending"] is False

    # Null clears an override; DELETE clears them all.
    d = client.patch(f"/api/workspaces/Chess/functions/{addr}", json={"return_type": None}).json()
    assert "return_type" not in d["record"]["overrides"]
    d = client.delete(f"/api/workspaces/Chess/functions/{addr}/overrides").json()
    assert d["record"]["overrides"] == {} and d["signature"]["name"] == "Move"


def test_edit_type_and_global_via_api(edit_api):
    client, _ = edit_api
    types = client.get("/api/workspaces/Chess/types").json()
    name = types[0]["name"]
    t = client.patch(f"/api/workspaces/Chess/types/{name}",
                     json={"fields": [{"offset": "0x14", "name": "team", "type": "int"}]})
    assert t.status_code == 200, t.text
    f14 = next(f for f in t.json()["fields"] if f["offset"] == 0x14)
    assert f14["name"] == "team" and f14["confidence"] == 1.0
    assert client.patch(f"/api/workspaces/Chess/types/{name}", json={"base_class": name}).status_code == 400
    assert client.patch(f"/api/workspaces/Chess/types/{name}",
                        json={"fields": [{"offset": 0x400, "type": "int"}]}).status_code == 400   # new field, no name
    cleared = client.delete(f"/api/workspaces/Chess/types/{name}/overrides").json()
    assert all(f["confidence"] < 1.0 for f in cleared["fields"])

    globals_ = client.get("/api/workspaces/Chess/globals").json()
    if globals_:
        g = client.patch(f"/api/workspaces/Chess/globals/{globals_[0]['address']}", json={"name": "g_board"}).json()
        assert g["name"] == "g_board" and g["confidence"] == 1.0


def test_edits_refused_while_a_job_runs(edit_api):
    client, _ = edit_api
    import threading
    gate, release = threading.Event(), threading.Event()

    class SlowLLM(FakeLLM):
        def complete_json(self, *a, **k):
            gate.set()
            release.wait(10)
            return super().complete_json(*a, **k)

    jobs = client.app.state.jobs
    jobs.pipeline_factory = lambda job, s: Pipeline(job.binary, s, on_event=job.add_event, llm=SlowLLM(),
                                                    runner=FakeRunner(FIXTURE))
    fns = client.get("/api/workspaces/Chess/functions").json()
    addr = next(f["address"] for f in fns if f["tier"])
    reset = client.post(f"/api/workspaces/Chess/functions/{addr}/reset", json={"analysis": True}).json()
    assert reset["record"]["analysis"] is None and reset["record"]["cpp"] == ""
    job = client.post("/api/workspaces/Chess/apply", json={}).json()
    assert gate.wait(10)
    assert client.patch(f"/api/workspaces/Chess/functions/{addr}", json={"summary": "x"}).status_code == 409
    release.set()
    _wait(client, job["id"])
