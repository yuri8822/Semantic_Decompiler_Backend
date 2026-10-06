"""Recovery from files a power cut left zero-filled (seen for real on 2026-10-03)."""

from api.jobs import Job, _read_events
from knowledge.store import KnowledgeBase
from pipeline import Pipeline
from settings import Settings
from tests.conftest import FIXTURE
from tests.fakes import FakeLLM, FakeRunner


def test_damaged_record_is_skipped_set_aside_and_redone(tmp_path):
    s = Settings().with_overrides({"workspace_dir": str(tmp_path / "ws"), "code": {"enabled": False},
                                   "analysis": {"rounds": 1}})
    Pipeline(tmp_path / "Chess.exe", s, llm=FakeLLM(), runner=FakeRunner(FIXTURE)).run()
    root = tmp_path / "ws" / "Chess"
    victim = root / "functions" / "0x140002a10.json"
    victim.write_bytes(b"\x00" * victim.stat().st_size)          # what the power cut did

    kb = KnowledgeBase.open(root)                                 # loads despite the damage
    assert kb.corrupt == ["functions/0x140002a10.json"] and "0x140002a10" not in kb.functions
    assert len(kb.functions) > 10

    llm, events = FakeLLM(), []
    Pipeline(tmp_path / "Chess.exe", s, llm=llm, runner=FakeRunner(FIXTURE), on_event=events.append).run()
    assert [t for _, t in llm.calls if t.startswith("analyze_")] == ["analyze_r1_0x140002a10"]   # only it is redone
    assert any("moved to _corrupt/" in e.get("text", "") for e in events)
    assert list((root / "_corrupt").rglob("0x140002a10.json"))     # kept for inspection
    kb = KnowledgeBase.open(root)
    assert not kb.corrupt and kb.functions["0x140002a10"].analysis is not None


def test_damaged_event_log_still_loads(tmp_path):
    log = tmp_path / "abc.events.jsonl"
    log.write_bytes(b'{"seq": 0, "type": "stage", "stage": "ghidra"}\n'
                    b'{"seq": 1, "type": "message", "text": "hi"}\n'
                    + b"\x00" * 300 + b'\n{"seq": 7, "type": "message", "text": "after"}\n')
    events = _read_events(log)
    assert [e["type"] for e in events] == ["stage", "message", "message"]
    assert [e["seq"] for e in events] == [0, 1, 2]                  # renumbered to match positions

    meta = tmp_path / "abc.json"
    meta.write_text('{"id": "abc", "binary": "x.exe", "status": "running"}')
    job = Job.load(meta)
    assert len(job.events) == 3
