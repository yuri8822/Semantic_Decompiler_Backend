"""Tests over a real Ghidra export of TestBinaries/Chess.exe (tests/fixtures/chess_subset.json)."""

import shutil

import pytest

from agents.analyzer import ground
from agents.context import Context
from agents.validator import Validator, errors
from knowledge.filters import exclusion_reason
from knowledge.ghidra_plan import build_plan
from knowledge.models import FunctionAnalysis, FunctionRecord, TypeRecord, FieldDef
from knowledge.signatures import assign_signatures, build_signature


def by_name(ir, full_name):
    return [f for f in ir.functions if f.full_name == full_name]


def seed(kb, ir):
    for fn in ir.functions:
        kb.save_function(FunctionRecord(address=fn.address, ghidra_name=fn.name, full_name=fn.full_name,
                                        excluded=exclusion_reason(fn)))


def test_ir_has_pcode_facts(chess_ir):
    piece = by_name(chess_ir, "Piece::Piece")[0]
    assert {(a.offset, a.size, a.access) for a in piece.field_accesses} == {(0, 8, "write"), (16, 1, "write"),
                                                                            (20, 4, "write")}
    engine = by_name(chess_ir, "Engine::Engine")[0]
    assert {p.offset for p in engine.arg_passes} >= {0x38, 0x58}   # embedded std::string members


def test_exclusion_filter(chess_ir):
    reasons = {f.full_name: exclusion_reason(f) for f in chess_ir.functions}
    assert reasons["std::operator<<"] and reasons["operator.new"] and reasons["__main"]
    assert reasons["std::istream::operator>>"]
    assert not reasons["Rook::Move"] and not reasons["main"] and not reasons["Engine::Engine"]
    traits = chess_ir.functions[0].model_copy(update={"name": "eq", "namespace": "char_traits<char>"})
    assert exclusion_reason(traits)


def test_signatures_from_symbols_and_aliases(kb, chess_ir):
    seed(kb, chess_ir)
    sigs = assign_signatures(kb, chess_ir)
    move = sigs[by_name(chess_ir, "Rook::Move")[0].address]
    assert move.definition_head() == "uint64_t Rook::Move(int param_1, int param_2, long long *param_3)"
    ctor = sigs[by_name(chess_ir, "Engine::Engine")[0].address]
    assert ctor.kind == "constructor" and ctor.definition_head() == "Engine::Engine()"
    dtor = sigs[by_name(chess_ir, "Engine::~Engine")[0].address]
    assert dtor.definition_head() == "Engine::~Engine()"
    # The two identical Piece::Piece variants collapse into one plus an alias.
    pieces = by_name(chess_ir, "Piece::Piece")
    assert pieces[0].address in sigs and pieces[1].address not in sigs
    assert kb.functions[pieces[1].address].alias_of == pieces[0].address
    assert sigs[by_name(chess_ir, "main")[0].address].return_type == "int"


def test_analysis_gating_in_signature(kb, chess_ir):
    seed(kb, chess_ir)
    fn = by_name(chess_ir, "Rook::Move")[0]
    rec = kb.functions[fn.address]
    rec.analysis = FunctionAnalysis.model_validate({
        "name": "Rook::TryMove", "name_confidence": 0.99, "class_name": "Rook", "method_kind": "method",
        "return_type": "bool", "return_confidence": 0.7,
        "params": [
            {"index": 0, "name": "this", "role": "this", "confidence": 0.99},
            {"index": 1, "name": "row", "type": "int", "confidence": 0.9},
            {"index": 2, "name": "col", "type": "int", "confidence": 0.7},
            {"index": 3, "name": "board", "type": "Board *", "confidence": 0.3},
        ],
    })
    sig = build_signature(rec, fn)
    # Symbol name kept; HIGH param applied; MEDIUM applied with TODO; LOW not applied.
    assert sig.definition_head() == "bool Rook::Move(int row, int col, long long *param_3)"
    assert any("col" in t for t in sig.todos) and any("bool" in t for t in sig.todos)


def test_grounding_drops_unobserved_claims(chess_ir):
    fn = by_name(chess_ir, "Piece::Piece")[0]
    a = FunctionAnalysis.model_validate({
        "name": "Piece::Piece", "name_confidence": 0.95, "class_name": "Piece", "method_kind": "constructor",
        "params": [{"index": 0, "name": "this", "role": "this", "confidence": 0.9},
                   {"index": 5, "name": "ghost", "confidence": 0.9}],
        "fields": [
            {"param": 0, "offset": "0x10", "name": "isWhite", "type": "bool", "confidence": 0.9},
            {"param": 0, "offset": "0x14", "name": "hasMoved", "type": "bool", "confidence": 0.9},
            {"param": 0, "offset": "0x40", "name": "invented", "type": "int", "confidence": 0.99},
        ],
        "locals": [{"old_name": "nope", "name": "x", "confidence": 0.9}],
    })
    g = ground(a, fn)
    assert [p.index for p in g.params] == [0]
    assert not g.locals
    names = {f.name: f for f in g.fields}
    assert "invented" not in names                     # offset never accessed
    assert names["isWhite"].confidence == 0.9          # 1-byte access matches bool
    assert names["hasMoved"].confidence < 0.6          # 4-byte access contradicts bool


def test_plan_applies_only_accepted_knowledge(kb, chess_ir):
    seed(kb, chess_ir)
    fn = by_name(chess_ir, "Rook::Move")[0]
    rec = kb.functions[fn.address]
    rec.analysis = FunctionAnalysis.model_validate({
        "name": "Rook::Move", "name_confidence": 0.95, "class_name": "Rook", "method_kind": "method",
        "summary": "moves a rook",
        "params": [{"index": 1, "old_name": "param_1", "name": "row", "type": "int", "confidence": 0.9},
                   {"index": 2, "old_name": "param_2", "name": "col", "type": "int", "confidence": 0.7},
                   {"index": 3, "old_name": "param_3", "name": "board", "type": "Board *", "confidence": 0.2}],
        "locals": [{"old_name": "local_24", "name": "dRow", "type": "int", "confidence": 0.9},
                   {"old_name": "local_20", "name": "dCol", "type": "int", "confidence": 0.1}],
    })
    kb.save_function(rec)
    kb.save_type(TypeRecord(name="Piece", size=0x18, confidence=0.9, fields=[
        FieldDef(offset=0x10, size=1, name="isWhite", type="bool", confidence=0.95),
        FieldDef(offset=0x14, size=4, name="moves", type="int", confidence=0.7),
        FieldDef(offset=0x8, size=4, name="guess", type="int", confidence=0.3),
    ]))
    plan = build_plan(kb, chess_ir)
    entry = next(e for e in plan["functions"] if e["address"] == fn.address)
    assert "name" not in entry                                   # symbol name, already correct
    assert [p["name"] for p in entry["params"]] == ["row", "col"]  # LOW 'board' withheld
    assert [l["name"] for l in entry["locals"]] == ["dRow"]
    assert "TODO" in entry["comment"]                            # medium 'col' flagged
    struct = plan["structs"][0]
    assert [f["name"] for f in struct["fields"]] == ["isWhite", "moves"]
    assert "comment" in struct["fields"][1] and "comment" not in struct["fields"][0]


def test_validator_catches_dropped_calls_and_branches(kb, chess_ir):
    seed(kb, chess_ir)
    sigs = assign_signatures(kb, chess_ir)
    ctx = Context(kb, chess_ir, sigs)
    main = by_name(chess_ir, "main")[0]
    sig = sigs[main.address]
    bad = "int main(int _Argc, char **_Argv, char **_Env)\n{\n    return 0;\n}"
    issues = Validator().check(ctx, main, sig, bad)
    assert any(i.check == "calls" and "GameLoop" in i.message for i in errors(issues))
    assert any(i.check == "calls" and "Engine" in i.message for i in errors(issues))
    good = ("int main(int _Argc, char **_Argv, char **_Env)\n{\n    Engine engine;\n"
            "    engine.GameLoop();\n    return 0;\n}")
    assert not errors(Validator().check(ctx, main, sig, good))

    move = by_name(chess_ir, "Rook::Move")[0]
    msig = sigs[move.address]
    flat = msig.definition_head() + "\n{\n    return 0;\n}"
    checks = {i.check for i in errors(Validator().check(ctx, move, msig, flat))}
    assert "branches" in checks
    wrong = "void Rook::Move(int a)\n{\n}"
    checks = {i.check for i in errors(Validator().check(ctx, move, msig, wrong))}
    assert {"parameters", "return_type"} <= checks


def test_validator_accepts_dropped_vtable_store(kb, chess_ir):
    seed(kb, chess_ir)
    kb.save_type(TypeRecord(name="Piece", size=0x18, confidence=0.9, fields=[
        FieldDef(offset=0, size=8, name="vftable", type="void **", confidence=0.95),
        FieldDef(offset=0x10, size=1, name="isWhite", type="bool", confidence=0.9),
        FieldDef(offset=0x14, size=4, name="moves", type="int", confidence=0.9)]))
    sigs = assign_signatures(kb, chess_ir)
    ctx = Context(kb, chess_ir, sigs)
    fn = by_name(chess_ir, "Piece::Piece")[0]
    code = "Piece::Piece()\n{\n    isWhite = false;\n    moves = 0;\n}"
    assert Validator().check(ctx, fn, sigs[fn.address], code) == []


def test_return_value_cross_check(kb, chess_ir):
    """Engine::CheckState is a UD2 trap Ghidra types as void, but GameLoop uses its result as int."""
    from agents.crosscheck import check_return_values, return_value_uses

    seed(kb, chess_ir)
    check_state = by_name(chess_ir, "Engine::CheckState")[0]
    uses = return_value_uses(chess_ir, check_state.address)
    assert len(uses) == 2 and all(u["type"] == "int" for u in uses)   # the third call discards it
    assert return_value_uses(chess_ir, by_name(chess_ir, "Engine::Draw")[0].address) == []

    rec = kb.functions[check_state.address]
    rec.analysis = FunctionAnalysis.model_validate({
        "name": "Engine::CheckState", "name_confidence": 0.98, "class_name": "Engine", "method_kind": "method",
        "return_type": "void", "return_confidence": 0.95})
    kb.save_function(rec)
    assert check_return_values(kb, chess_ir, [check_state.address]) == [check_state.address]
    a = kb.functions[check_state.address].analysis
    assert a.contradictions and a.observed_return_type == "int" and a.return_confidence < 0.6
    sig = build_signature(kb.functions[check_state.address], check_state)
    assert sig.definition_head() == "int Engine::CheckState()" and any("callers" in t for t in sig.todos)
    assert check_return_values(kb, chess_ir, [check_state.address]) == []   # idempotent

    # Re-analysis that answers int clears the contradiction.
    a.return_type, a.return_confidence = "int", 0.9
    check_return_values(kb, chess_ir, [check_state.address])
    assert not kb.functions[check_state.address].analysis.contradictions


def test_empty_llm_answer_is_an_error(tmp_path, monkeypatch):
    import llm.client as client_mod
    from llm.client import LLMClient, LLMError

    class Empty:
        def complete(self, system, user, tier):
            return "   "

    monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)
    with pytest.raises(LLMError):
        LLMClient("deepseek", impl=Empty(), log_dir=tmp_path).complete("s", "u")


@pytest.mark.skipif(shutil.which("g++") is None, reason="g++ not available")
def test_header_layout_offsets_are_exact(kb, chess_ir, tmp_path):
    """Derived-class fields inside the base's undeclared tail keep their exact offsets."""
    import subprocess

    from output.project import ProjectWriter

    seed(kb, chess_ir)
    kb.save_type(TypeRecord(name="Piece", size=0x18, confidence=0.9, fields=[
        FieldDef(offset=0, size=8, name="vftable", type="void **", confidence=0.95),
        FieldDef(offset=0x14, size=4, name="value", type="int", confidence=0.3),   # withheld
    ]))
    kb.save_type(TypeRecord(name="Rook", size=0x18, confidence=0.9, base_class="Piece", base_confidence=0.95,
                            fields=[FieldDef(offset=8, size=4, name="dest_col", type="int", confidence=0.9),
                                    FieldDef(offset=0xC, size=4, name="dest_row", type="int", confidence=0.9),
                                    FieldDef(offset=0x10, size=1, name="piece_type", type="uchar", confidence=0.9)]))
    kb.save_type(TypeRecord(name="Engine", size=0x84, confidence=0.9, fields=[
        FieldDef(offset=0x38, size=32, name="player1", type="std::string", confidence=0.9),
        FieldDef(offset=0x80, size=4, name="turn", type="unsigned int", confidence=0.9)]))
    sigs = assign_signatures(kb, chess_ir)
    w = ProjectWriter(tmp_path / "proj", kb, chess_ir, sigs, "Chess")
    w.write_headers()
    check = tmp_path / "proj" / "check.cpp"
    check.write_text('#include "reconstructed.h"\n#include <cstddef>\n'
                     "static_assert(offsetof(Rook, dest_col) == 0x8, \"\");\n"
                     "static_assert(offsetof(Rook, dest_row) == 0xc, \"\");\n"
                     "static_assert(offsetof(Rook, piece_type) == 0x10, \"\");\n"
                     "static_assert(sizeof(Rook) == 0x18, \"\");\n"
                     "static_assert(offsetof(Engine, player1) == 0x38, \"\");\n"
                     "static_assert(offsetof(Engine, turn) == 0x80, \"\");\n"
                     "static_assert(sizeof(Engine) == 0x84, \"\");\n"
                     "static_assert(std::is_base_of<Piece, Rook>::value, \"\");\n")
    proc = subprocess.run(["g++", "-std=c++17", "-fsyntax-only", "-w", "-Wno-invalid-offsetof",
                           "-I", str(tmp_path / "proj" / "include"), str(check)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(shutil.which("g++") is None, reason="g++ not available")
def test_offline_pipeline_end_to_end(tmp_path):
    from rich.console import Console

    from pipeline import Pipeline
    from tests.conftest import FIXTURE
    from tests.fakes import FakeLLM, FakeRunner

    llm, runner = FakeLLM(), FakeRunner(FIXTURE)
    p = Pipeline(tmp_path / "Chess.exe", "fake", rounds=2, workspace=tmp_path / "ws", llm=llm, runner=runner,
                 concurrency=4, console=Console(quiet=True))
    out = p.run()

    assert not p.failures, p.failures
    kinds = {k for k, _ in llm.calls}
    assert {"analyze", "types", "code"} <= kinds
    # The fake analyzer calls Engine::CheckState void while GameLoop uses its result: the
    # cross-check queues exactly that function for round 2, and the signature falls back
    # to the type the callers receive.
    round2 = [tag for kind, tag in llm.calls if kind == "analyze" and tag.startswith("analyze_r2_")]
    assert round2 == ["analyze_r2_0x140005f80"]
    assert len(runner.plans) == 2
    assert runner.plans[0]["structs"]      # class layouts reached Ghidra
    assert "int CheckState();" in (out / "include" / "types.h").read_text()
    for name in ("CMakeLists.txt", "include/types.h", "include/reconstructed.h", "src/functions.cpp",
                 "src/Engine.cpp", "function_map.json"):
        assert (out / name).exists(), name
    root = tmp_path / "ws" / "Chess"
    for d in ("functions", "types", "globals", "strings", "relationships"):
        assert any((root / d).iterdir()), d
    assert (root / "knowledge.json").exists() and (root / "report.md").exists()
    recs = [r for r in p.kb.in_scope() if r.cpp]
    assert recs and all(r.compile_status in ("ok", "error") for r in recs)
    assert sum(r.compile_status == "ok" for r in recs) >= len(recs) // 2
    types_h = (out / "include" / "types.h").read_text()
    assert "class Piece" in types_h and "field_10" in types_h

    # Rerun resumes: nothing new is sent to the LLM.
    before = len(llm.calls)
    Pipeline(tmp_path / "Chess.exe", "fake", rounds=2, workspace=tmp_path / "ws", llm=llm, runner=runner,
             console=Console(quiet=True)).run()
    assert len([c for c in llm.calls[before:] if c[0] != "code"]) == 0
