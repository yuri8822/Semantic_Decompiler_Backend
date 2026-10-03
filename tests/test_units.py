"""Unit tests for the deterministic parts of the pipeline."""

import pytest

from agents import cpp_text
from knowledge.callgraph import bottom_up_levels
from knowledge.confidence import accepted, needs_todo, tier
from knowledge.models import FieldGuess, FunctionAnalysis, to_confidence, to_int
from knowledge.naming import (
    cpp_to_ghidra_type, ghidra_to_cpp_type, is_default_variable_name, sanitize_identifier, split_qualified,
)
from llm.parsing import ParseError, extract_code, extract_json


# -- parsing ----------------------------------------------------------------------

def test_extract_json_from_fenced_block_with_prose():
    text = 'Sure!\n```json\n{"name": "A::b", "list": [1, 2,], // trailing\n "x": "{not a brace}"}\n```\nDone.'
    assert extract_json(text) == {"name": "A::b", "list": [1, 2], "x": "{not a brace}"}


def test_extract_json_bare_object_and_failure():
    assert extract_json('prefix {"a": {"b": 1}} suffix') == {"a": {"b": 1}}
    with pytest.raises(ParseError):
        extract_json("no json here")


def test_extract_code_prefers_largest_cpp_block():
    text = "intro\n```cpp\nint a;\n```\nand\n```cpp\nint f() {\n  return 1;\n}\n```"
    assert extract_code(text) == "int f() {\n  return 1;\n}"
    assert extract_code("int g() { return 2; }") == "int g() { return 2; }"


# -- models / confidence ------------------------------------------------------------

def test_lenient_coercions():
    assert to_int("0x18") == 24 and to_int("-0x8") == -8 and to_int(12) == 12 and to_int("junk") == 0
    assert to_confidence("85%") == pytest.approx(0.85)
    assert to_confidence(97) == pytest.approx(0.97)
    assert to_confidence("high") == 0.0
    f = FieldGuess.model_validate({"offset": "0x1c", "name": "armor", "confidence": "0.7"})
    assert f.offset == 0x1C and f.confidence == pytest.approx(0.7)
    a = FunctionAnalysis.model_validate({"name": "X", "method_kind": "weird", "evidence": "single"})
    assert a.method_kind == "free" and a.evidence == ["single"]


def test_confidence_tiers():
    assert tier(0.95) == "high" and tier(0.7) == "medium" and tier(0.3) == "low"
    assert accepted(0.6) and not accepted(0.59)
    assert needs_todo(0.7) and not needs_todo(0.9) and not needs_todo(0.2)


# -- naming -----------------------------------------------------------------------

def test_identifiers_and_types():
    assert sanitize_identifier("Draw[abi:cxx11]") == "Draw"
    assert sanitize_identifier("_M_construct<char_const*>") == "_M_construct"
    assert sanitize_identifier("class") == "class_"
    assert sanitize_identifier("~Engine") == "~Engine"
    assert split_qualified("std::map<a::b, c>::find") == ["std", "map<a::b, c>", "find"]
    assert ghidra_to_cpp_type("undefined4") == "uint32_t"
    assert ghidra_to_cpp_type("char * *") == "char **"
    assert ghidra_to_cpp_type("const std::string&") == "const std::string &"
    assert ghidra_to_cpp_type("longlong *") == "long long *"
    assert cpp_to_ghidra_type("unsigned int") == "uint"
    assert cpp_to_ghidra_type("Player *", {"Player"}) == "Player *"
    assert cpp_to_ghidra_type("std::string") is None
    assert cpp_to_ghidra_type("std::vector<int> *") == "void *"
    assert is_default_variable_name("param_2") and is_default_variable_name("iVar1")
    assert not is_default_variable_name("health")


# -- call graph ---------------------------------------------------------------------

def test_bottom_up_levels_with_cycle():
    graph = {"main": ["a", "b"], "a": ["c"], "b": ["c", "x_external"], "c": [], "r1": ["r2"], "r2": ["r1", "c"]}
    levels = bottom_up_levels(graph)
    level_of = {n: i for i, lv in enumerate(levels) for n in lv}
    assert level_of["c"] == 0
    assert level_of["a"] == level_of["b"] == 1
    assert level_of["main"] == 2
    assert level_of["r1"] == level_of["r2"] == 1  # a recursive pair shares one level above its callee


# -- C++ text -----------------------------------------------------------------------

CODE = """
// helper the model added
struct Helper { int x; };

/* doc */
void Player::TakeDamage(int amount, const char *why)
{
    if (health > 0 && amount > 0) {  // "if" in a comment: if
        health -= amount;
    }
    log("if (fake)");
}

int other() { return 1; }
"""


def test_find_and_extract_definitions():
    defs = cpp_text.find_definitions(CODE)
    assert [d.name for d in defs] == ["Player::TakeDamage", "other"]
    d = cpp_text.extract_definition(CODE, "Player::TakeDamage", "TakeDamage")
    assert d.param_count == 2 and d.return_part == "void"
    assert CODE[d.start:d.end].startswith("/* doc */")
    assert CODE[d.start:d.end].rstrip().endswith("}")


def test_decision_points_ignore_comments_and_strings():
    body = CODE.split("/* doc */")[1].split("int other")[0]
    assert cpp_text.decision_points(body) == 2   # one if + one &&
    assert "log" in cpp_text.called_names(body)
    assert "if" not in cpp_text.called_names(body)
    assert not cpp_text.returns_value(body)
