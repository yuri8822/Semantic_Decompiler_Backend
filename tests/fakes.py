"""
Offline stand-ins for the LLM and Ghidra, for exercising the pipeline end to
end. FakeLLM answers each specialist's prompt format deterministically from
the facts in the prompt itself; it is plausible, not smart.
"""

import json
import re
import shutil
import threading

from agents.prompts import ANALYZER_SYSTEM, CODE_SYSTEM, TYPE_SYSTEM


class FakeLLM:
    provider = "fake"

    def __init__(self, name_confidence: float = 0.9):
        self.name_confidence = name_confidence
        self.calls = []
        self._lock = threading.Lock()

    def _record(self, kind, tag):
        with self._lock:
            self.calls.append((kind, tag))

    def complete_json(self, system, user, tier="heavy", tag="json"):
        if system == ANALYZER_SYSTEM:
            self._record("analyze", tag)
            return self._analysis(user)
        if system == TYPE_SYSTEM:
            self._record("types", tag)
            return self._layout(user)
        raise AssertionError("unexpected JSON prompt")

    def complete_code(self, system, user, tier="heavy", tag="code"):
        assert system == CODE_SYSTEM
        self._record("code", tag)
        head = re.search(r"REQUIRED SIGNATURE:\n  (.*)", user).group(1)
        ret = head.split("(")[0].rsplit(" ", 1)[0] if "::" in head.split("(")[0] or " " in head.split("(")[0] else ""
        name = head.split("(")[0].split()[-1].lstrip("*")
        is_ctor_dtor = "::" in name and (name.split("::")[-1].lstrip("~") == name.split("::")[-2])
        if is_ctor_dtor or ret in ("", "void"):
            body = "{\n}"
        else:
            body = "{\n    return {};\n}"
        return f"{head}\n{body}"

    def _analysis(self, user):
        address = re.search(r"ADDRESS: (\S+)", user).group(1)
        ghidra = re.search(r"GHIDRA NAME: (.*?)   \(", user).group(1)
        keep = "KEEP IT" in user.split("\n", 3)[2]
        name = ghidra if keep else f"Widget::Func_{address[-4:]}"
        params = []
        section = user.split("PARAMETERS (Ghidra):\n", 1)[1].split("\n\n", 1)[0]
        for m in re.finditer(r"\[(\d+)\] (.*) (\w+)(  \((.*)\))?$", section, re.MULTILINE):
            idx, ptype, pname, flags = int(m.group(1)), m.group(2), m.group(3), m.group(5) or ""
            role = "this" if "auto this" in flags else "normal"
            params.append({"index": idx, "old_name": pname, "name": "this" if role == "this" else f"arg{idx}",
                           "type": ptype, "role": role, "confidence": self.name_confidence})
        cls = name.split("::")[0] if "::" in name else ""
        fields = []
        for m in re.finditer(r"param\[(\d+)\] \w+ \+(0x[0-9a-f]+)  size (\d+)", user):
            size = int(m.group(3))
            ftype = {1: "bool", 2: "short", 4: "int", 8: "uint64_t"}.get(size, "int")
            fields.append({"param": int(m.group(1)), "class_name": cls, "offset": m.group(2),
                           "name": f"field_{m.group(2)[2:]}", "type": ftype, "confidence": 0.9})
        kind = "free"
        if cls:
            member = name.split("::")[-1]
            kind = "constructor" if member == cls else "destructor" if member.startswith("~") else "method"
        return {
            "name": name, "name_confidence": self.name_confidence, "class_name": cls, "method_kind": kind,
            "summary": f"does something at {address}", "evidence": ["fake"],
            "return_type": "", "return_confidence": 0.0, "params": params, "fields": fields,
            "locals": [], "globals": [],
        }

    @staticmethod
    def _layout(user):
        name = re.search(r"CANDIDATE TYPE: (\w+)", user).group(1)
        fields, seen = [], set()
        for m in re.finditer(r"\+(0x[0-9a-f]+) size (\d+)", user):
            off, size = int(m.group(1), 16), int(m.group(2))
            if off in seen:
                continue
            seen.add(off)
            ftype = {1: "bool", 2: "short", 4: "int", 8: "void *"}.get(size, "int")
            fields.append({"offset": hex(off), "size": size, "name": f"field_{off:x}", "type": ftype,
                           "confidence": 0.9})
        return {"name": name, "kind": "class", "size": 0, "confidence": 0.9, "fields": fields}


class FakeRunner:
    """Ghidra stand-in: 'exports' a fixture, and 'applies' plans by re-exporting it unchanged."""

    def __init__(self, fixture):
        self.fixture = fixture
        self.plans = []

    def import_and_export(self, out_json):
        out_json.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.fixture, out_json)
        return out_json

    def apply_and_export(self, plan_json, report_json, out_json):
        self.plans.append(json.loads(plan_json.read_text(encoding="utf-8")))
        report_json.write_text(json.dumps({"applied": [], "failed": []}), encoding="utf-8")
        shutil.copy(self.fixture, out_json)
        return out_json
