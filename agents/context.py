"""
Renders knowledge-base and IR facts as prompt text. Shared by every agent so
they all describe functions, neighbours and classes the same way.
"""

from collections import defaultdict

from agents.crosscheck import return_value_uses
import settings
from ghidra_io.ir import FunctionIR, ProgramIR
from knowledge.confidence import tier
from knowledge.filters import is_imported_data


class Context:
    """Name resolution and rendering over one knowledge base + current IR."""

    def __init__(self, kb, ir: ProgramIR, signatures: dict = None, ir0: ProgramIR = None):
        self.kb = kb
        self.ir = ir
        self.ir0 = ir0 or ir      # round-0 export: Ghidra's inference before any applied knowledge
        self.signatures = signatures or {}
        self.limits = settings.current().prompts

    # -- names ------------------------------------------------------------------

    def name_of(self, address: str) -> str:
        sig = self.signatures.get(address)
        if sig:
            return sig.qualified
        rec = self.kb.functions.get(address)
        fn = self.ir.get(address)
        if rec and rec.alias_of:
            return self.name_of(rec.alias_of)
        if fn:
            return fn.full_name or fn.name
        return address

    def summary_of(self, address: str) -> str:
        rec = self.kb.functions.get(address)
        if rec and rec.excluded:
            return f"library/runtime code ({rec.excluded})"
        if rec and rec.analysis and rec.analysis.summary:
            a = rec.analysis
            return f"{a.summary} [name confidence {a.name_confidence:.2f}]"
        return "not analyzed yet"

    # -- function facts -------------------------------------------------------

    def header(self, fn: FunctionIR) -> str:
        origin = ("Ghidra default name — needs a real name" if fn.name_source == "DEFAULT"
                  else "name from a previous analysis round" if fn.name_source == "USER_DEFINED"
                  else "name from program symbols — KEEP IT")
        return "\n".join([
            f"ADDRESS: {fn.address}",
            f"GHIDRA NAME: {fn.full_name or fn.name}   ({origin})",
            f"GHIDRA SIGNATURE: {fn.signature}",
            f"CALLING CONVENTION: {fn.calling_convention}",
            f"SIZE: {fn.stats.instructions} instructions, {fn.stats.basic_blocks} basic blocks, "
            f"{fn.stats.cbranches} conditional branches, {fn.stats.calls} calls",
        ])

    def parameters(self, fn: FunctionIR) -> str:
        if not fn.parameters:
            return "  (none)"
        out = []
        for p in fn.parameters:
            flags = [f for f, on in (("auto this", p.is_this), ("hidden return slot", p.hidden_return)) if on]
            out.append(f"  [{p.index}] {p.type} {p.name}" + (f"  ({', '.join(flags)})" if flags else ""))
        return "\n".join(out)

    def locals(self, fn: FunctionIR) -> str:
        if not fn.locals:
            return "  (none)"
        return "\n".join(f"  {l.type} {l.name}" for l in fn.locals[:60])

    def field_accesses(self, fn: FunctionIR) -> str:
        """Aggregated `param + offset` accesses proven by p-code."""
        agg = defaultdict(lambda: {"read": 0, "write": 0, "sizes": set()})
        names = {}
        for a in fn.field_accesses:
            key = (a.param, a.offset)
            agg[key][a.access] += 1
            agg[key]["sizes"].add(a.size)
            names[a.param] = a.param_name
        if not agg:
            return "  (none observed)"
        out = []
        for (param, offset), v in sorted(agg.items()):
            sizes = "/".join(str(s) for s in sorted(v["sizes"]))
            rw = ", ".join(f"{k} x{v[k]}" for k in ("read", "write") if v[k])
            out.append(f"  param[{param}] {names[param]} +{offset:#x}  size {sizes}  {rw}")
        return "\n".join(out)

    def arg_passes(self, fn: FunctionIR) -> str:
        if not fn.arg_passes:
            return "  (none)"
        seen, out = set(), []
        for p in fn.arg_passes:
            key = (p.callee, p.arg, p.param, p.offset)
            if key in seen:
                continue
            seen.add(key)
            where = p.param_name + (f"+{p.offset:#x}" if p.offset else "")
            out.append(f"  {where} passed as argument {p.arg} to {self.name_of(p.callee)} ({p.callee})")
        return "\n".join(out)

    def callees(self, fn: FunctionIR) -> str:
        out = []
        for c in fn.calls[:self.limits.max_neighbours * 2]:
            if c.external:
                lib = f" from {c.library}" if c.library else ""
                out.append(f"  {c.name}  (imported{lib})")
            else:
                sig = self.signatures.get(c.address)
                shown = sig.definition_head() if sig else self.name_of(c.address)
                out.append(f"  {c.address} {shown} — {self.summary_of(c.address)}")
        return "\n".join(out) or "  (none)"

    def callers(self, fn: FunctionIR) -> str:
        out = [f"  {a} {self.name_of(a)} — {self.summary_of(a)}" for a in fn.callers[:self.limits.max_neighbours]]
        if len(fn.callers) > self.limits.max_neighbours:
            out.append(f"  ... and {len(fn.callers) - self.limits.max_neighbours} more")
        return "\n".join(out) or "  (none — entry point, callback, or called through a pointer)"

    def return_uses(self, fn: FunctionIR) -> str:
        if not fn.callers:
            return "  (no known callers)"
        uses = return_value_uses(self.ir0, fn.address)
        if not uses:
            return "  no caller uses the return value"
        return "\n".join(f"  {u['caller_name']}: {u['line']}" + (f"   (received as {u['type']})" if u["type"] else "")
                         for u in uses[:8])

    def strings(self, fn: FunctionIR) -> str:
        return "\n".join(f"  {s!r}" for s in fn.strings[:30]) or "  (none)"

    def globals(self, fn: FunctionIR) -> str:
        out = []
        for g in fn.globals[:30]:
            access = "+".join(k for k, on in (("read", g.read), ("write", g.write)) if on)
            if g.external or is_imported_data(g.name):
                out.append(f"  {g.name}  (library data, {access})")
                continue
            rec = self.kb.globals.get(g.address)
            known = f" — known as {rec.name}: {rec.type} [{tier(rec.confidence)}]" if rec and rec.name else ""
            out.append(f"  {g.address} {g.name} : {g.type or '?'} ({access}){known}")
        return "\n".join(out) or "  (none)"

    def decompiled(self, fn: FunctionIR) -> str:
        text = fn.decompiled.strip()
        if len(text) > self.limits.max_decompiled_chars:
            text = text[:self.limits.max_decompiled_chars] + "\n/* ... truncated ... */"
        return text

    def assembly(self, fn: FunctionIR) -> str:
        lines = fn.assembly[:self.limits.max_assembly_lines]
        more = len(fn.assembly) - len(lines)
        return "\n".join(lines) + (f"\n... ({more} more instructions)" if more > 0 else "")

    # -- classes --------------------------------------------------------------

    def class_layout(self, name: str) -> str:
        t = self.kb.types.get(name)
        if t is None:
            return f"class {name}  (layout not reconstructed yet)"
        head = f"{t.kind} {t.name}" + (f" : public {t.base_class}" if t.base_class else "")
        lines = [f"{head}   // size {t.size:#x}, confidence {t.confidence:.2f}"]
        for f in sorted(t.fields, key=lambda f: f.offset):
            lines.append(f"  +{f.offset:#05x}  {f.type} {f.name};  // size {f.size}, {tier(f.confidence)} "
                         f"confidence {f.confidence:.2f}")
        methods = [self.name_of(m) for m in t.members[:30]]
        if methods:
            lines.append("  methods: " + ", ".join(methods))
        return "\n".join(lines)

    def known_classes_brief(self, limit: int = 40) -> str:
        if not self.kb.types:
            return "  (none yet)"
        out = []
        for t in sorted(self.kb.types.values(), key=lambda t: t.name)[:limit]:
            fields = ", ".join(f"+{f.offset:#x} {f.name}" for f in sorted(t.fields, key=lambda f: f.offset)[:12])
            out.append(f"  {t.name} (size {t.size:#x}): {fields or 'no fields yet'}")
        return "\n".join(out)
