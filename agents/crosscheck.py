"""
Deterministic cross-checks between one function's analysis and what the
rest of the binary shows about it.

Return values: if callers use a function's result but its analysis says it
returns void, the analysis is contradicted by Ghidra's own data flow. The
return type is then withheld (confidence capped below the apply threshold),
the function is queued for re-analysis with the contradiction spelled out,
and the type the callers receive the result into becomes the fallback.

Call sites are read from the round-0 export: Ghidra's own inference, before
any of the pipeline's types were applied to the program.
"""

import re
from collections import Counter

from agents.cpp_text import mask
from config import CONFIDENCE_MEDIUM
from ghidra_io.ir import ProgramIR
from knowledge.naming import ghidra_to_cpp_type

_ASSIGNED_RE = re.compile(r"([A-Za-z_]\w*)\s*=\s*$")
_STATEMENT_KEYWORD_RE = re.compile(r"(\belse|\bdo|\bLAB_\w+\s*:)$")
_RETURN_CAP = CONFIDENCE_MEDIUM - 0.1


def return_value_uses(ir0: ProgramIR, callee_address: str) -> list:
    """Call sites where a caller uses `callee_address`'s result: [{caller, line, type}]."""
    callee = ir0.get(callee_address)
    if callee is None:
        return []
    uses = []
    for caller_address in callee.callers:
        caller = ir0.get(caller_address)
        if caller is None:
            continue
        patterns = []
        if callee.full_name and callee.full_name != callee.name:
            patterns.append(re.escape(callee.full_name))
        # The bare name is only trustworthy if no other callee of this caller shares it.
        if sum(c.name.split("::")[-1] == callee.name for c in caller.calls) <= 1:
            patterns.append(r"(?<![\w:>.])" + re.escape(callee.name))
        if not patterns:
            continue
        masked = mask(caller.decompiled)
        for m in re.finditer(r"(?:%s)\s*\(" % "|".join(patterns), masked):
            before = masked[:m.start()].rstrip()
            if not before or before[-1] in ";{}" or _STATEMENT_KEYWORD_RE.search(before):
                continue  # the call is a statement of its own: result discarded
            line_start = caller.decompiled.rfind("\n", 0, m.start()) + 1
            line_end = caller.decompiled.find("\n", m.start())
            line = caller.decompiled[line_start:line_end if line_end != -1 else None].strip()
            var_type = ""
            assigned = _ASSIGNED_RE.search(before[-120:])
            if assigned:
                local = caller.local(assigned.group(1))
                var_type = local.type if local else ""
            uses.append({"caller": caller_address, "caller_name": caller.full_name or caller.name,
                         "line": line, "type": var_type})
    return uses


def check_return_values(kb, ir0: ProgramIR, addresses) -> list:
    """Flag analyses that say void while callers use the result. Returns the addresses that changed."""
    changed = []
    for address in addresses:
        rec = kb.functions.get(address)
        a = rec.analysis if rec else None
        if a is None or a.method_kind in ("constructor", "destructor"):
            continue
        says_void = ghidra_to_cpp_type(a.return_type) == "void" if a.return_type else True
        uses = return_value_uses(ir0, address) if says_void else []
        contradictions, observed = [], ""
        if uses:
            types = Counter(ghidra_to_cpp_type(u["type"]) for u in uses if u["type"])
            observed = types.most_common(1)[0][0] if types else ""
            where = "; ".join(f"{u['caller_name']}: `{u['line']}`" for u in uses[:3])
            contradictions.append(
                f"callers use the return value ({where}) but the analysis says it returns "
                f"{a.return_type or 'nothing'}" + (f"; callers receive it as {observed}" if observed else ""))
        if contradictions:
            a.return_confidence = min(a.return_confidence, _RETURN_CAP)
        if contradictions != a.contradictions or observed != a.observed_return_type:
            a.contradictions, a.observed_return_type = contradictions, observed
            kb.save_function(rec)
            changed.append(address)
    return changed
