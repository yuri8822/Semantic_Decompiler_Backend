"""report.md: what was reconstructed, how confident the pipeline is, and what still needs a human."""

from collections import Counter
from pathlib import Path

from knowledge.confidence import accepted, tier
from output.compiler import first_error


def _cell(text: str, limit: int = 90) -> str:
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def write_report(kb, ir, sigs: dict, build: dict, failures: list) -> Path:
    recs = sorted(kb.functions.values(), key=lambda r: r.address)
    in_scope = [r for r in recs if not r.excluded and not r.alias_of]
    excluded = [r for r in recs if r.excluded]
    aliases = [r for r in recs if r.alias_of]
    analyzed = [r for r in in_scope if r.analysis]
    tiers = Counter(tier(r.analysis.name_confidence) for r in analyzed)
    with_code = [r for r in in_scope if r.cpp]
    compile_counts = Counter(r.compile_status for r in with_code)

    out = [f"# Reconstruction report — {ir.program.name}", ""]
    out += [
        f"- Target: {ir.program.language}, compiler spec `{ir.program.compiler}`, "
        f"image base {ir.program.image_base}",
        f"- Functions: {len(recs)} total, {len(in_scope)} in scope, {len(excluded)} excluded "
        f"(library/runtime), {len(aliases)} duplicate constructor/destructor variants",
        f"- Analysis: {len(analyzed)} analyzed — name confidence {tiers['high']} high / "
        f"{tiers['medium']} medium / {tiers['low']} low",
        f"- Classes reconstructed: {len(kb.types)}",
        f"- Code: {len(with_code)} functions — compile {compile_counts['ok']} ok, "
        f"{compile_counts['error']} failing, {compile_counts['unchecked']} unchecked",
        f"- Project build (CMake): {build.get('status', 'skipped')}",
        "",
    ]

    if kb.meta.get("rounds"):
        out += ["## Ghidra feedback rounds", "", "| Round | Plan (functions/structs/globals) | Applied | Skipped | Failed |",
                "|---|---|---|---|---|"]
        for r in sorted(kb.meta["rounds"], key=lambda r: r["round"]):
            p = r.get("plan", {})
            out.append(f"| {r['round']} | {p.get('functions', 0)}/{p.get('structs', 0)}/{p.get('globals', 0)} "
                       f"| {r.get('applied', 0)} | {r.get('skipped', 0)} | {r.get('failed', 0)} |")
        out.append("")

    if kb.meta.get("header_errors"):
        out += ["## Generated headers do not compile", "", "```", kb.meta["header_errors"][:3000], "```", ""]

    out += ["## Functions", "",
            "| Address | Name | Name conf. | Validator | Compile | Summary |", "|---|---|---|---|---|---|"]
    for r in in_scope:
        sig = sigs.get(r.address)
        name = sig.qualified if sig else r.full_name or r.ghidra_name
        conf = f"{r.analysis.name_confidence:.2f} {tier(r.analysis.name_confidence)}" if r.analysis else "—"
        errs = sum(i.severity == "error" for i in r.static_issues)
        warns = sum(i.severity == "warning" for i in r.static_issues)
        val = (f"{errs} err, {warns} warn" if r.cpp else "—")
        summary = r.analysis.summary if r.analysis else ""
        compiled = r.compile_status if (r.cpp or r.compile_status == "error") else "—"
        out.append(f"| `{r.address}` | `{_cell(name, 60)}` | {conf} | {val} | {compiled} | {_cell(summary)} |")
    out.append("")

    needs_human = [r for r in in_scope if r.compile_status == "error"
                   or (r.cpp and any(i.severity == "error" for i in r.static_issues))]
    if needs_human:
        out += ["## Needs attention", ""]
        for r in needs_human:
            sig = sigs.get(r.address)
            out.append(f"### `{r.address}` {sig.qualified if sig else r.ghidra_name}")
            for i in r.static_issues:
                if i.severity == "error":
                    out.append(f"- validator: {i.message}")
            if r.compile_status == "error":
                out.append(f"- compiler: `{_cell(first_error(r.compile_errors), 200)}`")
            out.append("")

    low = [r for r in in_scope if r.needs_reanalysis]
    if low:
        out += ["## Still low-confidence (not applied to Ghidra)", ""]
        out += [f"- `{r.address}` {r.analysis.name if r.analysis else r.ghidra_name} "
                f"({r.analysis.name_confidence:.2f})" if r.analysis else f"- `{r.address}` {r.ghidra_name}"
                for r in low]
        out.append("")

    inconsistencies = _inconsistencies(kb)
    if inconsistencies:
        out += ["## Knowledge inconsistencies", ""] + [f"- {i}" for i in inconsistencies] + [""]

    if kb.types:
        out += ["## Classes", ""]
        for t in sorted(kb.types.values(), key=lambda t: t.name):
            out.append(f"### {t.name} — size {t.size:#x}, confidence {t.confidence:.2f}"
                       + (f", base {t.base_class}" if t.base_class else ""))
            for f in sorted(t.fields, key=lambda f: f.offset):
                out.append(f"- `+{f.offset:#x}` `{f.type} {f.name}` ({f.size} bytes, {tier(f.confidence)} "
                           f"{f.confidence:.2f})")
            if t.notes:
                out.append(f"- notes: {_cell(t.notes, 400)}")
            out.append("")

    if failures:
        out += ["## Agent failures", ""] + [f"- {f['item']}: {_cell(f['error'], 300)}" for f in failures] + [""]

    out += ["## Excluded functions", ""] + [f"- `{r.address}` {r.full_name or r.ghidra_name} — {r.excluded}"
                                            for r in excluded]
    path = kb.root / "report.md"
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return path


def _inconsistencies(kb) -> list:
    """Disagreements between what individual functions claim and the reconstructed layouts."""
    found = []
    for t in kb.types.values():
        for other in t.same_as:
            found.append(f"type reconstructor thinks `{t.name}` and `{other}` are the same type (not merged)")
    for r in kb.functions.values():
        a = r.analysis
        if not a:
            continue
        for f in a.fields:
            t = kb.types.get(f.class_name)
            if not t or not accepted(f.confidence):
                continue
            layout = t.field_at(f.offset)
            vtable_names = ("vftable", "vtable", "vtbl", "vptr", "vfptr")
            if layout and any(k in layout.name.lower() for k in vtable_names) \
                    and any(k in f.name.lower() for k in vtable_names):
                continue  # same vtable pointer under a different spelling
            if layout and layout.name != f.name and accepted(layout.confidence):
                found.append(f"`{r.address}` calls {t.name}+{f.offset:#x} `{f.name}`, layout says `{layout.name}`")
    return found[:200]
