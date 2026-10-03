"""
Code Reconstructor — second LLM pass: readable C++ for one function, written
from the improved decompilation plus everything the knowledge base knows
(class layout, method identity, parameter meanings, neighbour signatures).
"""

from agents.cpp_text import extract_definition
from agents.prompts import CODE_SYSTEM, build_code_prompt, build_fix_prompt


class CodeReconstructor:
    def __init__(self, llm):
        self.llm = llm

    def write(self, ctx, fn, sig, rec) -> str:
        code = self.llm.complete_code(
            CODE_SYSTEM, build_code_prompt(ctx, fn, sig, rec), tag=f"code_{fn.address}",
        )
        return isolate(code, sig)

    def fix(self, ctx, fn, sig, rec, code: str, issues: list, compiler_output: str = "", tag: str = "fix") -> str:
        fixed = self.llm.complete_code(
            CODE_SYSTEM, build_fix_prompt(ctx, fn, sig, rec, code, issues, compiler_output),
            tag=f"{tag}_{fn.address}",
        )
        return isolate(fixed, sig)


def isolate(code: str, sig) -> str:
    """
    Keep only the requested definition: models sometimes add helper structs,
    includes or neighbouring functions, which would collide with the
    generated header. If the definition can't be located, the text is kept
    as-is and the validator reports it.
    """
    d = extract_definition(code, sig.qualified, sig.name)
    return code[d.start:d.end].strip() if d else code.strip()
