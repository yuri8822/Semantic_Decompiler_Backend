"""
llama.cpp — local provider, via llama-server's OpenAI-compatible endpoint
on http://localhost:8080. Model-agnostic: start llama-server with whatever
GGUF you want and this talks to it as-is.
"""

from llm.providers.base import BaseProvider, HEAVY

# Thinking is on server-side with a token budget (llamacpp_server.thinking
# and reasoning_budget, see llm/llamacpp_server.py).
# When the model runs past that budget the server force-closes the think
# block, keeps only what fit in `reasoning_content`, and the model -- not
# knowing it was cut off -- carries on thinking straight into `content`,
# emitting its own `</think>` when it finally finishes. So `content` can
# arrive as:  <tail of reasoning> </think> <the real answer>
# with no opening tag, since the server already consumed it.
#
# Everything after the LAST `</think>` is the answer, which also handles
# the well-formed `<think>...</think>` case, so both collapse to one rule.
_THINK_CLOSE = "</think>"


def strip_reasoning(text: str) -> str:
    """
    Everything after the last `</think>`, or `text` unchanged if there is
    no close tag. Deliberately the LAST one: a model that overruns its
    budget can emit several, and only the final one precedes the answer.
    """
    idx = text.rfind(_THINK_CLOSE)
    if idx == -1:
        return text
    return text[idx + len(_THINK_CLOSE):]


class LlamaCppProvider(BaseProvider):
    def __init__(self, cfg, timeout: int):
        from openai import OpenAI
        self._cfg = cfg
        self._client = OpenAI(
            base_url=cfg.base_url,
            api_key="llamacpp",   # required by the openai SDK but ignored by llama-server
            timeout=timeout,
        )

    def complete(self, system: str, user: str, tier: str = HEAVY) -> str:
        resp = self._client.chat.completions.create(
            model=self._cfg.model,   # llama-server ignores it and serves whatever is loaded
            max_tokens=self._cfg.max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        text = strip_reasoning(resp.choices[0].message.content or "").strip()

        # An empty answer means the whole generation went on thinking and
        # never reached a conclusion; raising beats handing "" downstream.
        if not text:
            raise RuntimeError(
                "llama.cpp returned no answer outside its reasoning trace "
                f"(finish_reason={resp.choices[0].finish_reason!r}). Lower "
                "--reasoning-budget or raise llm.llamacpp.max_tokens."
            )
        return text
