"""Anthropic Claude — cloud provider, with a heavy/fast model split."""

from config import ANTHROPIC_MODEL_HEAVY, ANTHROPIC_MODEL_FAST, MAX_TOKENS, AI_TIMEOUT_SECONDS
from llm.providers.base import BaseProvider, HEAVY


class AnthropicProvider(BaseProvider):
    def __init__(self):
        import anthropic
        self._client = anthropic.Anthropic(timeout=AI_TIMEOUT_SECONDS)

    def complete(self, system: str, user: str, tier: str = HEAVY) -> str:
        model = ANTHROPIC_MODEL_HEAVY if tier == HEAVY else ANTHROPIC_MODEL_FAST
        msg = self._client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
