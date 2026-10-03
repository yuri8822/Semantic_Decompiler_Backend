"""Anthropic Claude — cloud provider, with a heavy/fast model split."""

from llm.providers.base import BaseProvider, HEAVY


class AnthropicProvider(BaseProvider):
    def __init__(self, cfg, timeout: int):
        import anthropic
        self._cfg = cfg
        self._client = anthropic.Anthropic(timeout=timeout)

    def complete(self, system: str, user: str, tier: str = HEAVY) -> str:
        model = self._cfg.model_heavy if tier == HEAVY else self._cfg.model_fast
        msg = self._client.messages.create(
            model=model,
            max_tokens=self._cfg.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
