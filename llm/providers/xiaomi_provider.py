"""Xiaomi MiMo — cloud provider, Anthropic-compatible API. https://platform.xiaomimomo.com"""

import os

from llm.providers.base import BaseProvider, HEAVY


class XiaomiProvider(BaseProvider):
    def __init__(self, cfg, timeout: int):
        import anthropic
        self._cfg = cfg
        self._client = anthropic.Anthropic(
            api_key=os.environ.get("XIAOMI_API_KEY", ""),
            base_url=cfg.base_url,
            timeout=timeout,
        )

    def complete(self, system: str, user: str, tier: str = HEAVY) -> str:
        msg = self._client.messages.create(
            model=self._cfg.model,
            max_tokens=self._cfg.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
