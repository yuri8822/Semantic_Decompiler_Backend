"""Xiaomi MiMo — cloud provider, Anthropic-compatible API. https://platform.xiaomimomo.com"""

import os

from config import XIAOMI_BASE_URL, XIAOMI_MODEL, MAX_TOKENS, AI_TIMEOUT_SECONDS
from llm.providers.base import BaseProvider, HEAVY


class XiaomiProvider(BaseProvider):
    def __init__(self):
        import anthropic
        self._client = anthropic.Anthropic(
            api_key=os.environ.get("XIAOMI_API_KEY", ""),
            base_url=XIAOMI_BASE_URL,
            timeout=AI_TIMEOUT_SECONDS,
        )

    def complete(self, system: str, user: str, tier: str = HEAVY) -> str:
        msg = self._client.messages.create(
            model=XIAOMI_MODEL,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
