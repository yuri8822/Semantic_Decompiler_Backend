"""DeepSeek — cloud provider, OpenAI-compatible API. https://platform.deepseek.com"""

import os

from config import DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, DEEPSEEK_MAX_TOKENS, AI_TIMEOUT_SECONDS
from llm.providers.base import BaseProvider, HEAVY


class DeepSeekProvider(BaseProvider):
    def __init__(self):
        from openai import OpenAI
        self._client = OpenAI(
            base_url=DEEPSEEK_BASE_URL,
            api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
            timeout=AI_TIMEOUT_SECONDS,
        )

    def complete(self, system: str, user: str, tier: str = HEAVY) -> str:
        resp = self._client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            max_tokens=DEEPSEEK_MAX_TOKENS,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        choice = resp.choices[0]
        text = choice.message.content or ""
        if not text.strip():
            reasoning = getattr(choice.message, "reasoning_content", None) or ""
            raise RuntimeError(f"DeepSeek returned no answer (finish_reason={choice.finish_reason!r}, "
                               f"{len(reasoning)} chars of reasoning); raise DEEPSEEK_MAX_TOKENS if 'length'")
        return text
