"""DeepSeek — cloud provider, OpenAI-compatible API. https://platform.deepseek.com"""

import os

from llm.providers.base import BaseProvider, HEAVY


class DeepSeekProvider(BaseProvider):
    def __init__(self, cfg, timeout: int):
        from openai import OpenAI
        self._cfg = cfg
        self._client = OpenAI(
            base_url=cfg.base_url,
            api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
            timeout=timeout,
        )

    def complete(self, system: str, user: str, tier: str = HEAVY) -> str:
        resp = self._client.chat.completions.create(
            model=self._cfg.model,
            max_tokens=self._cfg.max_tokens,
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
                               f"{len(reasoning)} chars of reasoning); raise llm.deepseek.max_tokens if 'length'")
        return text
