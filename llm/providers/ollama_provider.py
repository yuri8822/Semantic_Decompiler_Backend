"""Ollama — local provider, via its OpenAI-compatible endpoint. https://ollama.com/library"""

from llm.providers.base import BaseProvider, HEAVY


class OllamaProvider(BaseProvider):
    def __init__(self, cfg, timeout: int):
        from openai import OpenAI
        self._cfg = cfg
        self._client = OpenAI(
            base_url=cfg.base_url,
            api_key="ollama",   # required by the openai SDK but ignored by Ollama
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
        return resp.choices[0].message.content or ""
