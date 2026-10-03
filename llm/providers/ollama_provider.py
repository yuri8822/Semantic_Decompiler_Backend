"""Ollama — local provider, via its OpenAI-compatible endpoint. https://ollama.com/library"""

from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_MAX_TOKENS, AI_TIMEOUT_SECONDS
from llm.providers.base import BaseProvider, HEAVY


class OllamaProvider(BaseProvider):
    def __init__(self, model: str = None):
        from openai import OpenAI
        self._client = OpenAI(
            base_url=OLLAMA_BASE_URL,
            api_key="ollama",   # required by the openai SDK but ignored by Ollama
            timeout=AI_TIMEOUT_SECONDS,
        )
        self._model = model or OLLAMA_MODEL

    def complete(self, system: str, user: str, tier: str = HEAVY) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            max_tokens=OLLAMA_MAX_TOKENS,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""
