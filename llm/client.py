"""
Provider-agnostic LLM client used by every agent: retries transient
failures, logs traffic to the workspace, and offers a JSON mode that asks
the model to repair an unparseable answer once before giving up.
"""

import itertools
import re
import threading
import time
from pathlib import Path

from config import LLM_PROVIDER, OLLAMA_MODEL, LLM_RETRIES, LOG_LLM_TRAFFIC
from llm.parsing import ParseError, extract_code, extract_json
from llm.providers import get_provider
from llm.providers.base import HEAVY, FAST

_JSON_REPAIR_SYSTEM = (
    "You fix malformed JSON. Return only the corrected JSON object, with no prose and no code fences."
)


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, provider: str = LLM_PROVIDER, ollama_model: str = OLLAMA_MODEL,
                 log_dir: Path = None, impl=None):
        self.provider = provider.lower()
        self._impl = impl or get_provider(self.provider, ollama_model=ollama_model)
        self._log_dir = Path(log_dir) if (log_dir and LOG_LLM_TRAFFIC) else None
        # Continue numbering across resumed runs so earlier logs are never overwritten.
        existing = [int(p.name[:5]) for p in self._log_dir.glob("[0-9][0-9][0-9][0-9][0-9]_*")] \
            if self._log_dir and self._log_dir.exists() else []
        self._counter = itertools.count(max(existing, default=0) + 1)
        self._lock = threading.Lock()

    def complete(self, system: str, user: str, tier: str = HEAVY, tag: str = "call") -> str:
        last_exc = None
        for attempt in range(LLM_RETRIES):
            try:
                text = self._impl.complete(system, user, tier)
                self._log(tag, system, user, text)
                if not text.strip():
                    raise LLMError("empty response")
                return text
            except Exception as exc:  # provider SDKs raise many unrelated types
                last_exc = exc
                self._log(tag, system, user, f"<<error: {exc!r}>>")
                if attempt + 1 < LLM_RETRIES:
                    time.sleep(2 ** attempt * 2)
        raise LLMError(f"{self.provider} failed after {LLM_RETRIES} attempts: {last_exc}") from last_exc

    def complete_json(self, system: str, user: str, tier: str = HEAVY, tag: str = "json") -> dict:
        text = self.complete(system, user, tier, tag)
        try:
            return extract_json(text)
        except ParseError as exc:
            repaired = self.complete(
                _JSON_REPAIR_SYSTEM,
                f"This should be a single JSON object but does not parse ({exc}). Fix it:\n\n{text}",
                FAST, f"{tag}-repair",
            )
            try:
                return extract_json(repaired)
            except ParseError as exc2:
                raise LLMError(f"model did not return valid JSON: {exc2}") from exc2

    def complete_code(self, system: str, user: str, tier: str = HEAVY, tag: str = "code") -> str:
        return extract_code(self.complete(system, user, tier, tag))

    def _log(self, tag: str, system: str, user: str, response: str):
        if not self._log_dir:
            return
        with self._lock:
            n = next(self._counter)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", tag)[:80]
        self._log_dir.mkdir(parents=True, exist_ok=True)
        path = self._log_dir / f"{n:05d}_{safe}.txt"
        path.write_text(
            f"=== PROVIDER: {self.provider}\n=== SYSTEM\n{system}\n\n=== USER\n{user}\n\n=== RESPONSE\n{response}\n",
            encoding="utf-8",
        )
