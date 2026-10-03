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

from llm.parsing import ParseError, extract_code, extract_json
from llm.providers import get_provider
from llm.providers.base import HEAVY, FAST

_JSON_REPAIR_SYSTEM = (
    "You fix malformed JSON. Return only the corrected JSON object, with no prose and no code fences."
)


class LLMError(RuntimeError):
    pass


class TrafficLog:
    """Numbered prompt/response files in one directory, shared by every client of a run."""

    def __init__(self, log_dir: Path):
        self.dir = Path(log_dir)
        # Continue numbering across resumed runs so earlier logs are never overwritten.
        existing = [int(p.name[:5]) for p in self.dir.glob("[0-9][0-9][0-9][0-9][0-9]_*")] \
            if self.dir.exists() else []
        self._counter = itertools.count(max(existing, default=0) + 1)
        self._lock = threading.Lock()

    def write(self, provider: str, tag: str, system: str, user: str, response: str) -> str:
        with self._lock:
            n = next(self._counter)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", tag)[:80]
        self.dir.mkdir(parents=True, exist_ok=True)
        name = f"{n:05d}_{safe}.txt"
        (self.dir / name).write_text(
            f"=== PROVIDER: {provider}\n=== SYSTEM\n{system}\n\n=== USER\n{user}\n\n=== RESPONSE\n{response}\n",
            encoding="utf-8",
        )
        return name


class LLMClient:
    """
    `on_call(info)` (optional) is invoked after every attempt with
    {provider, tag, seconds, ok, error, log}; the API turns it into live events.
    """

    def __init__(self, provider: str, llm_settings=None, log: TrafficLog = None, impl=None, on_call=None):
        self.provider = provider.lower()
        self.retries = llm_settings.retries if llm_settings else 3
        self._impl = impl or get_provider(self.provider, llm_settings)
        self._log = log
        self._on_call = on_call

    def complete(self, system: str, user: str, tier: str = HEAVY, tag: str = "call") -> str:
        last_exc = None
        for attempt in range(self.retries):
            start = time.monotonic()
            try:
                text = self._impl.complete(system, user, tier)
                log_name = self._write(tag, system, user, text)
                if not text.strip():
                    raise LLMError("empty response")
                self._notify(tag, start, True, "", log_name)
                return text
            except Exception as exc:  # provider SDKs raise many unrelated types
                last_exc = exc
                log_name = self._write(tag, system, user, f"<<error: {exc!r}>>")
                self._notify(tag, start, False, f"{type(exc).__name__}: {exc}", log_name)
                if attempt + 1 < self.retries:
                    time.sleep(2 ** attempt * 2)
        raise LLMError(f"{self.provider} failed after {self.retries} attempts: {last_exc}") from last_exc

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

    def _write(self, tag, system, user, response) -> str:
        return self._log.write(self.provider, tag, system, user, response) if self._log else ""

    def _notify(self, tag, start, ok, error, log_name):
        if self._on_call:
            self._on_call({"provider": self.provider, "tag": tag, "seconds": round(time.monotonic() - start, 2),
                           "ok": ok, "error": error, "log": log_name})
