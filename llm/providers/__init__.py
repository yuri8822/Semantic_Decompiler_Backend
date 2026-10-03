"""Provider registry — each LLM backend lives in its own file."""

import os

from settings import PROVIDERS  # noqa: F401  (re-exported)

# Environment variable each cloud provider needs.
API_KEY_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "xiaomi": "XIAOMI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
}


def missing_api_key(name: str) -> str:
    """The environment variable `name` needs but doesn't have, else ''."""
    var = API_KEY_VARS.get(name.lower())
    return var if var and not os.environ.get(var) else ""


def get_provider(name: str, llm_settings):
    key = name.lower()
    timeout = llm_settings.timeout_seconds
    if key == "anthropic":
        from llm.providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider(llm_settings.anthropic, timeout)
    if key == "xiaomi":
        from llm.providers.xiaomi_provider import XiaomiProvider
        return XiaomiProvider(llm_settings.xiaomi, timeout)
    if key == "deepseek":
        from llm.providers.deepseek_provider import DeepSeekProvider
        return DeepSeekProvider(llm_settings.deepseek, timeout)
    if key == "ollama":
        from llm.providers.ollama_provider import OllamaProvider
        return OllamaProvider(llm_settings.ollama, timeout)
    if key == "llamacpp":
        from llm.providers.llamacpp_provider import LlamaCppProvider
        return LlamaCppProvider(llm_settings.llamacpp, timeout)
    raise ValueError(f"Unknown provider {name!r}; expected one of {PROVIDERS}")
