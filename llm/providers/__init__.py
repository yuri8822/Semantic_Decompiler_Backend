"""Provider registry — each LLM backend lives in its own file."""

PROVIDERS = ("anthropic", "xiaomi", "deepseek", "ollama", "llamacpp")

# Environment variable each cloud provider needs.
API_KEY_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "xiaomi": "XIAOMI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
}


def get_provider(name: str, ollama_model: str = None):
    key = name.lower()
    if key == "anthropic":
        from llm.providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider()
    if key == "xiaomi":
        from llm.providers.xiaomi_provider import XiaomiProvider
        return XiaomiProvider()
    if key == "deepseek":
        from llm.providers.deepseek_provider import DeepSeekProvider
        return DeepSeekProvider()
    if key == "ollama":
        from llm.providers.ollama_provider import OllamaProvider
        return OllamaProvider(model=ollama_model)
    if key == "llamacpp":
        from llm.providers.llamacpp_provider import LlamaCppProvider
        return LlamaCppProvider()
    raise ValueError(f"Unknown provider {name!r}; expected one of {PROVIDERS}")
