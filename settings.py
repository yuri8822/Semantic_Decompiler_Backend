"""
Every tunable option, as one validated model.

Defaults live here; `settings.json` in the project root (written by the API
or by hand) overrides them; each run can override further. The JSON Schema of
`Settings` (titles, descriptions, ranges) is what a UI renders its options
form from, so documentation and validation live in exactly one place.

Objects that need settings receive them explicitly. Small helpers deep in
the pipeline (confidence tiers, grounding caps) read the active run's
settings through `current()`; the pipeline activates its settings with
`use()` and carries them into its worker threads.
"""

import json
import os
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

PROJECT_ROOT = Path(__file__).parent
SETTINGS_FILE = PROJECT_ROOT / "settings.json"

Provider = Literal["anthropic", "xiaomi", "deepseek", "ollama", "llamacpp"]
PROVIDERS = ("anthropic", "xiaomi", "deepseek", "ollama", "llamacpp")


class _Group(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# --- Ghidra ---------------------------------------------------------------------

class GhidraSettings(_Group):
    headless: str = Field(
        os.environ.get("GHIDRA_HEADLESS", r"D:\Programs\ghidra\support\analyzeHeadless.bat"),
        title="analyzeHeadless path", description="Path to Ghidra's analyzeHeadless launcher.")
    project_dir: str = Field("ghidra_project", title="Ghidra project directory",
                             description="Where the Ghidra project lives (relative paths are from the project root).")
    project_name: str = Field("AIRecon", title="Ghidra project name")
    script_dir: str = Field("ghidra_scripts", title="Ghidra script directory",
                            description="Directory holding ExportProgram.java and ApplyKnowledge.java.")


# --- LLM providers -----------------------------------------------------------------

class AnthropicSettings(_Group):
    model_heavy: str = Field("claude-opus-4-8", title="Heavy model",
                             description="Used for analysis, type reconstruction and code reconstruction.")
    model_fast: str = Field("claude-sonnet-4-6", title="Fast model", description="Used for JSON repair.")
    max_tokens: int = Field(16384, ge=256, le=200000, title="Max output tokens")


class EndpointSettings(_Group):
    base_url: str = Field(..., title="Base URL")
    model: str = Field(..., title="Model")
    max_tokens: int = Field(..., ge=256, le=1_000_000, title="Max output tokens",
                            description="Reasoning models spend part of this on reasoning before answering.")


class LLMSettings(_Group):
    provider: Provider = Field("deepseek", title="Provider", description="Default provider for every agent.")
    analyzer_provider: Optional[Provider] = Field(None, title="Analyzer provider",
                                                  description="Override the provider for the Analyzer only.")
    type_reconstructor_provider: Optional[Provider] = Field(
        None, title="Type Reconstructor provider", description="Override the provider for the Type Reconstructor only.")
    code_reconstructor_provider: Optional[Provider] = Field(
        None, title="Code Reconstructor provider", description="Override the provider for the Code Reconstructor only.")
    concurrency: int = Field(4, ge=1, le=64, title="Parallel LLM calls",
                             description="Functions on the same call-graph level run in parallel. Use 1 for local servers.")
    retries: int = Field(3, ge=1, le=10, title="Retries", description="Attempts per call on transient failures.")
    timeout_seconds: int = Field(300, ge=10, le=3600, title="Request timeout (s)")
    log_traffic: bool = Field(True, title="Log prompts and responses",
                              description="Write every prompt/response to the workspace's logs/llm/.")

    anthropic: AnthropicSettings = Field(AnthropicSettings(), title="Anthropic",
                                         description="Claude, cloud. Needs ANTHROPIC_API_KEY in .env.")
    xiaomi: EndpointSettings = Field(
        EndpointSettings(base_url="https://api.xiaomimimo.com/anthropic/", model="mimo-v2.5-pro", max_tokens=16384),
        title="Xiaomi MiMo", description="Cloud, Anthropic-compatible API. Needs XIAOMI_API_KEY in .env.")
    deepseek: EndpointSettings = Field(
        EndpointSettings(base_url="https://api.deepseek.com", model="deepseek-v4-pro", max_tokens=32768),
        title="DeepSeek", description="Cloud, OpenAI-compatible API. Needs DEEPSEEK_API_KEY in .env.")
    ollama: EndpointSettings = Field(
        EndpointSettings(base_url="http://localhost:11434/v1", model="carstenuhlig/omnicoder-9b:q4_k_m",
                         max_tokens=4096),
        title="Ollama", description="Local server, no key.")
    llamacpp: EndpointSettings = Field(
        EndpointSettings(base_url="http://localhost:8080/v1", model="local", max_tokens=49152),
        title="llama.cpp", description="Local server; the backend can launch it (see the llama.cpp server settings). "
                                       "Serves whatever model is loaded.")

    def provider_for(self, agent: str) -> str:
        return getattr(self, f"{agent}_provider", None) or self.provider


class LlamaServerSettings(_Group):
    """How the backend launches llama.cpp. It listens where llm.llamacpp.base_url points."""
    executable: str = Field("llama", title="llama.cpp executable",
                            description="`llama` (runs `llama serve`) or `llama-server`: a name on PATH or a full path.")
    model_path: str = Field("", title="Model file", description="Full path to the .gguf to serve.")
    model_dirs: list[str] = Field([], title="Extra model folders",
                                  description="Searched for .gguf files besides the HuggingFace, LM Studio and "
                                              "llama.cpp download caches.")
    context_size: int = Field(49152, ge=0, le=1_048_576, title="Context size (tokens)",
                              description="Prompt plus answer must fit. 0 = the model's own maximum.")
    gpu_layers: int = Field(999, ge=0, le=999, title="GPU layers",
                            description="Layers offloaded to the GPU: 999 = all, 0 = CPU only.")
    parallel: int = Field(1, ge=1, le=64, title="Server slots",
                          description="Requests served at once; the context is split between them.")
    thinking: Literal["off", "on", "auto"] = Field("off", title="Thinking",
                                                    description="Let reasoning models think before answering.")
    reasoning_budget: int = Field(2048, ge=-1, le=1_000_000, title="Thinking budget (tokens)",
                                  description="Only with thinking on; comes out of the max output tokens. -1 = no limit.")
    extra_args: str = Field("", title="Extra arguments", description="Passed to the server as-is, e.g. --threads 8.")
    auto_start: bool = Field(True, title="Start automatically",
                             description="When a run uses llama.cpp and no server is up, launch it and wait for "
                                         "the model to load.")
    load_timeout_seconds: int = Field(600, ge=10, le=7200, title="Load timeout (s)",
                                      description="How long a run waits for the model to load.")


# --- Pipeline stages ----------------------------------------------------------------

class ConfidenceSettings(_Group):
    high: float = Field(0.85, ge=0.0, le=1.0, title="High threshold",
                        description="At or above: applied to Ghidra and the C++ automatically.")
    medium: float = Field(0.60, ge=0.0, le=1.0, title="Medium threshold",
                          description="At or above (and below high): applied, but marked TODO. "
                                      "Below: withheld and queued for re-analysis.")

    @model_validator(mode="after")
    def _ordered(self):
        if self.medium > self.high:
            raise ValueError("the medium threshold must not exceed the high threshold")
        return self


class AnalysisSettings(_Group):
    rounds: int = Field(2, ge=1, le=10, title="Analysis rounds",
                        description="Analyze -> apply to Ghidra -> re-decompile. Rounds after the first only "
                                    "revisit low-confidence or contradicted functions.")
    apply_to_ghidra: bool = Field(True, title="Apply knowledge to Ghidra",
                                  description="Write discoveries back into Ghidra and re-decompile (the feedback loop).")
    reconstruct_types: bool = Field(True, title="Reconstruct class layouts")
    return_value_crosscheck: bool = Field(True, title="Return-value cross-check",
                                          description="Flag analyses that say void while callers use the result.")


class CodeSettings(_Group):
    enabled: bool = Field(True, title="Reconstruct code",
                          description="Off: stop after analysis (knowledge base and Ghidra only).")
    max_static_fix_rounds: int = Field(2, ge=0, le=10, title="Validator fix rounds",
                                       description="How often static-check errors are fed back per function.")
    max_compile_fix_rounds: int = Field(3, ge=0, le=10, title="Compiler fix rounds",
                                        description="How often compiler errors are fed back per function.")


class PromptSettings(_Group):
    max_decompiled_chars: int = Field(60000, ge=1000, le=1_000_000, title="Max decompilation characters",
                                      description="Longer decompilations are truncated in prompts.")
    max_assembly_lines: int = Field(160, ge=0, le=100000, title="Max assembly lines")
    max_neighbours: int = Field(12, ge=0, le=500, title="Max callers/callees listed")


class CompilerSettings(_Group):
    enabled: bool = Field(True, title="Compile validation",
                          description="Syntax-check each function with the compiler and build the project with CMake.")
    cxx: str = Field("g++", title="C++ compiler")
    cxx_standard: Literal["14", "17", "20", "23"] = Field("17", title="C++ standard")
    cmake: str = Field("cmake", title="CMake")
    timeout_seconds: int = Field(120, ge=5, le=3600, title="Compile timeout (s)")


class ScopeSettings(_Group):
    limit: int = Field(0, ge=0, title="Function limit", description="Only the first N in-scope functions (0 = all).")
    only: list[str] = Field([], title="Only these functions",
                            description="Addresses (0x...) or names; when set, nothing else is processed.")
    include: list[str] = Field([], title="Force into scope",
                               description="Addresses or names to reconstruct even if the library filter excludes them.")
    exclude: list[str] = Field([], title="Force out of scope", description="Addresses or names never to reconstruct.")


class Settings(_Group):
    workspace_dir: str = Field("workspace", title="Workspace directory",
                               description="Per-binary results (relative paths are from the project root).")
    ghidra: GhidraSettings = Field(GhidraSettings(), title="Ghidra",
                                   description="Headless analysis, and where its project lives.")
    llm: LLMSettings = Field(LLMSettings(), title="LLM providers",
                             description="Which models the agents use, and how they are called.")
    llamacpp_server: LlamaServerSettings = Field(LlamaServerSettings(), title="llama.cpp server",
                                                 description="Launching a local llama.cpp server from the backend.")
    confidence: ConfidenceSettings = Field(ConfidenceSettings(), title="Confidence gating",
                                           description="What a discovery's confidence allows.")
    analysis: AnalysisSettings = Field(AnalysisSettings(), title="Analysis",
                                       description="Analyzer rounds, class reconstruction and the Ghidra feedback loop.")
    code: CodeSettings = Field(CodeSettings(), title="Code reconstruction",
                               description="The Code Reconstructor and its fix loops with the Validator.")
    prompts: PromptSettings = Field(PromptSettings(), title="Prompt limits",
                                    description="How much of each function goes into a prompt.")
    compiler: CompilerSettings = Field(CompilerSettings(), title="Compilation",
                                       description="Compile validation and the CMake build.")
    scope: ScopeSettings = Field(ScopeSettings(), title="Scope", description="Which functions are reconstructed.")

    def path(self, value: str) -> Path:
        p = Path(value)
        return p if p.is_absolute() else PROJECT_ROOT / p

    def with_overrides(self, overrides: dict) -> "Settings":
        return Settings.model_validate(_deep_merge(self.model_dump(), overrides or {}))


def _deep_merge(base: dict, overrides: dict) -> dict:
    out = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


# --- persistence and the active run's settings ----------------------------------

def load(path: Path = SETTINGS_FILE) -> Settings:
    """Defaults overridden by settings.json, if present."""
    if Path(path).exists():
        return Settings().with_overrides(json.loads(Path(path).read_text(encoding="utf-8")))
    return Settings()


def save(settings: Settings, path: Path = SETTINGS_FILE):
    """Store only what differs from the defaults, so new defaults still reach old files."""
    diff = _diff(settings.model_dump(), Settings().model_dump())
    Path(path).write_text(json.dumps(diff, indent=2), encoding="utf-8")


def _diff(value: dict, default: dict) -> dict:
    out = {}
    for key, v in value.items():
        d = default.get(key)
        if isinstance(v, dict) and isinstance(d, dict):
            sub = _diff(v, d)
            if sub:
                out[key] = sub
        elif v != d:
            out[key] = v
    return out


_active: ContextVar[Optional[Settings]] = ContextVar("semdec_settings", default=None)
_saved_cache: dict = {}


def _saved() -> Settings:
    mtime = SETTINGS_FILE.stat().st_mtime if SETTINGS_FILE.exists() else None
    if "settings" not in _saved_cache or _saved_cache.get("mtime") != mtime:
        _saved_cache.update(mtime=mtime, settings=load())
    return _saved_cache["settings"]


def current() -> Settings:
    """The active run's settings, or the saved defaults outside a run."""
    s = _active.get()
    return s if s is not None else _saved()


@contextmanager
def use(settings: Settings):
    token = _active.set(settings)
    try:
        yield settings
    finally:
        _active.reset(token)
