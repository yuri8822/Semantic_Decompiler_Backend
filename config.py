import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent

# --- Ghidra -----------------------------------------------------------------
# analyzeHeadless launcher; override per machine with the GHIDRA_HEADLESS env var.
GHIDRA_HEADLESS = os.environ.get("GHIDRA_HEADLESS", r"D:\Programs\ghidra\support\analyzeHeadless.bat")
GHIDRA_PROJECT_DIR = PROJECT_ROOT / "ghidra_project"
GHIDRA_PROJECT_NAME = "AIRecon"
GHIDRA_SCRIPT_DIR = PROJECT_ROOT / "ghidra_scripts"

# --- Workspace --------------------------------------------------------------
# Everything one binary's run produces lives in WORKSPACE_DIR/<binary stem>/:
# Ghidra IR exports per round, the knowledge base (functions/, types/,
# globals/, strings/, relationships/, knowledge.json), LLM traffic logs, and
# the reconstructed/ C++ project.
WORKSPACE_DIR = PROJECT_ROOT / "workspace"
LOG_LLM_TRAFFIC = True

# --- AI provider ------------------------------------------------------------
# "anthropic", "xiaomi", "deepseek", "ollama" or "llamacpp"
LLM_PROVIDER = "deepseek"

# Anthropic (cloud). The heavy tier does analysis, type reconstruction and
# code reconstruction; the fast tier does JSON repair.
ANTHROPIC_MODEL_HEAVY = "claude-opus-4-8"
ANTHROPIC_MODEL_FAST = "claude-sonnet-4-6"

# Xiaomi MiMo (cloud, Anthropic-compatible API) — https://platform.xiaomimomo.com
XIAOMI_BASE_URL = "https://api.xiaomimimo.com/anthropic/"
XIAOMI_MODEL = "mimo-v2.5-pro"

# DeepSeek (cloud, OpenAI-compatible API) — https://platform.deepseek.com
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-v4-pro"
# Reasoning tokens count against this too; 16384 was exhausted by reasoning
# alone on the largest Chess.exe function, leaving an empty answer.
DEEPSEEK_MAX_TOKENS = 32768

# Ollama (local) — https://ollama.com/library
OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_MODEL = "carstenuhlig/omnicoder-9b:q4_k_m"

# llama.cpp (local) — llama-server's OpenAI-compatible endpoint (see
# start_llamacpp.bat). Model-agnostic: whatever GGUF the server has loaded runs.
LLAMACPP_BASE_URL = "http://localhost:8080/v1"
LLAMACPP_MODEL = "local"  # sent in the request; llama-server ignores it
# Output cap, set to the server's own context size (start_llamacpp.bat's `-c`)
# so the only real bound on a response is the context left after the prompt.
# Thinking (THINKING switch in start_llamacpp.bat) draws from this same budget.
LLAMACPP_CONTEXT_SIZE = 49152
LLAMACPP_MAX_TOKENS = LLAMACPP_CONTEXT_SIZE

MAX_TOKENS = 16384        # Anthropic / Xiaomi / DeepSeek
OLLAMA_MAX_TOKENS = 4096
AI_TIMEOUT_SECONDS = 300
LLM_RETRIES = 3           # transient API failures (rate limits, timeouts)

# Parallel LLM calls. Functions are processed bottom-up through the call
# graph; functions on the same level run concurrently. Use 1 for local servers.
LLM_CONCURRENCY = 4

# --- Confidence gating ------------------------------------------------------
# Every discovery (function name, parameter, local, field, global, class
# layout) carries a confidence in [0, 1]:
#   >= HIGH            applied to Ghidra and the C++ output as-is
#   >= MEDIUM, < HIGH  applied, but marked TODO in Ghidra comments and C++
#   <  MEDIUM          not applied; the function is queued for another
#                      analysis pass with the improved decompilation
CONFIDENCE_HIGH = 0.85
CONFIDENCE_MEDIUM = 0.60

# --- Pipeline ---------------------------------------------------------------
# Each analysis round: Analyzer -> Type Reconstructor -> apply to Ghidra ->
# re-decompile. Round 1 analyzes every function; later rounds only revisit
# functions with low-confidence results. 1 disables re-analysis.
ANALYSIS_ROUNDS = 2

# Code Reconstructor <-> Validator fix loops.
MAX_STATIC_FIX_ROUNDS = 2    # static-check errors fed back per function
MAX_COMPILE_FIX_ROUNDS = 3   # compiler errors fed back per function

# Prompt size limits (per function).
PROMPT_MAX_DECOMPILED_CHARS = 60000   # truncating makes a faithful rewrite impossible
PROMPT_MAX_ASSEMBLY_LINES = 160
PROMPT_MAX_NEIGHBOURS = 12

# --- Compilation ------------------------------------------------------------
CXX_COMPILER = "g++"
CXX_STANDARD = "17"
CMAKE = "cmake"
COMPILE_TIMEOUT_SECONDS = 120
