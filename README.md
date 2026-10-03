# Semantic Decompiler

Binary in, readable and compilable C++ project out.

The design rule: **the LLM is not the decompiler.** Ghidra stays the source of truth for
machine-level behaviour. LLM agents are the semantic layer on top: they name things, recover
types and classes, and rewrite pseudocode as idiomatic C++. Everything an agent claims is
checked against Ghidra's facts. Discoveries go back into Ghidra, so its own decompiler output
improves from round to round.

```
EXE ─► Ghidra headless import + auto-analysis ─► IR export (round 0)
      ┌─────────────────────────────────────────────────────────────────┐
      │ round r   Analyzer           understands each function           │
      │           Type Reconstructor builds class layouts                │
      │           confidence gate ─► ApplyKnowledge.java ─► re-decompile │
      │           low-confidence functions are queued for round r+1      │
      └─────────────────────────────────────────────────────────────────┘
      ─► Code Reconstructor ◄──► Validator (static checks + g++)
      ─► reconstructed/ (include/, src/, CMakeLists.txt) ─► CMake build ─► report.md
```

## Quick start

```
pip install -r requirements.txt
copy .env.example .env          # add the API key for your provider
python main.py TestBinaries\Chess.exe --provider deepseek
```

Requirements: Ghidra 11.x (set `GHIDRA_HEADLESS` or edit `config.py`), Java 21+, and
`g++` + `cmake` on PATH for compile validation. Without a compiler, compile validation is
skipped.

| Flag | Meaning |
|---|---|
| `--provider` | `anthropic`, `xiaomi`, `deepseek`, `ollama`, `llamacpp` |
| `--restart` | discard this binary's workspace and start over (otherwise a rerun **resumes**) |
| `--limit N` | process only the first N in-scope functions |
| `--rounds N` | analysis → apply → re-decompile rounds (default 2) |
| `--no-ghidra-apply` | turn off the Ghidra feedback loop |
| `--no-compile` | skip compiler validation and the CMake build |
| `--concurrency N` | parallel LLM calls (use 1 for local servers) |

## The pieces

**Ghidra IR** (`ghidra_scripts/ExportProgram.java`, `ghidra_io/`). For every function the
export holds the decompilation, assembly, callers and callees by address, imports, strings,
globals, parameters, locals and types. It also records two facts derived from p-code data flow:
- **field accesses**: every load/store through `parameter + constant`, with access size.
- **pointer passing**: `parameter + constant` passed as a call argument. This is how embedded
  member objects and shared object types show up.

These proven facts are what the agents' claims are checked against.

**The four specialists** (`agents/`), all reading and writing the same knowledge base:

| Agent | Input | Output |
|---|---|---|
| Analyzer (LLM) | one function plus its neighbours | semantic annotation: name, class, parameter/local/global names and types, fields, evidence, a confidence for each. **No code.** |
| Type Reconstructor (LLM) | every function touching one class: proven offsets, per-function guesses, pointer passing, allocation sites | class layout: fields, size, base class |
| Code Reconstructor (LLM) | improved decompilation, assembly, class layout, exact signature, callee signatures | one C++ function definition |
| Validator (deterministic) | reconstruction vs. Ghidra's facts | issues, which are fed back for fixes |

Each LLM answer is **grounded** before it is stored:
- Fields at offsets that were never accessed are dropped.
- Types whose size contradicts the observed access size are demoted below the apply threshold.
- Guesses about parameters, locals or globals that don't exist are discarded.
- Names that come from program symbols are never overridden.

**Confidence gating** (`knowledge/confidence.py`, thresholds in `config.py`):

| Confidence | Effect |
|---|---|
| ≥ 0.85 high | applied to Ghidra and the C++ automatically |
| ≥ 0.60 medium | applied, but marked `TODO` in Ghidra plate/field comments and in the C++ |
| < 0.60 low | not applied; the function is re-analyzed next round with the improved decompilation |

**Feedback loop** (`knowledge/ghidra_plan.py`, `ghidra_scripts/ApplyKnowledge.java`). Each
round, accepted knowledge goes into a plan that Ghidra applies headlessly:
- class namespaces and structures
- function names and `__thiscall`
- parameter, local and global names and types
- return types and comments

Then the program is re-exported. Once types are applied, `*(int *)(this + 0x14)` decompiles as
`this->moves`, which makes the next analysis and the code reconstruction easier.

**Validation**:
- *Static checks* (`agents/validator.py`): the definition matches the required signature
  (name, parameter count, return type) and the return semantics. Every program function the
  binary calls is still called. Decision-point count stays close to Ghidra's (catches dropped
  branches). Proven field accesses use the declared field names. Globals and string literals are
  present. No decompiler residue (`param_1`, `DAT_…`, `CONCAT44`) is left.
- *Compilation* (`output/compiler.py`): each function is syntax-checked with g++ against the
  generated headers, and compiler errors are fed back to the Code Reconstructor. Then the whole
  project is built with CMake.
- Fix loops are bounded (`MAX_STATIC_FIX_ROUNDS`, `MAX_COMPILE_FIX_ROUNDS`). A function that
  still fails to compile ships inside `#if 0` with the reason. It is listed in `report.md`, never
  silently dropped.

**Headers** (`output/project.py`) are generated from the knowledge base by code, never by the
LLM. Class layouts use explicit padding under `#pragma pack(1)`, so the recovered offsets are
exact. Type names the knowledge base can't define become opaque placeholder structs, so the
headers always compile.

## Workspace layout

Everything for one binary lives in `workspace/<binary>/`:

```
knowledge.json          run metadata, Ghidra rounds, final name map
functions/<addr>.json   analysis (with confidence and evidence), C++, validation, compile status
types/<Class>.json      reconstructed layouts
globals/<addr>.json     recovered global names and types
strings/strings.json    program strings and who references them
relationships/          calls, field accesses, pointer passing, class membership
ghidra/                 round_N.json IR exports, plan_N.json, report_N.json
logs/llm/               every prompt and response
reconstructed/          the C++ project (include/, src/, CMakeLists.txt, build.log)
report.md               summary, per-function status, things that need a human
```

## Scope (V1)

Not yet implemented:
- vtable detection, virtual-function grouping and class-hierarchy inference. Observed vtable
  pointers become an explicit `vftable` field, and methods are declared non-virtual so the
  layout stays exact.
- Automatic merging of types that the Type Reconstructor reports as `same_as`. These are
  listed in the report instead.

Out of scope: library and runtime code (the C runtime, `std::` internals, toolchain startup).
It is detected by `knowledge/filters.py` and never sent to an LLM.

## Tests

```
python -m pytest tests
```

The tests run against a real Ghidra export of `Chess.exe` (`tests/fixtures/`). They include an
offline end-to-end run of the whole pipeline with a fake LLM and real `g++`.
