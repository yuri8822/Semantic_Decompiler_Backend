"""
Semantic Decompiler — binary -> readable, compilable C++ project.

Ghidra is the source of truth for machine-level behaviour; LLM agents are
the semantic reconstruction layer on top of it. See README.md.

Usage:
    python main.py <binary> [options]       run from the command line
    python serve.py                         run the HTTP API instead

Options default to settings.json (see settings.py); flags override them.
"""

import argparse
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from rich.console import Console
from rich.panel import Panel

import settings as settings_mod
from ghidra_io.runner import GhidraError
from pipeline import Cancelled, ConfigurationError, Pipeline
from reporting import ConsoleReporter
from settings import PROVIDERS

console = Console()


def overrides_from_args(args) -> dict:
    o = {}

    def put(path, value):
        node = o
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = value

    if args.provider:
        put(("llm", "provider"), args.provider)
    if args.ollama_model:
        put(("llm", "ollama", "model"), args.ollama_model)
    if args.concurrency:
        put(("llm", "concurrency"), args.concurrency)
    if args.rounds:
        put(("analysis", "rounds"), args.rounds)
    if args.no_ghidra_apply:
        put(("analysis", "apply_to_ghidra"), False)
    if args.no_compile:
        put(("compiler", "enabled"), False)
    if args.limit is not None:
        put(("scope", "limit"), args.limit)
    if args.only:
        put(("scope", "only"), args.only)
    if args.workspace:
        put(("workspace_dir",), args.workspace)
    return o


def main():
    defaults = settings_mod.load()
    parser = argparse.ArgumentParser(description="AI-assisted semantic decompiler: binary -> C++ project")
    parser.add_argument("binary", help="path to the executable to reconstruct")
    parser.add_argument("--provider", choices=PROVIDERS, help=f"LLM provider (default: {defaults.llm.provider})")
    parser.add_argument("--ollama-model", metavar="MODEL", help="model name for --provider ollama")
    parser.add_argument("--restart", action="store_true",
                        help="discard this binary's workspace (knowledge base, Ghidra exports, output) and start over")
    parser.add_argument("--limit", type=int, metavar="N", help="only process the first N in-scope functions (0 = all)")
    parser.add_argument("--only", nargs="+", metavar="FUNC", help="only these functions (addresses or names)")
    parser.add_argument("--rounds", type=int, metavar="N",
                        help=f"analysis rounds (default: {defaults.analysis.rounds})")
    parser.add_argument("--no-ghidra-apply", action="store_true",
                        help="don't write discoveries back into Ghidra (disables the re-decompile feedback loop)")
    parser.add_argument("--no-compile", action="store_true", help="skip compiler validation and the CMake build")
    parser.add_argument("--concurrency", type=int, metavar="N",
                        help=f"parallel LLM calls (default: {defaults.llm.concurrency}; use 1 for local servers)")
    parser.add_argument("--workspace", help="workspace root directory")
    parser.add_argument("--verbose", action="store_true", help="stream Ghidra's output")
    args = parser.parse_args()

    try:
        run_settings = defaults.with_overrides(overrides_from_args(args))
    except ValueError as exc:
        console.print(f"[bold red]Invalid settings:[/bold red] {exc}")
        sys.exit(2)

    binary = Path(args.binary)
    console.print(Panel(
        f"[bold]Binary:[/bold] {binary}\n[bold]Provider:[/bold] {run_settings.llm.provider}\n"
        f"[bold]Workspace:[/bold] {run_settings.path(run_settings.workspace_dir) / binary.stem}",
        title="[bold cyan]Semantic Decompiler[/bold cyan]", expand=False,
    ))

    try:
        pipeline = Pipeline(binary, run_settings, restart=args.restart,
                            on_event=ConsoleReporter(console, verbose=args.verbose))
    except ConfigurationError as exc:
        console.print(f"[bold red]ERROR:[/bold red] {exc}")
        sys.exit(1)
    try:
        pipeline.run()
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)
    except GhidraError as exc:
        console.print(f"[bold red]Ghidra failed:[/bold red]\n{exc}")
        sys.exit(1)
    except (KeyboardInterrupt, Cancelled):
        console.print("\n[yellow]Interrupted — progress is saved; rerun the same command to resume.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
