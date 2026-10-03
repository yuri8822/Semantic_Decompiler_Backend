"""
Semantic Decompiler — binary -> readable, compilable C++ project.

Ghidra is the source of truth for machine-level behaviour; LLM agents are
the semantic reconstruction layer on top of it. See README.md.

Usage:
    python main.py <binary> [options]
"""

import argparse
import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from rich.console import Console
from rich.panel import Panel

from config import ANALYSIS_ROUNDS, LLM_CONCURRENCY, LLM_PROVIDER, OLLAMA_MODEL, WORKSPACE_DIR
from ghidra_io.runner import GhidraError
from llm.providers import API_KEY_VARS, PROVIDERS
from pipeline import Pipeline

console = Console()


def main():
    parser = argparse.ArgumentParser(description="AI-assisted semantic decompiler: binary -> C++ project")
    parser.add_argument("binary", help="path to the executable to reconstruct")
    parser.add_argument("--provider", default=LLM_PROVIDER, choices=PROVIDERS,
                        help=f"LLM provider (default: {LLM_PROVIDER})")
    parser.add_argument("--ollama-model", default=OLLAMA_MODEL, metavar="MODEL",
                        help="model name for --provider ollama")
    parser.add_argument("--restart", action="store_true",
                        help="discard this binary's workspace (knowledge base, Ghidra exports, output) and start over")
    parser.add_argument("--limit", type=int, default=0, metavar="N",
                        help="only process the first N in-scope functions (0 = all)")
    parser.add_argument("--rounds", type=int, default=ANALYSIS_ROUNDS, metavar="N",
                        help=f"analysis rounds: analyze -> apply to Ghidra -> re-decompile (default: {ANALYSIS_ROUNDS})")
    parser.add_argument("--no-ghidra-apply", action="store_true",
                        help="don't write discoveries back into Ghidra (disables the re-decompile feedback loop)")
    parser.add_argument("--no-compile", action="store_true", help="skip compiler validation and the CMake build")
    parser.add_argument("--concurrency", type=int, default=LLM_CONCURRENCY, metavar="N",
                        help=f"parallel LLM calls (default: {LLM_CONCURRENCY}; use 1 for local servers)")
    parser.add_argument("--workspace", default=str(WORKSPACE_DIR), help="workspace root directory")
    parser.add_argument("--verbose", action="store_true", help="stream Ghidra's output")
    args = parser.parse_args()

    key_var = API_KEY_VARS.get(args.provider)
    if key_var and not os.environ.get(key_var):
        console.print(f"[bold red]ERROR:[/bold red] {key_var} is not set. Add it to .env: {key_var}=...")
        sys.exit(1)

    binary = Path(args.binary)
    console.print(Panel(
        f"[bold]Binary:[/bold] {binary}\n[bold]Provider:[/bold] {args.provider}\n"
        f"[bold]Workspace:[/bold] {Path(args.workspace) / binary.stem}",
        title="[bold cyan]Semantic Decompiler[/bold cyan]", expand=False,
    ))

    pipeline = Pipeline(
        binary, args.provider, ollama_model=args.ollama_model, restart=args.restart, limit=args.limit,
        rounds=args.rounds, apply_to_ghidra=not args.no_ghidra_apply, compile_check=not args.no_compile,
        concurrency=args.concurrency, verbose=args.verbose, workspace=Path(args.workspace), console=console,
    )
    try:
        pipeline.run()
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)
    except GhidraError as exc:
        console.print(f"[bold red]Ghidra failed:[/bold red]\n{exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — progress is saved; rerun the same command to resume.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
