"""Renders pipeline events (see pipeline.py) on the terminal with rich."""

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

_STAGE_LABELS = {
    "ghidra": "Ghidra", "scope": "Scope", "analysis": "Analyzer", "types": "Type Reconstructor",
    "apply": "Ghidra apply", "code": "Code Reconstructor", "project": "Project",
}


class ConsoleReporter:
    def __init__(self, console: Console = None, verbose: bool = False):
        self.console = console or Console()
        self.verbose = verbose
        self._progress = None
        self._task = None

    def __call__(self, event: dict):
        handler = getattr(self, "_on_" + event["type"], None)
        if handler:
            handler(event)

    def _stop_progress(self):
        if self._progress is not None:
            self._progress.stop()
            self._progress, self._task = None, None

    def _on_stage(self, e):
        self._stop_progress()
        self.console.print(f"\n[bold]{e['title']}[/bold]")

    def _on_progress(self, e):
        if self._progress is None:
            self._progress = Progress(SpinnerColumn(), TextColumn("{task.description:<28}"), BarColumn(),
                                      MofNCompleteColumn(), TimeElapsedColumn(), console=self.console)
            self._progress.start()
            self._task = self._progress.add_task(_STAGE_LABELS.get(e["stage"], e["stage"]), total=e["total"])
        self._progress.update(self._task, completed=e["done"])
        if not e["ok"]:
            self._progress.console.print(f"  [yellow]![/yellow] {e['item']}: {e['error'][:200]}")
        if e["done"] >= e["total"]:
            self._stop_progress()

    def _on_message(self, e):
        style = {"warning": "[yellow]![/yellow] ", "error": "[red]✗[/red] "}.get(e["level"], "  ")
        target = self._progress.console if self._progress else self.console
        target.print(f"  {style}{e['text']}")

    def _on_stage_done(self, e):
        self._stop_progress()
        s = e["summary"]
        parts = [f"{k.replace('_', ' ')} {v}" for k, v in s.items() if not isinstance(v, (dict, list))]
        if parts:
            self.console.print("  [green]✓[/green] " + ", ".join(parts))

    def _on_ghidra_output(self, e):
        if self.verbose:
            self.console.print(f"  [dim]{e['line']}[/dim]", highlight=False)

    def _on_run_finished(self, e):
        self._stop_progress()
        if e["status"] == "done":
            s = e["summary"]
            t = s["name_confidence"]
            self.console.print(
                f"\n[bold green]Done.[/bold green] {s['reconstructed']}/{s['functions']} functions reconstructed — "
                f"names: {t['high']} high / {t['medium']} medium / {t['low']} low confidence; compile: "
                f"{s['compile_ok']} ok, {s['compile_errors']} failing; {s['validator_errors']} with unresolved "
                f"validator errors; project build: {s['build']}")
            self.console.print(f"  project: [bold]{s['project']}[/bold]")
            self.console.print(f"  report:  [bold]{s['report']}[/bold]")
        elif e["status"] == "cancelled":
            self.console.print("\n[yellow]Cancelled — progress is saved; run again to resume.[/yellow]")
        else:
            self.console.print(f"\n[bold red]Failed:[/bold red] {e['error']}")
