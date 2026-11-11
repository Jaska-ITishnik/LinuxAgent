#!/usr/bin/env python3
"""Rich terminal interface for the modular Ollama personal-agent runtime.

Install dependencies from requirements.txt and run with ``python agents.py``.
"""
from __future__ import annotations

import asyncio
import json
import os
import select
import sys
import time
from typing import Any

from core.config import ConfigLoadError, load_config
from core.llm_client import OllamaClient
from core.runtime import AgentRuntime, create_agent_runtime
from ollama import Client
from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from security.approval import ApprovalDecision, ApprovalRequest
from security.approval import TrustedApprovalInterface
from security.audit_logger import AuditLogError

MODEL = os.environ.get("AGENT_MODEL", "gemma4:e2b-it-qat")
HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")

console = Console()
client = Client(host=HOST, timeout=180)


def banner() -> None:
    title = Text("◆ UBUNTU AI AGENT ◆", style="bold bright_cyan", justify="center")
    details = Text(f"Local inference  ·  {MODEL}\n/help  /tools  /clear  /exit", style="bright_magenta", justify="center")
    console.print(Panel.fit(Text.assemble(title, "\n", details), border_style="bright_blue", box=box.DOUBLE, padding=(1, 3)))


def tool_table() -> None:
    table = Table(title="Available Tools", box=box.ROUNDED, border_style="cyan", header_style="bold magenta")
    table.add_column("Tool", style="bright_cyan")
    table.add_column("Category", style="white")
    if _active_runtime is None:
        table.add_row("Tools are unavailable", "runtime not initialized")
    else:
        for definition in _active_runtime.registry.list_tools():
            table.add_row(definition.name, definition.category)
    console.print(table)


def check_server() -> bool:
    try:
        response = client.list()
        models = response.get("models", []) if isinstance(response, dict) else response.models
        installed = [m.get("model", "") if isinstance(m, dict) else m.model for m in models]
        if MODEL not in installed:
            console.print(f"[yellow]Model {MODEL!r} not found in Ollama.[/yellow]")
            console.print(f"Run: [bold]ollama pull {MODEL}[/bold]")
            return False
        console.print("[green]● Ollama connected[/green]  [dim]Model available[/dim]")
        return True
    except Exception as exc:
        console.print(f"[red]Ollama connection failed:[/red] {exc}")
        console.print("[yellow]Try:[/yellow] sudo systemctl start ollama")
        return False


class RichApprovalInterface(TrustedApprovalInterface):
    """Trusted terminal-only approval source; model output is never accepted."""

    def request_approval(self, request: ApprovalRequest, timeout_seconds: float) -> ApprovalDecision:
        console.print(Panel(
            json.dumps({
                "operation": request.operation,
                "target": request.target_resource,
                "impact": request.potential_impact,
                "arguments": request.arguments,
                "approval_id": request.approval_id,
            }, ensure_ascii=False, indent=2),
            title="[bold yellow]Human approval required[/bold yellow]",
            border_style="yellow",
        ))
        console.print(f"Approve this exact operation? [y]es / [n]o / [c]ancel (expires in {timeout_seconds:.0f}s): ", end="")
        ready, _, _ = select.select([sys.stdin], [], [], timeout_seconds)
        if not ready:
            console.print("\n[yellow]Approval expired; operation denied.[/yellow]")
            return ApprovalDecision.CANCEL
        response = sys.stdin.readline().strip().lower()
        return {
            "y": ApprovalDecision.APPROVE,
            "n": ApprovalDecision.DENY,
            "c": ApprovalDecision.CANCEL,
        }.get(response, ApprovalDecision.DENY)


_active_runtime: AgentRuntime | None = None


def _show_controller_progress(phase: str, message: str) -> None:
    if phase == "tool":
        console.print(Rule(f"[cyan]{message}[/cyan]", style="bright_blue"))
    elif phase == "tool_result":
        console.print(f"[dim]{message}[/dim]")
    elif phase == "thinking":
        console.print(f"[dim]{message}[/dim]")


def _interactive_loop(runtime: AgentRuntime) -> None:
    history: list[dict[str, Any]] = []
    session_id = os.urandom(16).hex()
    while True:
        try:
            console.print()
            user = Prompt.ask("[bold bright_blue]❯ You[/bold bright_blue]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[cyan]Goodbye![/cyan]")
            break
        if not user:
            continue
        cmd = user.lower()
        if cmd in {"exit", "quit", "/exit", "/quit"}:
            console.print("[cyan]Goodbye![/cyan]")
            break
        if cmd == "/help":
            console.print("[cyan]/tools[/cyan] list tools  •  [cyan]/clear[/cyan] clear chat  •  [cyan]/exit[/cyan] quit")
            continue
        if cmd == "/tools":
            tool_table()
            continue
        if cmd == "/clear":
            history.clear()
            console.clear()
            banner()
            continue
        started = time.monotonic()
        try:
            result = asyncio.run(runtime.controller.run(
                user,
                history=history,
                session_id=session_id,
                on_progress=_show_controller_progress,
            ))
            answer, count = result.answer, result.tool_calls
            console.print(Panel(
                Markdown(answer),
                title="[bold green]✦ Agent response[/bold green]",
                border_style="green" if not result.error_code else "yellow",
            ))
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. No further steps will run.[/yellow]")
            continue
        except Exception:
            console.print(Panel("The request could not be completed.", title="[red]Agent error[/red]", border_style="red"))
            continue
        history += [{"role": "user", "content": user}, {"role": "assistant", "content": answer}]
        elapsed = time.monotonic() - started
        console.print(f"[dim]◷ {elapsed:.1f}s  ·  ⚙ {count} tool call(s)  ·  {MODEL}[/dim]")


def main() -> None:
    global MODEL, HOST, client, _active_runtime
    try:
        config = load_config()
    except ConfigLoadError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(2)
    MODEL = config.ollama.model
    HOST = config.ollama.host
    client = Client(host=HOST, timeout=config.ollama.timeout)
    banner()
    if not check_server():
        sys.exit(1)
    try:
        runtime = create_agent_runtime(
            config,
            approval_interface=RichApprovalInterface(),
            llm_client=OllamaClient(config.ollama, client=client),
        )
    except (AuditLogError, OSError, ValueError) as exc:
        console.print(f"[red]Agent startup error:[/red] {exc}")
        sys.exit(2)
    _active_runtime = runtime
    try:
        _interactive_loop(runtime)
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
