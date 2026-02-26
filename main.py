#!/usr/bin/env python3
"""
llmguard-cli: Real-time prompt injection and jailbreak detector for LLM pipelines.

Detects adversarial prompts using multi-layer analysis:
  1. Heuristic pattern matching (20+ attack signatures)
  2. Shannon entropy and linguistic anomaly detection
  3. AI meta-reasoning (LLM-as-judge) for contextual classification

Usage:
    python main.py check "Ignore all previous instructions and..."
    echo "user input" | python main.py check -
    python main.py scan prompts.jsonl --output json
    python main.py serve --port 8080  # HTTP API mode
"""

import json
import sys
import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from src.ai_guard import analyze, analyze_batch
from src.detector import ThreatCategory

console = Console()


def _threat_color(is_threat: bool, action: str) -> str:
    if action == "block":
        return "bold red"
    elif action == "flag_for_review":
        return "bold yellow"
    elif action == "log_and_monitor":
        return "yellow"
    return "green"


@click.group()
@click.version_option("1.0.0", prog_name="llmguard-cli")
def cli():
    """llmguard-cli — Prompt injection and jailbreak detector for LLM pipelines."""
    pass


@cli.command()
@click.argument("text", default="-")
@click.option("--no-ai", is_flag=True, default=False,
              help="Use heuristics only (no AI meta-reasoning, faster).")
@click.option("--threshold", default=0.65, show_default=True,
              help="Threat detection threshold (0.0-1.0).")
@click.option("--output", default="rich",
              type=click.Choice(["rich", "json"], case_sensitive=False),
              help="Output format.")
def check(text, no_ai, threshold, output):
    """Check a single prompt for injection or jailbreak attempts.

    Pass '-' as TEXT to read from stdin.

    \b
    Examples:
        python main.py check "Ignore all previous instructions"
        echo "What is the capital of France?" | python main.py check -
        python main.py check "DAN mode enabled" --output json
    """
    if text == "-":
        text = sys.stdin.read().strip()

    if not text:
        console.print("[bold red]No input provided.[/bold red]")
        sys.exit(1)

    result = analyze(text, use_ai=not no_ai, threshold=threshold)

    if output == "json":
        print(json.dumps(result.to_dict(), indent=2))
        sys.exit(1 if result.is_threat else 0)

    # Rich output
    color = _threat_color(result.is_threat, result.recommended_action)
    status = f"[{color}]{'⚠ THREAT DETECTED' if result.is_threat else '✓ BENIGN'}[/{color}]"

    console.print(Panel(
        f"{status}\n\n"
        f"Category:    [cyan]{result.threat_category.value}[/cyan]\n"
        f"Action:      [{color}]{result.recommended_action}[/{color}]\n"
        f"Confidence:  {result.confidence:.1%}\n"
        f"Heuristic:   {result.heuristic_score:.1%}  |  AI: "
        f"{'N/A' if result.ai_score is None else f'{result.ai_score:.1%}'}",
        title="llmguard-cli Analysis",
        expand=False,
    ))

    if result.matched_patterns:
        console.print("[bold yellow]Matched Patterns:[/bold yellow]")
        for p in result.matched_patterns[:5]:
            console.print(f"  • {p}")

    if result.explanation:
        console.print(f"\n[dim]AI Reasoning: {result.explanation}[/dim]")

    sys.exit(1 if result.is_threat else 0)


@cli.command()
@click.argument("input_file")
@click.option("--text-field", default="text", show_default=True,
              help="JSON field name containing the prompt text (for JSONL input).")
@click.option("--no-ai", is_flag=True, default=False)
@click.option("--threshold", default=0.65, show_default=True)
@click.option("--output", default="table",
              type=click.Choice(["table", "json"], case_sensitive=False))
def scan(input_file, text_field, no_ai, threshold, output):
    """Scan a JSONL file or plain text file of prompts.

    \b
    Examples:
        python main.py scan prompts.jsonl --text-field content
        python main.py scan prompts.txt --output json > results.json
    """
    texts = []
    try:
        with open(input_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    texts.append(obj.get(text_field, str(obj)))
                except json.JSONDecodeError:
                    texts.append(line)
    except FileNotFoundError:
        console.print(f"[bold red]File not found: {input_file}[/bold red]")
        sys.exit(1)

    if not texts:
        console.print("[bold red]No prompts found in input file.[/bold red]")
        sys.exit(1)

    console.print(f"[dim]Scanning {len(texts)} prompts...[/dim]")
    results = analyze_batch(texts, use_ai=not no_ai, threshold=threshold)

    if output == "json":
        print(json.dumps([r.to_dict() for r in results], indent=2))
        return

    threats = [r for r in results if r.is_threat]
    table = Table(
        title=f"Scan Results — {len(threats)}/{len(results)} threats detected",
        show_header=True, header_style="bold red"
    )
    table.add_column("#", width=4, style="dim")
    table.add_column("Prompt Preview", max_width=50)
    table.add_column("Category", style="yellow")
    table.add_column("Action", width=18)
    table.add_column("Confidence", width=10)

    for i, r in enumerate(results, 1):
        color = _threat_color(r.is_threat, r.recommended_action)
        table.add_row(
            str(i),
            r.input_text[:80] + "..." if len(r.input_text) > 80 else r.input_text,
            r.threat_category.value,
            f"[{color}]{r.recommended_action}[/{color}]",
            f"{r.confidence:.1%}",
        )

    console.print(table)


@cli.command()
@click.option("--port", default=8080, show_default=True, help="Port to listen on.")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--no-ai", is_flag=True, default=False)
@click.option("--threshold", default=0.65, show_default=True)
def serve(port, host, no_ai, threshold):
    """Start an HTTP API server for real-time prompt screening.

    POST /analyze with JSON body: {"text": "..."}
    Returns: DetectionResult as JSON.

    \b
    Example:
        python main.py serve --port 8080
        curl -X POST http://localhost:8080/analyze -H "Content-Type: application/json" \\
             -d '{"text": "Ignore all previous instructions"}'
    """
    try:
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware
        from pydantic import BaseModel
        import uvicorn

        app = FastAPI(title="llmguard-cli API", version="1.0.0")
        app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

        class AnalyzeRequest(BaseModel):
            text: str
            use_ai: bool = not no_ai
            threshold: float = threshold

        @app.post("/analyze")
        def analyze_endpoint(req: AnalyzeRequest):
            result = analyze(req.text, use_ai=req.use_ai, threshold=req.threshold)
            return result.to_dict()

        @app.get("/health")
        def health():
            return {"status": "ok", "version": "1.0.0"}

        console.print(Panel(
            f"[bold green]llmguard-cli API running[/bold green]\n"
            f"http://{host}:{port}/analyze\n"
            f"AI meta-reasoning: {'disabled' if no_ai else 'enabled'}",
            expand=False
        ))
        uvicorn.run(app, host=host, port=port)

    except ImportError:
        console.print("[bold red]FastAPI/uvicorn not installed. Run: pip install fastapi uvicorn[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    cli()
