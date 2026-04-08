"""Helper script to fetch tool definitions from a live MCP server.

Usage:
    uv run python scripts/fetch_mcp_tools.py http://localhost:8080 --output ./tools/

This will connect to the MCP server, list all available tools, and save each
tool definition as a separate YAML file in the output directory.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import typer
import yaml
from rich.console import Console
from rich.table import Table

app = typer.Typer()
console = Console()


def fetch_tools(endpoint: str) -> list[dict]:
    """Call the MCP tools/list endpoint and return raw tool definitions."""
    endpoint = endpoint.rstrip("/")
    
    # Try MCP JSON-RPC format first
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1,
    }
    
    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                f"{endpoint}/tools/list",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
            
            # MCP format: {"result": {"tools": [...]}}
            if "result" in data and "tools" in data["result"]:
                return data["result"]["tools"]
            
            # Fallback: direct tools list
            if "tools" in data:
                return data["tools"]
            
            console.print("[yellow]Warning: Unexpected response format[/yellow]")
            console.print(json.dumps(data, indent=2))
            return []
            
    except httpx.HTTPError as exc:
        console.print(f"[red]HTTP error: {exc}[/red]")
        return []
    except Exception as exc:
        console.print(f"[red]Connection error: {exc}[/red]")
        return []


@app.command()
def main(
    endpoint: str = typer.Argument(..., help="MCP server endpoint URL (e.g., http://localhost:8080)"),
    output: Path = typer.Option(
        Path("./mcp_tools"),
        "--output",
        "-o",
        help="Output directory for tool YAML files",
    ),
    format: str = typer.Option(
        "yaml",
        "--format",
        "-f",
        help="Output format: 'yaml' or 'json'",
    ),
) -> None:
    """Fetch tool definitions from an MCP server and save them to files."""
    
    console.print(f"[cyan]Connecting to MCP server:[/cyan] {endpoint}")
    tools = fetch_tools(endpoint)
    
    if not tools:
        console.print("[red]No tools found or connection failed.[/red]")
        console.print("\n[yellow]Make sure:[/yellow]")
        console.print("  1. The MCP server is running")
        console.print("  2. The endpoint URL is correct")
        console.print("  3. The server implements MCP tools/list method")
        sys.exit(1)
    
    console.print(f"[green]Found {len(tools)} tool(s)[/green]\n")
    
    # Display tools in a table
    table = Table(title="Available Tools")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Parameters", style="yellow")
    
    for tool in tools:
        name = tool.get("name", "unknown")
        desc = tool.get("description", "")[:60]
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        param_count = len(props)
        table.add_row(name, desc, str(param_count))
    
    console.print(table)
    
    # Save each tool to a file
    output.mkdir(parents=True, exist_ok=True)
    
    for tool in tools:
        name = tool.get("name", "unknown")
        output_file = output / f"{name}.{format}"
        
        if format == "yaml":
            with open(output_file, "w") as f:
                yaml.dump(tool, f, sort_keys=False, default_flow_style=False)
        else:
            with open(output_file, "w") as f:
                json.dump(tool, f, indent=2)
        
        console.print(f"[green]✓[/green] Saved [cyan]{name}[/cyan] → {output_file}")
    
    console.print(f"\n[green]All tools saved to:[/green] {output.absolute()}")
    console.print("\n[cyan]Next steps:[/cyan]")
    console.print(f"  1. Review the tool definitions in {output}/")
    console.print("  2. Edit config.yaml to set your API keys and agent_endpoint")
    console.print(f"  3. Run: [bold]uv run agent-hardener analyze --tool-file {output}/<tool>.yaml --config config.yaml[/bold]")


if __name__ == "__main__":
    app()
