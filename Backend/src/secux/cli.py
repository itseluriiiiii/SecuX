import click
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from secux.Log_Analysis_Agent import LogAnalysisAgent
from secux.Authentication_Agent import AuthenticationAgent
from secux.Network_Monitoring_Agent import NetworkMonitoringAgent
from secux.Vulnerability_Analysis_Agent import VulnerabilityAnalysisAgent
from secux.Super_Agent import SuperAgent
from secux.config import get_system_config, get_available_log_files, format_timestamp


@click.group()
@click.version_option(version="0.1.0")
def cli():
    pass


@cli.command("logscan")
@click.option(
    "--timeframe",
    "-t",
    type=int,
    default=24,
    help="Timeframe to analyze in hours (default: 24)"
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW",
    help="Minimum severity threshold for findings (default: LOW)"
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Output file path (default: secux_logscan_YYYYMMDD_HHMMSS.json)"
)
@click.option(
    "--append",
    "-a",
    is_flag=True,
    default=False,
    help="Append to existing output file"
)
@click.option(
    "--monitor",
    "-m",
    is_flag=True,
    default=False,
    help="Enable continuous monitoring mode"
)
@click.option(
    "--interval",
    "-i",
    type=int,
    default=60,
    help="Monitoring interval in seconds (default: 60)"
)
@click.option(
    "--paths",
    "-p",
    multiple=True,
    type=click.Path(exists=True),
    help="Specific log file paths to analyze"
)
@click.option(
    "--no-summary",
    is_flag=True,
    default=False,
    help="Suppress summary output"
)
@click.option(
    "--list-logs",
    is_flag=True,
    default=False,
    help="List available log files for this system"
)
def logscan(
    timeframe: int,
    severity: str,
    output: Path,
    append: bool,
    monitor: bool,
    interval: int,
    paths: tuple,
    no_summary: bool,
    list_logs: bool
):
    if list_logs:
        list_available_logs()
        return
    
    if not output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = Path(f"secux_logscan_{timestamp}.json")
    
    if monitor:
        run_monitoring(
            timeframe=timeframe,
            severity=severity,
            output=output,
            append=append,
            interval=interval,
            paths=list(paths) if paths else None
        )
    else:
        run_single_scan(
            timeframe=timeframe,
            severity=severity,
            output=output,
            append=append,
            paths=list(paths) if paths else None,
            show_summary=not no_summary
        )


def list_available_logs():
    config = get_system_config()
    available = get_available_log_files(config)
    
    click.echo(f"\nAvailable log files on {config.hostname} ({config.os}):\n")
    
    for log in available:
        status_icon = "[OK]" if log["status"] == "success" else "[FAIL]"
        
        click.echo(f"  {status_icon} {log['name']}")
        click.echo(f"      Path: {log['path']}")
        if log["status"] == "success":
            click.echo(f"      Size: {log['size']} bytes")
            click.echo(f"      Modified: {format_timestamp(log['modified'])}")
        else:
            click.echo(f"      Status: {log.get('error', 'unknown')}")
        click.echo()


def run_single_scan(
    timeframe: int,
    severity: str,
    output: Path,
    append: bool,
    paths: list,
    show_summary: bool
):
    try:
        agent = LogAnalysisAgent(
            timeframe_hours=timeframe,
            severity_threshold=severity
        )
        
        result = agent.run(
            log_paths=paths,
            output_file=output,
            append=append,
            show_summary=show_summary
        )
        
        if show_summary and output:
            click.echo(f"\n[green]Results saved to:[/green] {output.absolute()}")
        
    except Exception as e:
        click.echo(f"[red]Error during analysis:[/red] {str(e)}", err=True)
        sys.exit(1)


def run_monitoring(
    timeframe: int,
    severity: str,
    output: Path,
    append: bool,
    interval: int,
    paths: list
):
    from rich.console import Console
    from rich.live import Live
    from rich.spinner import Spinner
    
    console = Console()
    
    console.print(f"[cyan]Starting continuous monitoring mode...[/cyan]")
    console.print(f"[cyan]Interval:[/cyan] {interval}s")
    console.print(f"[cyan]Timeframe:[/cyan] {timeframe}h")
    console.print(f"[cyan]Output:[/cyan] {output}")
    console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
    
    last_scan = datetime.now(timezone.utc)
    agent = LogAnalysisAgent(
        timeframe_hours=timeframe,
        severity_threshold=severity
    )
    
    try:
        while True:
            with console.status(f"[cyan]Scanning logs...[/cyan]") as status:
                result = agent.run_incremental(
                    log_paths=paths,
                    since=last_scan
                )
                
                new_entries, new_findings = result
                
                if new_entries or new_findings:
                    console.print(f"\n[green]New events detected:[/green] {len(new_entries)}")
                    console.print(f"[yellow]New findings:[/yellow] {len(new_findings)}")
                    
                    for finding in new_findings[:3]:
                        console.print(f"  - [{finding.severity}] {finding.description[:70]}")
                    
                    full_result = agent.run(
                        log_paths=paths,
                        output_file=output,
                        append=True,
                        show_summary=False
                    )
                    
                    with open(output, 'w', encoding='utf-8') as f:
                        import json
                        json.dump(full_result, f, indent=2, default=str)
                    
                    console.print(f"[dim]Updated: {output}[/dim]")
                
                last_scan = datetime.now(timezone.utc)
            
            import time
            time.sleep(interval)
            
    except KeyboardInterrupt:
        console.print("\n[cyan]Monitoring stopped.[/cyan]")


@cli.command("audit")
@click.option(
    "--timeframe",
    "-t",
    type=int,
    default=24,
    help="Timeframe to analyze in hours (default: 24)"
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW",
    help="Minimum severity threshold for report (default: LOW)"
)
def audit(timeframe: int, severity: str):
    """Run a full multi-agent security audit and super-agent summary."""
    run_full_audit(timeframe, severity)


@cli.command("auth-scan")
@click.argument("data")
def auth_scan(data: str):
    """Run targeted authentication intelligence on specific data."""
    agent = AuthenticationAgent()
    click.echo(agent.analyze(data))


@cli.command("network-scan")
@click.argument("data")
def network_scan(data: str):
    """Run targeted network pattern analysis on specific data."""
    agent = NetworkMonitoringAgent()
    click.echo(agent.analyze(data))


@cli.command("vuln-scan")
@click.argument("data")
def vuln_scan(data: str):
    """Run targeted vulnerability assessment on specific data."""
    agent = VulnerabilityAnalysisAgent()
    click.echo(agent.analyze(data))


def run_full_audit(timeframe: int, severity_threshold: str):
    from rich.console import Console
    from rich.status import Status
    from concurrent.futures import ThreadPoolExecutor
    
    console = Console()
    console.print("\n[bold cyan]>>> Initializing Fast Parallel Multi-Agent Security Audit[/bold cyan]")
    console.print(f"[dim]Timeframe: {timeframe}h | Threshold: {severity_threshold}[/dim]\n")

    # PHASE 1: Base Log Analysis (Sequential)
    with console.status("[bold yellow]Phase 1: Running Base Log Analysis...[/bold yellow]") as status:
        log_agent = LogAnalysisAgent(timeframe_hours=timeframe, severity_threshold=severity_threshold)
        log_results = log_agent.run(show_summary=False)
        console.print("[green]OK[/green] Log Analysis Complete")

    # PHASE 2: Parallel AI Analysis (Concurrent)
    console.print("[bold yellow]Phase 2: Launching Parallel AI Analysts (Auth, Network, Vuln)...[/bold yellow]")
    
    # Prepare data for agents
    auth_context = str(log_results.get("findings", []))[:2000]
    net_context = str(log_results.get("system_info", {}))[:2000]
    vuln_context = f"OS: {log_results.get('system_info', {}).get('os')}, Logs: {len(log_results.get('system_info', {}).get('logs_accessed', []))}"

    def run_agent(agent_class, context):
        agent = agent_class()
        return agent.analyze(context)

    with ThreadPoolExecutor(max_workers=3) as executor:
        # Submit all tasks
        future_auth = executor.submit(run_agent, AuthenticationAgent, auth_context)
        future_net = executor.submit(run_agent, NetworkMonitoringAgent, net_context)
        future_vuln = executor.submit(run_agent, VulnerabilityAnalysisAgent, vuln_context)
        
        # Wait for results
        with console.status("[bold blue]Waiting for concurrent AI results...[/bold blue]"):
            auth_results = future_auth.result()
            console.print("  [blue]├─[/blue] Authentication Intelligence: [green]OK[/green]")
            
            net_results = future_net.result()
            console.print("  [blue]├─[/blue] Network Patterns: [green]OK[/green]")
            
            vuln_results = future_vuln.result()
            console.print("  [blue]└─[/blue] Vulnerability Assessment: [green]OK[/green]")

    # PHASE 3: Super Agent Correlation (Sequential)
    with console.status("[bold purple]Phase 3: Super Agent Correlation & Interpretation...[/bold purple]") as status:
        super_agent = SuperAgent()
        
        summary_context = {
            "log_analysis": {
                "total_findings": len(log_results.get("findings", [])),
                "top_findings": [f.get("description") for f in log_results.get("findings", [])[:5]]
            },
            "auth_intelligence": auth_results[:1000] if auth_results else "No significant findings",
            "network_patterns": net_results[:1000] if net_results else "No unusual patterns",
            "vulnerabilities": vuln_results[:1000] if vuln_results else "No critical weaknesses"
        }
        
        final_report = super_agent.analyze(str(summary_context))
        console.print("[green]OK[/green] Full Audit Process Complete\n")

    console.print(final_report)

@cli.command("help")
def help_cmd():
    click.echo("""
SecuX Log Analysis Agent
========================

Usage:
  secux logscan [OPTIONS]

Commands:
  logscan      Analyze system logs for security anomalies
  audit        Run a full multi-agent audit with AI orchestration
  auth-scan    Run standalone authentication intelligence
  network-scan Run standalone network pattern analysis
  vuln-scan    Run standalone vulnerability assessment
  help         Show this help message

Logscan Options:
  -t, --timeframe HOURS      Timeframe to analyze (default: 24)
  -s, --severity LEVEL       Minimum severity: LOW, MEDIUM, HIGH, CRITICAL
  -o, --output PATH          Output file path
  -a, --append               Append to existing output file
  -m, --monitor              Enable continuous monitoring
  -i, --interval SECONDS     Monitoring interval (default: 60)
  -p, --paths PATH           Specific log file paths
  --no-summary               Suppress summary output
  --list-logs                List available log files

Audit Options:
  -t, --timeframe HOURS      Timeframe to analyze (default: 24)
  -s, --severity LEVEL       Minimum severity threshold

Examples:
  secux logscan                          Analyze last 24 hours
  secux logscan --timeframe 48           Analyze last 48 hours
  secux logscan --severity HIGH          Show only HIGH+ findings
  secux logscan --output report.json     Save to file
  secux logscan --monitor                Continuous monitoring
  secux logscan --list-logs              Show available logs
""")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "help":
        help_cmd()
    else:
        cli()


if __name__ == "__main__":
    main()
