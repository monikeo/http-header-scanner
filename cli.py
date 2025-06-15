"""
Command inie interface for the HTTP Header Security Scanner
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from http_header_scanner.core.scanner import HeaderScanner
from http_header_scanner.utils.export import ReportExporter
from http_header_scanner.models.findings import SecurityAnalysisReport

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="HTTP Header Security Scanner - Advanced Web Security Analysis Tool",
        epilog="Example: http_header_scanner -u https://example.com --format json"
    )

    # Target selection
    target_group = parser.add_argument_group("Target Selection")
    target_group.add_argument("-u", "--url", help="Single URL to scan")
    target_group.add_argument(
        "-i", "--input-file",
        type=Path,
        help="File containing URLs to scan (one per line)"
    )
    target_group.add_argument(
        "-b", "--batch",
        action="store_true",
        help="Enable batch mode for multiple URLs"
    )

    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    scan_group.add_argument(
        "--user-agent",
        default="SecurityScanner/1.0",
        help="Custom User-Agent string"
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-f", "--format",
        choices=["text", "json", "html", "pdf", "csv"],
        default="text",
        help="Output format (default: text)"
    )
    output_group.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file path"
    )
    output_group.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    if not args.url and not args.input_file:
        console.print("[red]Error: No target specified. Use --url or --input-file[/red]")
        sys.exit(1)

    scanner = HeaderScanner()

    if args.url:
        reports = [ scanner.scan(
            args.url,
            timeout=args.timeout,
            user_agent=args.user_agent
        )]
    elif args.input_file:
        with open(args.input_file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        reports = [
            scanner.scan(url, timeout=args.timout, user_agent=args.user_agent)
            for url in urls
        ]

    if args.format == "text":
        display_text_report(reports[0] if args.url else reports)
    elif args.format == "json":
        if args.output:
            ReportExporter.to_json(reports[0] if args.url else reports, args.output)
        else:
            console.print_json(data=reports[0] if args.url else reports)
    elif args.format == "csv" and args.output:
        if len(reports) > 1 or args.batch:
            ReportExporter.to_csv(reports, args.output)
        else:
            console.print("[red]CSV export requires multiple reports[/red]")

def display_text_report(report: SecurityAnalysisReport):
    """
    Display report in rich format text
    """
    console.print(
        Panel.fit(
            f"[bold]Security Header Analysis for {report['url']}[/bold]\n"
            f"[green]Final URL:[/green] {report['final_url']}\n"
            f"[green]Status Code:[/green] {report['status_code']}\n"
            f"[green]Overall Risk:[/green] [bold]{report['overall_risk']}[/bold]\n"
            f"[green]Total Score:[/green] {report['total_score']}",
            title="Summary",
            border_style="blue"
        )
    )

    # TLS Information
    tls = report["tls_analysis"]
    console.print(
        Panel.fit(
            f"[green]TLS Version:[/green] {tls['version']} ([bold]{tls['grade']}[/bold])\n"
            f"[green]Cipher:[/green] {tls['cipher_strength']}\n"
            f"[green]Vulnerabilities:[/green] {', '.join(tls['vulnerabilities']) or 'None'}",
            title="TLS Configuration",
            border_style="yellow"
        )
    )

    # Framework Information
    if report["framework_analysis"]:
        framework = report["framework_analysis"]
        console.print(
            Panel.fit(
                f"[green]Framework:[/green] {framework['name']} ({framework['type']})\n"
                f"[green]Version:[/green] {framework['version'] or 'Unknown'}\n"
                f"[green]Confidence:[/green] {framework['confidence']*100:.1f}%",
                title="Technology Detection",
                border_style="green"
            )
        )

    # Headers table
    if report["headers"]:
        table = Table(title="Security Header Findings", show_header=True, header_style="bold magenta")
        table.add_column("Header", style="cyan")
        table.add_column("Value", width=40)
        table.add_column("Status", justify="right")
        table.add_column("Issue", style="yellow")
        table.add_column("Score", justify="right")
        
        for finding in report["headers"]:
            status_color = {
                "Critical": "red",
                "High": "bright_red",
                "Medium": "yellow",
                "Low": "blue",
                "Pass": "green",
                "Error": "magenta"
            }.get(finding["status"], "white")
            
            table.add_row(
                finding["header"],
                finding["value"][:50] + ("..." if len(finding["value"]) > 50 else ""),
                f"[{status_color}]{finding['status']}[/{status_color}]",
                finding.get("issue", ""),
                str(finding["cvss_score"])
            )
        
        console.print(table)
    
    # CSP Analysis
    if report.get("csp_analysis"):
        csp = report["csp_analysis"]
        console.print(
            Panel.fit(
                f"[bold]Content Security Policy Analysis[/bold]\n"
                f"[green]Risk Level:[/green] {csp['risk_level']}\n"
                f"[green]Score:[/green] {csp['score']}\n"
                f"[green]Missing Directives:[/green] {', '.join(csp['missing_directives']) or 'None'}\n"
                f"[green]Unsafe Directives:[/green] {', '.join(csp['unsafe_directives']) or 'None'}",
                border_style="red"
            )
        )
        
        if csp["recommendations"]:
            console.print("[bold]Recommendations:[/bold]")
            for rec in csp["recommendations"]:
                console.print(f"• {rec}")


if __name__ == "__main__":
    main()
