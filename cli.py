"""
Command line interface for the HTTP Header Security Scanner
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.box import SIMPLE_HEAVY
from rich.text import Text

from http_header_scanner.core.scanner import HeaderScanner
from http_header_scanner.utils.export import ReportExporter
from http_header_scanner.models.findings import SecurityAnalysisReport, RiskLevel
from http_header_scanner.models.headers import SECURITY_HEADERS

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
    scan_group.add_argument(
        "--hide-sensitive",
        action="store_true",
        help="Hide server/version information in output"
    )
    scan_group.add_argument(
        "--full",
        action="store_true",
        help="Show full header values (not truncated)"
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

    try:
        if args.url:
            reports = [scanner.scan(
                args.url,
                timeout=args.timeout,
                user_agent=args.user_agent
            )]
        elif args.input_file:
            if not args.input_file.exists():
                console.print(f"[red]Error: Input file not found: {args.input_file}[/red]")
                sys.exit(1)
                
            with open(args.input_file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
                
            if not urls:
                console.print("[red]Error: No valid URLs found in input file[/red]")
                sys.exit(1)
                
            reports = []
            for url in urls:
                if args.verbose:
                    console.print(f"[yellow]Scanning: {url}[/yellow]")
                reports.append(scanner.scan(url, timeout=args.timeout, user_agent=args.user_agent))
    except Exception as e:
        console.print(f"[red]Error during scanning: {str(e)}[/red]")
        sys.exit(1)

    if args.format == "text":
        if args.url:
            display_text_report(reports[0], args)
        else:
            for i, report in enumerate(reports):
                display_text_report(report, args)
                if i < len(reports) - 1:
                    console.print("\n" + "="*80 + "\n")
    elif args.format == "json":
        if args.output:
            ReportExporter.to_json(reports[0] if args.url else reports, args.output)
            console.print(f"[green]JSON report saved to: {args.output}[/green]")
        else:
            console.print_json(data=reports[0] if args.url else reports)
    elif args.format == "csv" and args.output:
        if len(reports) > 1 or args.batch:
            ReportExporter.to_csv(reports, args.output)
            console.print(f"[green]CSV report saved to: {args.output}[/green]")
        else:
            console.print("[red]CSV export requires multiple reports (use --batch with single URL or --input-file)[/red]")
    elif args.format == "pdf" and args.output:
        if len(reports) == 1:
            ReportExporter.to_pdf(reports[0], args.output)
            console.print(f"[green]PDF report saved to: {args.output}[/green]")
        else:
            console.print("[red]PDF export currently supports single reports only[/red]")
    elif args.format == "html" and args.output:
        console.print("[yellow]HTML export is not implemented yet[/yellow]")

def display_text_report(report: SecurityAnalysisReport, args: argparse.Namespace):
    """Display report in rich formatted text with enhanced security"""
    # Get severity counts for summary
    severity_counts = {
        RiskLevel.CRITICAL.name: 0,
        RiskLevel.HIGH.name: 0,
        RiskLevel.MEDIUM.name: 0,
        RiskLevel.LOW.name: 0,
        RiskLevel.PASS.name: 0,
        RiskLevel.INFO.name: 0
    }
    
    for finding in report["headers"]:
        status_name = finding["status"].name
        if status_name in severity_counts:
            severity_counts[status_name] += 1
    
    # Summary panel with vulnerability counts
    summary_panel = Panel.fit(
        f"[bold]Security Assessment for: [cyan]{report['url']}[/cyan][/bold]\n"
        f"[green]Final URL:[/green] {report['final_url']}\n"
        f"[green]Status Code:[/green] {report['status_code']}\n"
        f"[green]Scan Date:[/green] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"[bold]Risk Summary:[/bold]\n"
        f"  [red]Critical:[/red] {severity_counts[RiskLevel.CRITICAL.name]}  "
        f"[bright_red]High:[/bright_red] {severity_counts[RiskLevel.HIGH.name]}  "
        f"[yellow]Medium:[/yellow] {severity_counts[RiskLevel.MEDIUM.name]}  "
        f"[blue]Low:[/blue] {severity_counts[RiskLevel.LOW.name]}  "
        f"[green]Pass:[/green] {severity_counts[RiskLevel.PASS.name]}\n"
        f"[bold]Overall Risk:[/bold] [bold]{report['overall_risk'].name}[/bold]  "
        f"[bold]Total Score:[/bold] [yellow]{report['total_score']}[/yellow]",
        title="Assessment Summary",
        border_style="blue",
        padding=(1, 2)
    )
    console.print(summary_panel)

    # TLS Information
    tls = report["tls_analysis"]
    tls_panel = Panel.fit(
        f"[green]TLS Version:[/green] {tls['version']} ([bold]{tls['grade']}[/bold])\n"
        f"[green]Cipher Strength:[/green] {tls['cipher_strength']}\n"
        f"[green]Vulnerabilities:[/green] {', '.join(tls['vulnerabilities']) or 'None found'}",
        title="TLS Configuration Analysis",
        border_style="yellow",
        padding=(1, 2)
    )
    console.print(tls_panel)

    # Framework Information
    if report.get("framework_analysis"):
        framework = report["framework_analysis"]
        framework_panel = Panel.fit(
            f"[green]Technology:[/green] {framework['name']} ({framework['type']})\n"
            f"[green]Version:[/green] {framework['version'] or 'Unknown'}\n"
            f"[green]Confidence:[/green] {framework['confidence']*100:.1f}%\n"
            f"[green]Common Vulnerabilities:[/green] {', '.join(framework['vulnerabilities'][:3]) or 'None'}",
            title="Technology Stack Detection",
            border_style="green",
            padding=(1, 2)
        )
        console.print(framework_panel)

    # Security headers table
    if report["headers"]:
        # Filter out sensitive headers if requested
        headers_to_display = []
        sensitive_headers = {"server", "x-powered-by", "x-aspnet-version"}
        
        for finding in report["headers"]:
            header_name = finding["header"].lower()
            
            if args.hide_sensitive and header_name in sensitive_headers:
                continue
                
            headers_to_display.append(finding)
        
        if headers_to_display:
            table = Table(
                title="Security Header Analysis", 
                show_header=True, 
                header_style="bold magenta",
                box=SIMPLE_HEAVY,
                show_lines=False
            )
            table.add_column("Header", style="cyan", no_wrap=True)
            table.add_column("Value", width=40)
            table.add_column("Status", justify="center", width=12)
            table.add_column("Issue", style="yellow")
            table.add_column("CVSS", justify="right", width=6)
            
            for finding in headers_to_display:
                status = finding["status"]
                value = finding["value"]
                
                if not args.full and len(value) > 50:
                    value = value[:47] + "..."
                
                status_color = {
                    RiskLevel.CRITICAL: "red",
                    RiskLevel.HIGH: "bright_red",
                    RiskLevel.MEDIUM: "yellow",
                    RiskLevel.LOW: "blue",
                    RiskLevel.PASS: "green",
                    RiskLevel.INFO: "cyan"
                }.get(status, "white")
                
                # Highlight security headers differently
                if finding["header"] in SECURITY_HEADERS:
                    header_style = "bold cyan"
                else:
                    header_style = "cyan"
                
                table.add_row(
                    Text(finding["header"], style=header_style),
                    value,
                    Text(status.name, style=status_color),
                    finding.get("issue", ""),
                    str(finding["cvss_score"])
                )
            
            console.print(table)
        else:
            console.print("[yellow]No headers to display (all filtered by --hide-sensitive)[/yellow]")

    # CSP Analysis
    if report.get("csp_analysis"):
        csp = report["csp_analysis"]
        csp_panel = Panel.fit(
            f"[bold]Content Security Policy (CSP) Analysis[/bold]\n"
            f"[green]Risk Level:[/green] [bold]{csp['risk_level'].name}[/bold]\n"
            f"[green]Score:[/green] {csp['score']}/20\n"
            f"[green]Missing Directives:[/green] {', '.join(csp['missing_directives']) or 'None'}\n"
            f"[green]Unsafe Directives:[/green] {', '.join(csp['unsafe_directives']) or 'None'}\n"
            f"[green]Wildcards Found:[/green] {', '.join(csp['wildcards']) or 'None'}",
            border_style="red",
            padding=(1, 2)
        )
        console.print(csp_panel)
        
        if csp["recommendations"]:
            console.print("[bold underline]CSP Recommendations:[/bold underline]")
            for i, rec in enumerate(csp["recommendations"], 1):
                console.print(f"{i}. {rec}")

    # Generate recommendations
    recommendations = generate_recommendations(report)
    if recommendations:
        rec_panel = Panel.fit(
            "\n".join([f"{i}. {rec}" for i, rec in enumerate(recommendations, 1)]),
            title="[bold]Security Recommendations[/bold]",
            border_style="green",
            padding=(1, 2)
        )
        console.print(rec_panel)
    
    # Missing security headers
    missing_headers = get_missing_headers(report)
    if missing_headers:
        missing_panel = Panel.fit(
            "\n".join([f"- {header}" for header in missing_headers]),
            title="[bold yellow]Missing Critical Security Headers[/bold yellow]",
            border_style="yellow",
            padding=(1, 2)
        )
        console.print(missing_panel)

def generate_recommendations(report: SecurityAnalysisReport) -> List[str]:
    """Generate actionable security recommendations based on findings"""
    recommendations = []
    critical_findings = []
    
    # Process header findings
    for finding in report["headers"]:
        if finding["status"] in [RiskLevel.CRITICAL, RiskLevel.HIGH] and finding.get("recommendation", ""):
            critical_findings.append(finding)
    
    # Add critical header recommendations
    for finding in critical_findings:
        rec = f"{finding['header']}: {finding['recommendation']}"
        if rec not in recommendations:
            recommendations.append(rec)
    
    # Add CSP recommendations
    if report.get("csp_analysis"):
        for rec in report["csp_analysis"].get("recommendations", []):
            if rec not in recommendations:
                recommendations.append(rec)
    
    # Add framework-specific recommendations
    if report.get("framework_analysis"):
        framework = report["framework_analysis"]
        if framework["name"] == "WordPress":
            recommendations.append("Update WordPress core and plugins to latest versions")
            recommendations.append("Implement Web Application Firewall (WAF)")
            recommendations.append("Disable XML-RPC if not needed")
        elif framework["name"] == "Django":
            recommendations.append("Ensure DEBUG=False in production settings")
            recommendations.append("Implement security middleware for headers")
        elif framework["name"] == "React":
            recommendations.append("Implement Content Security Policy (CSP) with nonces")
            recommendations.append("Sanitize all user inputs to prevent XSS")
    
    # Add TLS recommendations
    tls = report["tls_analysis"]
    if tls["grade"] in ["D", "F"]:
        recommendations.append(f"Upgrade TLS configuration from {tls['version']} to TLS 1.2 or higher")
    if "POODLE" in tls["vulnerabilities"]:
        recommendations.append("Disable SSLv3 to mitigate POODLE vulnerability")
    if "BEAST" in tls["vulnerabilities"]:
        recommendations.append("Enable TLS 1.1+ and disable TLS 1.0 to mitigate BEAST vulnerability")
    
    # Add general recommendations
    if not any(f["header"] == "Content-Security-Policy" for f in report["headers"]):
        recommendations.append("Implement Content Security Policy (CSP) header")
    
    if not any(f["header"] == "Strict-Transport-Security" for f in report["headers"]):
        recommendations.append("Implement Strict-Transport-Security (HSTS) header")
    
    return recommendations

def get_missing_headers(report: SecurityAnalysisReport) -> List[str]:
    """Identify missing critical security headers"""
    critical_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options"
    ]
    
    existing_headers = {f["header"].lower() for f in report["headers"]}
    return [h for h in critical_headers if h.lower() not in existing_headers]

if __name__ == "__main__":
    main()
