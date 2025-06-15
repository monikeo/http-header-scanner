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
from rich.progress import track

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
        "-d", "--domain",
        help="Scan entire domain (discover URLs)"
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
        "--threads",
        type=int,
        default=5,
        help="Concurrent scanning threads (default: 5)"
    )
    scan_group.add_argument(
        "--user-agent",
        default="SecurityScanner/2.0",
        help="Custom User-Agent string"
    )
    scan_group.add_argument(
        "--full",
        action="store_true",
        help="Show full header values (not truncated)"
    )
    scan_group.add_argument(
        "--crawl",
        type=int,
        default=0,
        help="Crawl depth for domain scanning (0=disabled)"
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
    output_group.add_argument(
        "--export-vulns",
        action="store_true",
        help="Export only vulnerability findings"
    )

    args = parser.parse_args()

    # Validate input
    if not args.url and not args.input_file and not args.domain:
        console.print("[red]Error: No target specified. Use --url or --input-file[/red]")
        sys.exit(1)

    scanner = HeaderScanner()
    reports = []

    try:
        # Single URL scan
        if args.url:
            reports.append(scanner.scan(
                args.url,
                timeout=args.timeout,
                user_agent=args.user_agent
            ))
        elif args.input_file:
            if not args.input_file.exists():
                console.print(f"[red]Error: Input file not found: {args.input_file}[/red]")
                sys.exit(1)
                
            with open(args.input_file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
                
            if not urls:
                console.print("[red]Error: No valid URLs found in input file[/red]")
                sys.exit(1)
                
            for url in track(urls, description="Scanning URLs..."):
                if args.verbose:
                    console.print(f"[yellow]Scanning: {url}[/yellow]")
                reports.append(scanner.scan(url, timeout=args.timeout, user_agent=args.user_agent))
        # Domain scan
        elif args.domain:
            from .crawler import DomainCrawler
            crawler = DomainCrawler(args.domain, max_depth=args.crawl)
            urls = crawler.discover()

            for url in track(urls, description=f"Crawling {args.domain}"):
                reports.append(scanner.scan(url, timeout=args.timeout, user_agent=args.user_agent))

    except Exception as e:
        console.print(f"[red]Error during scanning: {str(e)}[/red]")
        sys.exit(1)

    # Process reports
    if args.export_vulns:
        reports = [r for r in reports if r['overall_risk'] != RiskLevel.PASS]

    # Output handling
    if args.format == "text":
        display_text_reports(reports, args)
    elif args.format == "json":
        if args.output:
            ReportExporter.to_json(reports, args.output)
            console.print(f"[green]JSON report saved to: {args.output}[/green]")
        else:
            console.print_json(data=reports)
    elif args.format == "csv":
        if args.output:
            ReportExporter.to_csv(reports, args.output)
            console.print(f"[green]CSV report saved to: {args.output}[/green]")
        else:
            console.print("[red]CSV export requires output file[/red]")
    elif args.format == "pdf":
        if len(reports) == 1:
            ReportExporter.to_pdf(reports[0], args.output)
            console.print(f"[green]PDF report saved to: {args.output}[/green]")
        else:
            console.print("[red]PDF export currently supports single reports only[/red]")
    elif args.format == "html":
        console.print("[yellow]HTML export is not implemented yet[/yellow]")
        """
        if args.output:
            ReportExporter.to_html(reports, args.output)
            console.print(f"[green]HTML report saved to: {args.output}[/green]")
        """
    elif args.format == "sarif":
        if args.output:
            ReportExporter.to_sarif(reports, args.output)
            console.print(f"[green]SARIF report saved to: {args.output}[/green]")

def display_text_reports(reports: List[SecurityAnalysisReport], args: argparse.Namespace):
    """Display multiple reports in rich formatted text"""
    for i, report in enumerate(reports):
        if i > 0:
            console.print("\n" + "="*80 + "\n")
        
        display_text_report(report, args)

def display_text_report(report: SecurityAnalysisReport, args: argparse.Namespace):
    """Display report in rich formatted text with enhanced security"""

    # Handle missing attributes safely
    hide_sensitive = getattr(args, 'hide_sensitive', False)
    full_output = getattr(args, 'full', False)

    # Get severity counts for summary
    severity_counts = {
        RiskLevel.CRITICAL.name: 0,
        RiskLevel.HIGH.name: 0,
        RiskLevel.MEDIUM.name: 0,
        RiskLevel.LOW.name: 0,
        RiskLevel.PASS.name: 0,
        RiskLevel.INFO.name: 0,
        RiskLevel.ERROR.name: 0
    }
    
    for finding in report.get("headers", []):
        status_name = finding.get("status", RiskLevel.INFO).name
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
    """
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
    """
    tls = report.get("tls_analysis")
    if tls:
        tls_panel = Panel.fit(
            f"[green]TLS Version:[/green] {tls.get('version', 'Unknown')} "
            f"([bold]{tls.get('grade', 'N/A')}[/bold])\n"
            f"[green]Cipher Strength:[/green] {tls.get('cipher_strength', 'Unknown')}\n"
            f"[green]Vulnerabilities:[/green] {', '.join(tls.get('vulnerabilities', [])) or 'None found'}",
            title="TLS Configuration Analysis",
            border_style="yellow",
            padding=(1, 2)
        )
        console.print(tls_panel)
    else:
        console.print("[yellow]No TLS analysis available[/yellow]")

    # Framework Information
    """
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
    """
    if report.get("framework_analysis"):
        framework = report["framework_analysis"]
        framework_panel = Panel.fit(
            f"[green]Technology:[/green] {framework.get('name', 'Unknown')} "
            f"({framework.get('type', 'Unknown')})\n"
            f"[green]Version:[/green] {framework.get('version', 'Unknown')}\n"
            f"[green]Confidence:[/green] {framework.get('confidence', 0)*100:.1f}%\n"
            f"[green]Common Vulnerabilities:[/green] {', '.join(framework.get('vulnerabilities', [])[:3]) or 'None'}",
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
        
        for finding in report.get("headers", []):
            header_name = finding.get("header", "").lower()
            
            if hide_sensitive and header_name in sensitive_headers:
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
                status = finding.get("status", RiskLevel.INFO)
                value = finding.get("value", "")
                
                if not args.full and len(value) > 50:
                    value = value[:50] + "..."
                
                status_color = {
                    RiskLevel.CRITICAL: "red",
                    RiskLevel.HIGH: "bright_red",
                    RiskLevel.MEDIUM: "yellow",
                    RiskLevel.LOW: "blue",
                    RiskLevel.PASS: "green",
                    RiskLevel.INFO: "cyan",
                    RiskLevel.ERROR: "magenta"
                }.get(status, "white")
                
                # Highlight security headers differently
                header_name = finding.get("header", "")
                if header_name in SECURITY_HEADERS:
                    header_style = "bold cyan"
                else:
                    header_style = "cyan"
                
                table.add_row(
                    Text(header_name, style=header_style),
                    value,
                    Text(status.name, style=status_color),
                    finding.get("issue", ""),
                    str(finding.get("cvss_score", 0.0))
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
    for finding in report.get("headers", []):
        status = finding.get("status")
        if status and status in [RiskLevel.CRITICAL, RiskLevel.HIGH] and finding.get("recommendation", ""):
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
        name = framework.get("name")
        if name == "WordPress":
            recommendations.append("Update WordPress core and plugins to latest versions")
            recommendations.append("Implement Web Application Firewall (WAF)")
            recommendations.append("Disable XML-RPC if not needed")
        elif name == "Django":
            recommendations.append("Ensure DEBUG=False in production settings")
            recommendations.append("Implement security middleware for headers")
        elif name == "React":
            recommendations.append("Implement Content Security Policy (CSP) with nonces")
            recommendations.append("Sanitize all user inputs to prevent XSS")
    
    # Add TLS recommendations - with null checking
    tls = report.get("tls_analysis")
    if tls:
        grade = tls.get("grade")
        version = tls.get("version", "current version")
        vulnerabilities = tls.get("vulnerabilities", [])

        if grade in ["D", "F"]:
            recommendations.append(f"Upgrade TLS configuration from {version} to TLS 1.2 or higher")
        if "POODLE" in vulnerabilities:
            recommendations.append("Disable SSLv3 to mitigate POODLE vulnerability")
        if "BEAST" in vulnerabilities:
            recommendations.append("Enable TLS 1.1+ and disable TLS 1.0 to mitigate BEAST vulnerability")

    # Add general recommendations
    headers = report.get("headers", [])
    if not any(f.get("header") == "Content-Security-Policy" for f in headers):
        recommendations.append("Implement Content Security Policy (CSP) header")
    
    if not any(f.get("header") == "Strict-Transport-Security" for f in headers):
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
