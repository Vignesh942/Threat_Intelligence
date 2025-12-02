# main_rich.py
from check_otx import check_domain_in_otx
from check_virustotal import vt_check
from check_abuseipdb import abuse_check
from check_urlscan import urlscan_check
from file_storage import save_iocs
from gemini_client import ai_summarize
from check_whois import whois_lookup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

def pretty_print_otx(res: dict):
    if "error" in res:
        console.print(Panel(f"[red]Error:[/red] {res['error']}", title="OTX"))
        return

    table = Table(title="OTX Result")
    table.add_column("Field")
    table.add_column("Value")

    table.add_row("Original input", res.get("ioc_original", ""))
    table.add_row("Normalized", res.get("ioc_normalized", ""))
    table.add_row("Status", res.get("status", ""))
    table.add_row("Pulse count", str(res.get("pulse_count", 0)))
    table.add_row("Passive DNS hits", str(res.get("passive_dns_count", 0)))
    table.add_row("Whois", res.get("whois_name", "N/A"))
    if res.get("pulses"):
        table.add_row("Pulses", ", ".join(res.get("pulses")))

    console.print(table)

def pretty_print_vt(vt: dict):
    table = Table(title="VirusTotal Result")
    if "error" in vt:
        console.print(Panel(f"[red]Error:[/red] {vt['error']}", title="VirusTotal"))
        return
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Type", vt.get("type", ""))
    table.add_row("Malicious", str(vt.get("malicious", 0)))
    table.add_row("Suspicious", str(vt.get("suspicious", 0)))
    table.add_row("Harmless", str(vt.get("harmless", 0)))
    table.add_row("Total engines", str(vt.get("total_engines", 0)))
    console.print(table)

def pretty_print_abuse(ab: dict):
    if not ab:
        console.print(Panel("[yellow]AbuseIPDB skipped (only for IPs)[/yellow]"))
        return
    if "error" in ab:
        console.print(Panel(f"[red]Error:[/red] {ab['error']}", title="AbuseIPDB"))
        return
    table = Table(title="AbuseIPDB Result")
    table.add_column("Field")
    table.add_column("Value")
    for k in ["ip", "abuse_score", "total_reports", "last_reported", "isp", "country", "domain"]:
        table.add_row(k.replace("_", " ").title(), str(ab.get(k, "")))
    console.print(table)

def pretty_print_urlscan(data: dict):
    table = Table(title="URLScan.io Result")
    table.add_column("Field")
    table.add_column("Value")
    if "error" in data:
        console.print(Panel(f"[red]Error:[/red] {data['error']}", title="URLScan.io"))
        return
    table.add_row("URL", data.get("url", ""))
    table.add_row("Tags", str(data.get("tags", "")))
    verdict = data.get("verdict", {})
    table.add_row("Verdict", str(verdict.get("overall", "")))
    table.add_row("Malicious", str(verdict.get("malicious", "")))
    table.add_row("Suspicious", str(verdict.get("suspicious", "")))
    table.add_row("Harmless", str(verdict.get("harmless", "")))
    console.print(table)

def pretty_print_whois(data: dict):
    if "error" in data:
        console.print(Panel(f"[red]Error:[/red] {data['error']}", title="WHOIS"))
        return
    table = Table(title="WHOIS Result")
    table.add_column("Field")
    table.add_column("Value")
    for k in ["domain_name", "registrar", "creation_date", "expiration_date", "status", "emails", "name_servers"]:
        table.add_row(k.replace("_", " ").title(), str(data.get(k, "")))
    console.print(table)

def generate_llm_summary(otx, vt, abuse, urlscan, whois):
    prompt = f"""
You are a cybersecurity analyst. Summarize the threat intelligence and give a final assessment.

Return output STRICTLY in a Markdown table with two columns: Field | Result

Fields:
- Summary
- Threat Score (0 to 10)
- Recommendation (Safe, Suspicious, Malicious)
- Reason

Do not add extra explanation. Only output the table.

=== DATA ===
OTX: {otx}
VirusTotal: {vt}
AbuseIPDB: {abuse}
URLScan: {urlscan}
WHOIS: {whois}
"""
    return ai_summarize(prompt)

def main():
    console.print(Panel("[bold cyan]Threat Intelligence Checker[/bold cyan]"))

    user_input = console.input("[bold green]Enter domain/URL/IP to check:[/bold green] ").strip()
    if not user_input:
        console.print("[red]No input provided. Exiting.[/red]")
        return

    with Progress(SpinnerColumn(), TextColumn("{task.description}")) as progress:
        task_otx = progress.add_task("Checking OTX...", start=False)
        progress.start_task(task_otx)
        otx_result = check_domain_in_otx(user_input)
        progress.stop_task(task_otx)

        task_vt = progress.add_task("Checking VirusTotal...", start=False)
        progress.start_task(task_vt)
        vt_result = vt_check(user_input)
        progress.stop_task(task_vt)

        task_abuse = progress.add_task("Checking AbuseIPDB...", start=False)
        progress.start_task(task_abuse)
        abuse_result = abuse_check(user_input) if vt_result.get("type") == "ip" else {}
        progress.stop_task(task_abuse)

        task_urlscan = progress.add_task("Checking URLScan.io...", start=False)
        progress.start_task(task_urlscan)
        urlscan_result = urlscan_check(user_input)
        progress.stop_task(task_urlscan)

        task_whois = progress.add_task("Checking WHOIS...", start=False)
        progress.start_task(task_whois)
        normalized_domain = otx_result.get("ioc_normalized", user_input)
        whois_result = whois_lookup(normalized_domain)
        progress.stop_task(task_whois)

    # Print results
    pretty_print_otx(otx_result)
    pretty_print_vt(vt_result)
    pretty_print_abuse(abuse_result)
    pretty_print_urlscan(urlscan_result)
    pretty_print_whois(whois_result)

    console.print("\n[bold magenta]AI Summary (Gemini Flash 2.0)[/bold magenta]")
    ai_output = generate_llm_summary(otx_result, vt_result, abuse_result, urlscan_result, whois_result)
    console.print(ai_output)

    # Save results
    record = {
        "indicator": user_input,
        "otx_result": otx_result,
        "vt_result": vt_result,
        "abuse_result": abuse_result,
        "urlscan_result": urlscan_result,
        "whois_result": whois_result,
        "ai_summary": ai_output
    }
    save_iocs([record])
    console.print("\n[bold green]Saved to ioc_results.json[/bold green]")

if __name__ == "__main__":
    main()
