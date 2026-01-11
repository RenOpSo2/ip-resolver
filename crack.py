#!/usr/bin/env python3
"""
IP Cr4ck3r - interactive and batch domain -> IP lookup
Author: @R3noDev,
"""

import sys
import socket
import argparse
import json
import csv
from urllib.parse import urlparse
from time import sleep
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def clean_host(target: str) -> str:
    """
    Clean a user input and return hostname.
    Accepts plain domain, domain/path, or URL with scheme.
    """
    if not target:
        raise ValueError("Empty target")
    parsed = urlparse(target if "://" in target else "//" + target)
    host = parsed.hostname or target
    return host.strip().rstrip(".")


def resolve_host(host: str, timeout: float = 5.0):
    """
    Resolve host to a sorted list of unique IP addresses (A and AAAA).
    """
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({info[4][0] for info in infos})
        return addrs
    except socket.gaierror as e:
        raise RuntimeError(f"DNS lookup failed: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Unexpected error: {e}") from e


def try_dns_records(host: str):
    """
    Try to fetch DNS record types using dnspython if available.
    Returns dict of records or None if dnspython not installed.
    """
    try:
        import dns.resolver  
    except Exception:
        return None

    resolver = dns.resolver.Resolver()
    records = {}
    for rtype in ("A", "AAAA", "CNAME", "MX"):
        try:
            answers = resolver.resolve(host, rtype, raise_on_no_answer=False)
            if answers.rrset is not None:
                records[rtype] = [r.to_text() for r in answers]
        except Exception:
            continue
    return records


def print_records_table(host: str, addrs, extra_records=None):
    t = Table(title=f"Results for: {host}", box=box.SIMPLE_HEAVY)
    t.add_column("Type", style="cyan", no_wrap=True)
    t.add_column("Value", style="magenta")

    if addrs:
        for a in addrs:
            typ = "IPv6" if ":" in a else "IPv4"
            t.add_row(typ, a)
    else:
        t.add_row("IP", "[red]No address found[/red]")

    if extra_records:
        for rtype, items in extra_records.items():
            for it in items:
                t.add_row(rtype, it)

    console.print(t)


def interactive_loop():
    console.print(Panel("[bold green]IP Finder[/bold green]\nEnter a URL or domain. Type [bold]q[/bold] to quit.", title="IP Cr4cker", subtitle="Safe / Informational"))
    while True:
        try:
            url = console.input("[bold cyan]> [/bold cyan]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold red]Aborted.[/bold red] Bye.")
            break

        if not url:
            console.print("[yellow]Please enter a domain or URL (or q to quit).[/yellow]")
            continue

        if url.lower() in {"q", "quit", "exit"}:
            console.print("[italic]Bye![/italic]")
            break

        try:
            host = clean_host(url)
        except ValueError:
            console.print("[red]Empty input.[/red]")
            continue

        with console.status(f"[bold]Resolving {host} ...[/bold]", spinner="dots"):
            try:
                addrs = resolve_host(host)
                extra = try_dns_records(host)
                sleep(0.2)
            except Exception as e:
                console.print(f"[red]Error:[/red] {e}")
                continue

        print_records_table(host, addrs, extra)


def batch_mode(infile: str, outfile: str, fmt: str):
    """
    Read domains from infile (one per line), write results to outfile in csv or json.
    """
    targets = []
    with open(infile, "r", encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            try:
                targets.append(clean_host(s))
            except Exception:
                continue

    results = []
    for host in targets:
        try:
            addrs = resolve_host(host)
            extra = try_dns_records(host) or {}
            results.append({"host": host, "ips": addrs, "records": extra})
            console.log(f"[green]Resolved[/green] {host} -> {len(addrs)} addr(s)")
        except Exception as e:
            console.log(f"[red]Failed[/red] {host}: {e}")
            results.append({"host": host, "ips": [], "error": str(e)})

    if fmt == "json":
        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    else:  
        with open(outfile, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["host", "ips", "records_or_error"])
            for r in results:
                writer.writerow([r.get("host"), ";".join(r.get("ips", [])), json.dumps(r.get("records") or r.get("error") or "")])

    console.print(f"[bold green]Wrote results to:[/bold green] {outfile}")


def parse_args():
    p = argparse.ArgumentParser(prog="IP Cr4ck3r", description="Resolve domain/URL to IP(s). Interactive by default.")
    p.add_argument("--batch", "-b", help="Input file with domains/URLs (one per line).")
    p.add_argument("--out", "-o", help="Output file for batch mode (default: results.json or results.csv).")
    p.add_argument("--format", "-f", choices=("json", "csv"), default="json", help="Output format for batch mode.")
    p.add_argument("--no-records", action="store_true", help="Do not attempt to fetch DNS records (skips dnspython).")
    return p.parse_args()


def main():
    args = parse_args()

    if args.batch:
        out = args.out or (f"results.{args.format}")
        batch_mode(args.batch, out, args.format)
        return

    interactive_loop()


if __name__ == "__main__":
    main()