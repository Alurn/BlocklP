#!/usr/bin/env python3
"""Zero-dependency IPv4 filtering, union accumulation, and window aggregation."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Iterable

DATE_FILE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.ipv4$")


def strip_comment(line: str) -> str:
    """Strip inline comments and surrounding whitespace."""
    return line.split("#", 1)[0].strip()


def load_excluded_intervals(config_paths: Iterable[Path]) -> tuple[list[int], list[int]]:
    """Load IPv4 addresses/CIDRs from config files into sorted non-overlapping intervals."""
    networks: list[ipaddress.IPv4Network] = []
    for path in config_paths:
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                token = strip_comment(raw)
                if not token:
                    continue
                try:
                    net = ipaddress.ip_network(token, strict=False)
                except ValueError:
                    continue
                if isinstance(net, ipaddress.IPv4Network):
                    networks.append(net)

    if not networks:
        return [], []

    collapsed = list(ipaddress.collapse_addresses(networks))
    starts = [int(net.network_address) for net in collapsed]
    ends = [int(net.broadcast_address) for net in collapsed]
    return starts, ends


def is_excluded(ip_int: int, starts: list[int], ends: list[int]) -> bool:
    """Return True if ip_int falls within any sorted excluded interval."""
    if not starts:
        return False
    idx = bisect_right(starts, ip_int) - 1
    return idx >= 0 and ip_int <= ends[idx]


def parse_ipv4_lines(lines: Iterable[str]) -> set[int]:
    """Parse valid single IPv4 addresses as 32-bit integers (ignores IPv6 and CIDRs)."""
    result: set[int] = set()
    for raw in lines:
        token = strip_comment(raw)
        if not token or "/" in token:
            continue
        try:
            addr = ipaddress.IPv4Address(token)
        except ValueError:
            continue
        result.add(int(addr))
    return result


def read_ipv4_file(path: Path) -> set[int]:
    """Read a plain IPv4 file into a set of 32-bit integers."""
    if not path.is_file():
        return set()
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return parse_ipv4_lines(f)


def atomic_write_ipv4(path: Path, ip_ints: Iterable[int]) -> int:
    """Atomically write sorted plain IPv4 addresses (no comments) to path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_ips = sorted(ip_ints)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", suffix=".ipv4", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            for ip_int in sorted_ips:
                f.write(f"{ipaddress.IPv4Address(ip_int)}\n")
        os.replace(tmp_name, path)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise
    return len(sorted_ips)


def filter_ips(ip_ints: set[int], starts: list[int], ends: list[int]) -> set[int]:
    """Return subset of ip_ints not present in excluded intervals."""
    if not starts:
        return set(ip_ints)
    return {ip_int for ip_int in ip_ints if not is_excluded(ip_int, starts, ends)}


def cmd_filter(args: argparse.Namespace) -> int:
    """Clean incoming IPs, enforce minimum count, and union with existing archive."""
    starts, ends = load_excluded_intervals(Path(p) for p in args.config)

    if args.input == "-":
        incoming_raw = parse_ipv4_lines(sys.stdin)
    else:
        incoming_raw = read_ipv4_file(Path(args.input))

    incoming_clean = filter_ips(incoming_raw, starts, ends)

    if len(incoming_clean) < args.min_lines:
        print(
            f"[ipfilter] Valid IPv4 count ({len(incoming_clean)}) is below threshold ({args.min_lines}); aborting overwrite.",
            file=sys.stderr,
        )
        return 2

    combined = set(incoming_clean)
    if args.existing:
        existing_clean = filter_ips(read_ipv4_file(Path(args.existing)), starts, ends)
        combined |= existing_clean

    out_path = Path(args.output)
    total = atomic_write_ipv4(out_path, combined)
    print(
        f"[ipfilter] Incoming valid: {len(incoming_clean)}, union total written to {out_path}: {total}"
    )
    return 0


def update_readme_stats(readme_path: Path, counts: dict[str, int], now_utc: datetime) -> None:
    """Update the auto-generated statistics table inside README.md."""
    if not readme_path.is_file():
        return

    start_marker = "<!-- STATS:START -->"
    end_marker = "<!-- STATS:END -->"
    content = readme_path.read_text(encoding="utf-8")
    if start_marker not in content or end_marker not in content:
        return

    updated_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    table = "\n".join(
        [
            start_marker,
            f"> 最後更新時間：`{updated_str}`",
            "",
            "| 清單檔案 | 時間視窗 | 有效 IP 筆數 | 適用場景 |",
            "| :--- | :--- | ---: | :--- |",
            f"| `blocklist-1d.ipv4` | 近 1 天（2 日歸檔） | **{counts['1d']:,}** | 防火牆／WAF 預設防護（低誤擋） |",
            f"| `blocklist-7d.ipv4` | 近 7 天累積 | **{counts['7d']:,}** | 中強度持續性威脅防護 |",
            f"| `blocklist-30d.ipv4` | 近 30 天累積 | **{counts['30d']:,}** | 高強度防護（需留意誤擋風險） |",
            end_marker,
        ]
    )

    pattern = re.compile(
        re.escape(start_marker) + r".*?" + re.escape(end_marker),
        flags=re.DOTALL,
    )
    new_content = pattern.sub(table, content, count=1)
    if new_content != content:
        readme_path.write_text(new_content, encoding="utf-8")


def cmd_aggregate(args: argparse.Namespace) -> int:
    """Prune expired archives, re-apply whitelist, and build 1d/7d/30d blocklists."""
    now_utc = datetime.now(timezone.utc)
    today = (
        datetime.strptime(args.today, "%Y-%m-%d").date()
        if args.today
        else now_utc.date()
    )
    db_dir = Path(args.db_dir)
    out_dir = Path(args.out_dir)
    starts, ends = load_excluded_intervals(Path(p) for p in args.config)

    retention_cutoff = today - timedelta(days=args.retention_days - 1)
    archives: dict[datetime.date, set[int]] = {}

    if db_dir.is_dir():
        for entry in sorted(db_dir.iterdir()):
            if not entry.is_file():
                continue
            match = DATE_FILE_RE.match(entry.name)
            if not match:
                continue
            file_date = datetime.strptime(match.group(1), "%Y-%m-%d").date()
            if file_date < retention_cutoff or file_date > today:
                if file_date < retention_cutoff:
                    entry.unlink()
                    print(f"[ipfilter] Pruned expired archive: {entry.name}")
                continue

            raw_ips = read_ipv4_file(entry)
            clean_ips = filter_ips(raw_ips, starts, ends)
            if len(clean_ips) != len(raw_ips):
                atomic_write_ipv4(entry, clean_ips)
            archives[file_date] = clean_ips

    windows = {
        "1d": (today - timedelta(days=1), "blocklist-1d.ipv4"),
        "7d": (today - timedelta(days=6), "blocklist-7d.ipv4"),
        "30d": (today - timedelta(days=29), "blocklist-30d.ipv4"),
    }

    counts: dict[str, int] = {}
    any_updated = False
    for label, (start_date, filename) in windows.items():
        merged: set[int] = set()
        for d, ips in archives.items():
            if start_date <= d <= today:
                merged |= ips
        out_path = out_dir / filename
        if not merged and out_path.is_file():
            existing_count = len(read_ipv4_file(out_path))
            if existing_count > 0:
                counts[label] = existing_count
                print(
                    f"[ipfilter] Warning: 0 IPs in {label} window; preserving existing {out_path} ({existing_count} IPs).",
                    file=sys.stderr,
                )
                continue
        count = atomic_write_ipv4(out_path, merged)
        counts[label] = count
        any_updated = True
        print(f"[ipfilter] Wrote {out_path} ({count} IPs)")

    if args.readme and any_updated:
        update_readme_stats(Path(args.readme), counts, now_utc)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IPv4 blocklist filter & aggregator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_filter = subparsers.add_parser("filter", help="Clean and union incoming IPv4 list")
    p_filter.add_argument("--input", required=True, help="Input file path or '-' for stdin")
    p_filter.add_argument("--output", required=True, help="Output plain IPv4 file path")
    p_filter.add_argument("--existing", help="Optional existing archive to union with")
    p_filter.add_argument("--config", action="append", default=[], help="Exclusion file (bogons/whitelist)")
    p_filter.add_argument("--min-lines", type=int, default=0, help="Minimum valid incoming IPs required")
    p_filter.set_defaults(func=cmd_filter)

    p_agg = subparsers.add_parser("aggregate", help="Prune old archives and generate 1d/7d/30d lists")
    p_agg.add_argument("--db-dir", required=True, help="Directory containing YYYY-MM-DD.ipv4 files")
    p_agg.add_argument("--out-dir", required=True, help="Output directory for blocklist-*.ipv4")
    p_agg.add_argument("--config", action="append", default=[], help="Exclusion file (bogons/whitelist)")
    p_agg.add_argument("--retention-days", type=int, default=30, help="Days of daily archives to keep")
    p_agg.add_argument("--today", help="Override UTC date (YYYY-MM-DD) for testing")
    p_agg.add_argument("--readme", help="Optional README.md path to update stats table")
    p_agg.set_defaults(func=cmd_aggregate)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
