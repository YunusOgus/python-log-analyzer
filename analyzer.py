"""A safe, offline log analyzer for educational use."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for(?: invalid user)? (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
ERROR_PATTERN = re.compile(r"\b(ERROR|CRITICAL|FATAL)\b", re.IGNORECASE)


@dataclass
class LogAnalysis:
    """Stores the counts discovered while reading a log."""

    total_lines: int = 0
    failed_auth_attempts: int = 0
    error_lines: int = 0
    failed_attempts_by_ip: Counter[str] = field(default_factory=Counter)
    failed_attempts_by_user: Counter[str] = field(default_factory=Counter)


def analyze_lines(lines: Iterable[str]) -> LogAnalysis:
    """Analyze log lines and return a summary.

    The function only recognizes common SSH failed-password messages.
    Unknown lines are safely ignored.
    """

    result = LogAnalysis()

    for line in lines:
        result.total_lines += 1

        failed_login = FAILED_PASSWORD_PATTERN.search(line)
        if failed_login:
            result.failed_auth_attempts += 1
            result.failed_attempts_by_ip[failed_login["ip"]] += 1
            result.failed_attempts_by_user[failed_login["user"]] += 1

        if ERROR_PATTERN.search(line):
            result.error_lines += 1

    return result


def analyze_file(path: Path) -> LogAnalysis:
    """Open a text log safely and pass its lines to the analyzer."""

    with path.open(encoding="utf-8", errors="replace") as log_file:
        return analyze_lines(log_file)


def print_report(result: LogAnalysis, threshold: int) -> None:
    """Print a readable command-line report."""

    print("=== Python Log Analyzer ===")
    print(f"Lines analyzed: {result.total_lines}")
    print(f"Failed authentication attempts: {result.failed_auth_attempts}")
    print(f"Error-level log lines: {result.error_lines}")

    print(f"\nIPs meeting the threshold ({threshold}):")
    matching_ips = [
        (ip_address, count)
        for ip_address, count in result.failed_attempts_by_ip.most_common()
        if count >= threshold
    ]

    if not matching_ips:
        print("  No IP addresses reached the threshold.")
    else:
        for ip_address, count in matching_ips:
            print(f"  - {ip_address}: {count} failed attempts")

    print("\nUsernames seen in failed-login events:")
    if not result.failed_attempts_by_user:
        print("  No failed-login events found.")
    else:
        for username, count in result.failed_attempts_by_user.most_common():
            print(f"  - {username}: {count}")


def parse_arguments() -> argparse.Namespace:
    """Read command-line options."""

    parser = argparse.ArgumentParser(
        description="Analyze a local log file for failed SSH logins and errors."
    )
    parser.add_argument("log_file", type=Path, help="Path to the log file to analyze")
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Minimum failed attempts before an IP is highlighted (default: 3)",
    )
    arguments = parser.parse_args()

    if arguments.threshold < 1:
        parser.error("--threshold must be at least 1")

    return arguments


def main() -> None:
    """Run the command-line program."""

    arguments = parse_arguments()

    try:
        result = analyze_file(arguments.log_file)
    except OSError as error:
        raise SystemExit(f"Could not read {arguments.log_file}: {error}") from error

    print_report(result, arguments.threshold)


if __name__ == "__main__":
    main()
