# Python Log Analyzer

A safe, educational Python project for reviewing local authentication and application logs.

## What it does

- Counts failed SSH authentication attempts
- Lists the IP addresses and usernames that appear in failed-login events
- Highlights IP addresses that reach a configurable threshold
- Counts application lines marked as ERROR, CRITICAL, or FATAL
- Works entirely offline with a log file you own or are authorized to inspect

## Requirements

- Python 3.10 or newer
- No third-party packages

## Quick start

    python analyzer.py sample.log

Use a different threshold for repeated failed logins:

    python analyzer.py sample.log --threshold 2

Run the automated test:

    python -m unittest -v

## Example output

    === Python Log Analyzer ===
    Lines analyzed: 6
    Failed authentication attempts: 4
    Error-level log lines: 1

    IPs meeting the threshold (3):
      - 198.51.100.42: 3 failed attempts

## Project structure

- analyzer.py — the command-line analyzer
- sample.log — fictional log data using documentation-only IP addresses
- test_analyzer.py — an automated test for the analysis logic
- README.md — project overview and instructions

## Safety note

Only analyze logs that you own or have explicit permission to inspect. This project reads a file and produces a report; it does not send traffic, scan systems, or attempt access.

## Ideas for your next version

- Support Apache or Nginx access logs
- Export reports as JSON or CSV
- Add date-range filtering
- Visualize results with a chart
