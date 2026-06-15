# controlscan

A lightweight CLI that checks system-level security controls against a baseline and flags drift. Useful for keeping track of configuration changes over time.

## What it does

Runs a series of system checks (SSH key permissions, firewall status, kernel parameters, disk encryption, audit logging, file integrity, password policy, sudo config, world-writable files, unnecessary services), compares results against a saved baseline, and generates a JSON report. That is it — it is a small tool, not a production compliance suite.

The point is catching drift between snapshots: if a control passed last week and fails today, you know something changed.

## Usage

```bash
# Snapshot current state as baseline
python3 controlscan.py baseline

# Run checks and compare against baseline
python3 controlscan.py check

# View scan history
python3 controlscan.py history
```

## Controls checked

| Control | Category | Severity |
|---------|----------|----------|
| SSH key file permissions | Access Control | High |
| Host firewall active | Network Security | High |
| Password policy strength | Access Control | Medium |
| Critical file integrity | System Integrity | Medium |
| Unnecessary services | System Hardening | Low |
| Passwordless sudo users | Access Control | High |
| Disk encryption | Data Protection | High |
| Audit logging active | Monitoring | Medium |
| World-writable system files | File Security | Medium |
| Security kernel parameters | System Hardening | Medium |

## Output

Results go to `~/.controlscan/` — one JSON report per scan, plus a history log and optional baseline. Each report includes pass/fail per control, drift flags (if a baseline exists), and severity for remediation triage.

## Caveats

- Runs without root by default, so some checks are best-effort (e.g., reading `/etc/shadow` is skipped on permission errors)
- The check list is small and opinionated — add your own by editing `CONTROLS` and `CHECK_FUNCTIONS` in the script
- This is a proof-of-concept, not a compliance framework
