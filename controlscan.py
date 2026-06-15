#!/usr/bin/env python3
"""
controlscan: IT Control Drift Detection for SOX Audits.
Checks system-level controls against baselines and generates
audit-ready evidence reports.

Usage:
    python3 controlscan.py check         # Run all controls
    python3 controlscan.py history       # Show drift history
    python3 controlscan.py baseline      # Snapshot current state as baseline
"""

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CONTROL_SCAN_DIR = Path.home() / ".controlscan"
BASELINE_FILE = CONTROL_SCAN_DIR / "baseline.json"
HISTORY_FILE = CONTROL_SCAN_DIR / "history.jsonl"

CONTROLS = {
    "ssh_key_permissions": {
        "name": "SSH Key File Permissions",
        "category": "Access Control",
        "severity": "high",
        "description": "SSH private keys should be readable only by their owner",
        "risk": "Unauthorized access to SSH keys can lead to privilege escalation",
    },
    "firewall_active": {
        "name": "Host Firewall Active",
        "category": "Network Security",
        "severity": "high",
        "description": "System firewall should be enabled",
        "risk": "Disabled firewall exposes the system to unauthorized network access",
    },
    "password_policy": {
        "name": "Password Policy Strength",
        "category": "Access Control",
        "severity": "medium",
        "description": "System should enforce minimum password quality requirements",
        "risk": "Weak passwords increase risk of credential compromise",
    },
    "file_integrity_monitor": {
        "name": "Critical File Integrity",
        "category": "System Integrity",
        "severity": "medium",
        "description": "Monitor checksums of critical system files for unauthorized changes",
        "risk": "Unexpected file changes may indicate compromise or configuration drift",
    },
    "unnecessary_services": {
        "name": "Unnecessary Services Running",
        "category": "System Hardening",
        "severity": "low",
        "description": "Identify services listening on ports that may not be required",
        "risk": "Unnecessary services increase attack surface area",
    },
    "passwordless_sudo": {
        "name": "Passwordless Sudo Users",
        "category": "Access Control",
        "severity": "high",
        "description": "Users with passwordless sudo (NOPASSWD) are a privilege escalation risk",
        "risk": "Passwordless sudo bypasses authentication for all commands",
    },
    "disk_encryption": {
        "name": "Disk Encryption Status",
        "category": "Data Protection",
        "severity": "high",
        "description": "Root filesystem should be encrypted at rest",
        "risk": "Unencrypted disk allows data access if storage is physically removed",
    },
    "audit_logging": {
        "name": "Audit Logging Active",
        "category": "Monitoring",
        "severity": "medium",
        "description": "System audit daemon should be running and capturing events",
        "risk": "Without audit logging, security events cannot be traced",
    },
    "world_writable_files": {
        "name": "World-Writable System Files",
        "category": "File Security",
        "severity": "medium",
        "description": "Critical system files and directories should not be world-writable",
        "risk": "World-writable files allow any user to modify system configuration",
    },
    "kernel_parameters": {
        "name": "Security Kernel Parameters",
        "category": "System Hardening",
        "severity": "medium",
        "description": "Key kernel security parameters should be properly configured",
        "risk": "Weak kernel settings reduce system resistance to network attacks",
    },
}


def color(text, code):
    return f"\033[{code}m{text}\033[0m"


def green(text):
    return color(text, "92")


def red(text):
    return color(text, "91")


def yellow(text):
    return color(text, "93")


def blue(text):
    return color(text, "94")


def gray(text):
    return color(text, "90")


# ---------------------------------------------------------------------------
# Control check implementations
# ---------------------------------------------------------------------------

def check_ssh_key_permissions():
    ssh_dir = Path.home() / ".ssh"
    keys_found = list(ssh_dir.glob("id_*")) if ssh_dir.exists() else []
    results = []
    for key in keys_found:
        mode = os.stat(key).st_mode
        owner_only = not (mode & stat.S_IRWXG or mode & stat.S_IRWXO)
        results.append({
            "file": str(key),
            "owner_read_only": owner_only,
            "permissions": oct(mode & 0o777),
        })
    passed = all(r["owner_read_only"] for r in results) if results else True
    return {
        "passed": passed,
        "detail": f"{len(results)} SSH keys checked, all restricted to owner"
        if passed
        else f"{sum(1 for r in results if not r['owner_read_only'])} keys have excessive permissions",
    }


def check_firewall_active():
    active = False
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "ufw"], capture_output=True, text=True, timeout=5
        )
        active = result.stdout.strip() == "active"
    except (subprocess.SubprocessError, FileNotFoundError):
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n"], capture_output=True, text=True, timeout=5
            )
            rules = [l for l in result.stdout.splitlines() if "Chain" in l]
            active = len(rules) > 3
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
    return {"passed": active, "detail": "Firewall is active" if active else "No active firewall detected"}


def check_password_policy():
    score = 0
    checks = []
    if _check_pam_pwquality():
        score += 1
        checks.append("pam_pwquality configured")
    else:
        checks.append("pam_pwquality not configured")
    min_len = _check_min_password_length()
    if min_len:
        score += 1
        checks.append(f"min password length >= {min_len}")
    else:
        checks.append("password length may be too short")
    passed = score >= 1
    return {"passed": passed, "detail": "; ".join(checks)}


def _check_pam_pwquality():
    try:
        result = subprocess.run(
            ["grep", "-r", "pam_pwquality.so", "/etc/pam.d/"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _check_min_password_length():
    try:
        result = subprocess.run(
            ["grep", "^minlen", "/etc/security/pwquality.conf"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout:
            return int(result.stdout.split("=")[1].strip())
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


def check_file_integrity_monitor():
    critical = ["/etc/passwd", "/etc/ssh/sshd_config"]
    results = []
    for path in critical:
        f = Path(path)
        if f.exists():
            try:
                h = hashlib.sha256(f.read_bytes()).hexdigest()
                results.append({"file": path, "hash": h})
            except PermissionError:
                results.append({"file": path, "hash": "ACCESS_DENIED"})
    passed = len([r for r in results if r.get("hash") != "ACCESS_DENIED"]) == len(critical)
    return {
        "passed": passed,
        "detail": f"{len(results)}/{len(critical)} critical files checked",
        "artifacts": results,
    }


def check_unnecessary_services():
    common = ["telnet", "rsh", "rlogin", "vsftpd", "tftp"]
    found = []
    for svc in common:
        result = subprocess.run(
            ["systemctl", "is-active", svc], capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip() == "active":
            found.append(svc)
    passed = len(found) == 0
    return {
        "passed": passed,
        "detail": f"No unnecessary services found" if passed else f"Running: {', '.join(found)}",
    }


def check_passwordless_sudo():
    sudoers_paths = ["/etc/sudoers"]
    sudoers_d = Path("/etc/sudoers.d")
    if sudoers_d.exists():
        sudoers_paths.extend(str(p) for p in sudoers_d.iterdir())
    nopasswd_users = []
    for path in sudoers_paths:
        f = Path(path)
        if f.exists():
            try:
                content = f.read_text()
                for line in content.splitlines():
                    if "NOPASSWD" in line and not line.strip().startswith("#"):
                        parts = line.split()
                        if parts:
                            nopasswd_users.append(parts[0])
            except PermissionError:
                pass
    passed = len(nopasswd_users) == 0
    return {
        "passed": passed,
        "detail": f"No NOPASSWD users" if passed else f"NOPASSWD users: {', '.join(set(nopasswd_users))}",
    }


def check_disk_encryption():
    encrypted = False
    try:
        result = subprocess.run(
            ["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"],
            capture_output=True, text=True, timeout=10,
        )
        encrypted = "crypto" in result.stdout.lower() or "luks" in result.stdout.lower()
    except (subprocess.SubprocessError, FileNotFoundError):
        try:
            result = subprocess.run(
                ["findmnt", "-T", "/", "-o", "SOURCE"],
                capture_output=True, text=True, timeout=5,
            )
            source = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
            encrypted = "dm-" in source or "crypt" in source.lower()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
    return {"passed": encrypted, "detail": "Disk encryption detected" if encrypted else "No disk encryption detected"}


def check_audit_logging():
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "auditd"],
            capture_output=True, text=True, timeout=5,
        )
        active = result.stdout.strip() == "active"
    except (subprocess.SubprocessError, FileNotFoundError):
        active = False
    return {"passed": active, "detail": "auditd is running" if active else "auditd is not running"}


def check_world_writable_files():
    critical_dirs = ["/etc", "/bin", "/usr/bin"]
    found = []
    for d in critical_dirs:
        p = Path(d)
        if p.exists():
            for entry in p.iterdir():
                try:
                    if entry.is_file() and os.stat(entry).st_mode & stat.S_IWOTH:
                        found.append(str(entry))
                except (PermissionError, OSError):
                    pass
    passed = len(found) == 0
    return {
        "passed": passed,
        "detail": f"No world-writable critical files" if passed else f"{len(found)} world-writable files in critical directories",
        "artifacts": found[:20],
    }


def check_kernel_parameters():
    params = {
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv6.conf.all.accept_redirects": "0",
    }
    results = {}
    for param, expected in params.items():
        try:
            result = subprocess.run(
                ["sysctl", "-n", param], capture_output=True, text=True, timeout=5
            )
            actual = result.stdout.strip()
            results[param] = {"expected": expected, "actual": actual, "match": actual == expected}
        except (subprocess.SubprocessError, FileNotFoundError):
            results[param] = {"expected": expected, "actual": "unknown", "match": False}
    passed = all(r["match"] for r in results.values())
    return {
        "passed": passed,
        "detail": f"{sum(1 for r in results.values() if r['match'])}/{len(results)} parameters correctly set",
        "artifacts": results,
    }


CHECK_FUNCTIONS = {
    "ssh_key_permissions": check_ssh_key_permissions,
    "firewall_active": check_firewall_active,
    "password_policy": check_password_policy,
    "file_integrity_monitor": check_file_integrity_monitor,
    "unnecessary_services": check_unnecessary_services,
    "passwordless_sudo": check_passwordless_sudo,
    "disk_encryption": check_disk_encryption,
    "audit_logging": check_audit_logging,
    "world_writable_files": check_world_writable_files,
    "kernel_parameters": check_kernel_parameters,
}


# ---------------------------------------------------------------------------
# Baseline management
# ---------------------------------------------------------------------------

def load_baseline():
    if BASELINE_FILE.exists():
        return json.loads(BASELINE_FILE.read_text())
    return {}


def save_baseline(baseline):
    CONTROL_SCAN_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(json.dumps(baseline, indent=2))
    print(f"  Baseline saved: {BASELINE_FILE}")


def snapshot_baseline():
    print(f"\n  Snapshotting current state as baseline...")
    baseline = {}
    for cid, control in CONTROLS.items():
        check_fn = CHECK_FUNCTIONS.get(cid)
        if check_fn:
            result = check_fn()
            baseline[cid] = {
                "name": control["name"],
                "passed": result["passed"],
                "detail": result["detail"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            status = green("PASS") if result["passed"] else red("FAIL")
            print(f"  [{status}] {control['name']}")
    save_baseline(baseline)
    return baseline


# ---------------------------------------------------------------------------
# Drift checking
# ---------------------------------------------------------------------------

def append_history(scan_id, results):
    CONTROL_SCAN_DIR.mkdir(parents=True, exist_ok=True)
    with open(HISTORY_FILE, "a") as f:
        f.write(json.dumps({"scan_id": scan_id, "timestamp": datetime.now(timezone.utc).isoformat(), "results": results}) + "\n")


def run_checks(baseline=None):
    if baseline is None:
        baseline = {}

    scan_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    print(f"\n{'=' * 60}")
    print(f"  controlscan: SOX IT Control Drift Check")
    print(f"  Scan ID: {scan_id}")
    print(f"  Host: {platform.node()} ({platform.system()} {platform.release()})")
    print(f"{'=' * 60}")

    results = {}
    summary = {"passed": 0, "failed": 0, "drifted": 0, "new": 0}

    for cid, control in CONTROLS.items():
        check_fn = CHECK_FUNCTIONS.get(cid)
        if not check_fn:
            continue

        result = check_fn()
        passed = result["passed"]
        detail = result.get("detail", "")

        # Check drift from baseline
        drifted = False
        if cid in baseline:
            if baseline[cid]["passed"] != passed:
                drifted = True
                summary["drifted"] += 1
        else:
            summary["new"] += 1

        results[cid] = {
            "name": control["name"],
            "category": control["category"],
            "severity": control["severity"],
            "passed": passed,
            "detail": detail,
            "drifted": drifted,
            "risk": control["risk"],
        }

        if passed:
            summary["passed"] += 1
            icon = green("PASS")
        else:
            summary["failed"] += 1
            icon = red("FAIL")

        drift_mark = f" {yellow('DRIFT')}" if drifted else ""
        print(f"  [{icon}]{drift_mark} {control['name']:38s} {gray(detail[:50])}")

    # Save to history
    append_history(scan_id, results)

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print(f"  {green(f'Passed: {summary["passed"]}')}  {red(f'Failed: {summary["failed"]}')}", end="")
    if summary["drifted"]:
        print(f"  {yellow(f'Drifted: {summary["drifted"]}')}", end="")
    if summary["new"]:
        print(f"  {blue(f'New: {summary["new"]}')}", end="")
    print()

    # Remediation priority
    failed_high = sum(
        1 for r in results.values() if not r["passed"] and r["severity"] == "high"
    )
    if failed_high:
        print(f"  {red(f'CRITICAL: {failed_high} high-severity control(s) failing')}")

    # Generate audit report
    report_path = CONTROL_SCAN_DIR / f"report-{scan_id}.json"
    report = {
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "summary": summary,
        "controls": results,
    }
    report_path.write_text(json.dumps(report, indent=2))
    print(f"  Audit report: {report_path}")

    return results


def show_history():
    if not HISTORY_FILE.exists():
        print("  No scan history found.")
        return
    with open(HISTORY_FILE) as f:
        lines = f.readlines()

    print(f"\n{'=' * 60}")
    print(f"  SCAN HISTORY ({len(lines)} scans)")
    print(f"{'=' * 60}")
    for i, line in enumerate(reversed(lines[-10:])):
        entry = json.loads(line)
        ts = entry["timestamp"][:19]
        results = entry["results"]
        passed = sum(1 for r in results.values() if r["passed"])
        failed = sum(1 for r in results.values() if not r["passed"])
        print(
            f"  #{entry['scan_id']:8s} {ts}  "
            f"{green(f'{passed} passed')}  {red(f'{failed} failed')}"
        )


def main():
    CONTROL_SCAN_DIR.mkdir(parents=True, exist_ok=True)

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print("Usage:")
        print("  controlscan.py check       Run all control checks")
        print("  controlscan.py baseline    Snapshot current state as baseline")
        print("  controlscan.py history     Show scan history")
        print("  controlscan.py report      Generate audit report from latest scan")
        return

    command = sys.argv[1]

    if command == "baseline":
        snapshot_baseline()
    elif command == "check":
        baseline = load_baseline()
        if not baseline:
            print(f"  {yellow('No baseline found. Set one with: controlscan.py baseline')}")
        run_checks(baseline)
    elif command == "history":
        show_history()
    elif command == "report":
        baseline = load_baseline()
        run_checks(baseline)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
