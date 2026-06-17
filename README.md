# controlscan
> Lightweight CLI for IT control drift detection

```
$ controlscan check --baseline baseline.yaml --host web-01.internal
[PASS] sshd:PermitRootLogin = no
[PASS] sshd:PasswordAuthentication = no
[FAIL] sysctl:net.ipv4.ip_forward = 0  (current: 1)
[PASS] firewall:default-deny = true
Result: 3 PASS, 1 FAIL — drift detected
```

## Overview
A lightweight CLI that compares current system security control values against a baseline YAML and flags configuration drift. Designed for IT teams who need a fast, agentless way to audit Linux/Windows hosts against CIS benchmarks or internal baselines.

## Features
- YAML-based baselines (human-readable, version-controllable)
- Pluggable check modules (sshd, sysctl, firewall, packages, etc.)
- Single-binary, no agent install
- Exit codes for CI integration (0 = clean, 1 = drift, 2 = error)

## Tech Stack
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) ![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## Installation
```bash
git clone https://github.com/MeGaurav4/controlscan.git
cd controlscan
pip install -e .
```

## Usage
```bash
controlscan check --baseline baseline.yaml --host web-01.internal
controlscan check --baseline baseline.yaml --inventory hosts.txt --format json
```

## License
MIT