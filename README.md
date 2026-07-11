# huginn

Blue team cybersecurity posture assessment CLI. Collects system configuration data and evaluates it against CIS Benchmarks and NIST controls to identify security misconfigurations.

**Platform support:** Windows (primary), Linux

---

## Features

- Low-level OS calls — minimal detection footprint
- Findings aligned to CIS Benchmarks and NIST 800-53
- Self-contained HTML report with sortable/filterable findings table
- BloodHound v4-compatible JSON output (`computers` ingest format)
- Ships as a single binary with no runtime dependencies

## Quick start

```sh
# Collect, analyze, and generate all reports in one step (default)
huginn run

# Outputs written to ./huginn-output/
#   huginn-report.json       — full report (findings + system info)
#   huginn-report.html       — self-contained HTML report
#   huginn-bloodhound.json   — BloodHound v4 ingest file
```

## Usage

```
huginn [OPTIONS] [COMMAND]

Commands:
  run       Collect + analyze + report [default]
  collect   Collect raw system data → huginn-collection.json
  analyze   Analyze a collected JSON file → reports
  report    Re-render reports from an existing huginn-report.json

Options:
  -o, --output <FORMAT>     json | html | bloodhound | all  [default: all]
  -d, --dir <PATH>          Output directory  [default: ./huginn-output]
  -q, --quiet               Suppress progress output
      --collectors <LIST>   Comma-separated subset of collectors to run
      --include-passed      Include passed checks in output
```

### Offline workflow

Collect on the target, analyze on another machine:

```sh
# On the target (no internet required)
huginn collect -d /tmp/huginn

# Transfer huginn-collection.json, then analyze offline
huginn analyze -i huginn-collection.json -d ./reports
```

## Security checks

| ID | Check | Severity |
|----|-------|----------|
| CIS-1.1.1 | Minimum password length < 14 | High |
| CIS-1.1.2 | Maximum password age not configured | Medium / Low |
| CIS-1.1.3 | Password history < 24 | Medium |
| CIS-1.1.4 | Password complexity disabled | High |
| CIS-1.1.5 | Reversible password encryption enabled | Critical |
| CIS-1.2.1 | Account lockout threshold not set | High |
| CIS-1.2.2 | Lockout duration too short | Low |
| CIS-1.2.3 | Lockout observation window too short | Low |
| CIS-2.3.7 | UAC disabled | Critical |
| CIS-2.3.7 | UAC secure desktop disabled | Medium |
| CIS-2.3.11 | LSA protection disabled | High |
| CIS-2.3.11 | Credential Guard disabled | High |
| CIS-2.3.11 | Windows Defender disabled | Critical |
| CIS-5 | Services with unquoted binary paths | High |
| CIS-5 | Services with weak ACLs | High |
| CIS-9 | Firewall profile disabled | Critical / High |
| CIS-18 | SMBv1 enabled | High |

## Building from source

Requires Rust 1.85+ (edition 2024).

```sh
git clone https://github.com/cloudhalla/huginn
cd huginn
cargo build --release
# Binary: target/release/huginn
```

Windows cross-compilation from Linux:

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

## BloodHound integration

Import `huginn-bloodhound.json` into BloodHound via the upload button. The computer node will carry a `HuginnAssessment` property with risk score, finding counts, and top findings for quick triage in Cypher queries:

```cypher
MATCH (c:Computer)
WHERE c.huginn_risk_score >= 70
RETURN c.name, c.huginn_risk_score, c.huginn_critical ORDER BY c.huginn_risk_score DESC
```

## License

MIT
