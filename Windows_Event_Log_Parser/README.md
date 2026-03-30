# Windows Event Log Parser for SOC Analysis

A professional Python tool to parse Windows `.evtx` files and extract security events, login attempts, and critical alerts for SOC investigations.

## Features

- 🔍 Parse single `.evtx` files or entire directories
- 📊 Extract 30+ critical security event IDs (logons, account changes, process creation)
- 📁 Export to **CSV**, **JSON**, and **HTML** report formats
- 🚨 Identify high-severity alerts automatically
- 📈 Generate summary statistics with login success/failure rates
- 🎨 Color-coded console output for easy analysis


## Output Files

The tool generates the following files in the output directory:

| File | Description |
|------|-------------|
| `all_events_*.csv` | Complete event list |
| `security_events_*.csv` | Security-relevant events only |
| `login_attempts_*.csv` | All login events (successful/failed) |
| `alerts_*.csv` | High severity events |
| `parsed_events_*.json` | Full JSON export |
| `soc_report_*.html` | Professional HTML report |


## Supported Event IDs
Logon Events: 4624 (success), 4625 (failed), 4648, 4672

Account Management: 4720-4726, 4732-4733

Process Creation: 4688-4689

Service Events: 4697-4699

System Events: 6005-6008

PowerShell: 4103-4104

# Author
Kareeb Sadab
CUET CSE