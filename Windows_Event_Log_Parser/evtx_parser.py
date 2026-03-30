#!/usr/bin/env python3
"""
Professional Windows Event Log Parser for SOC Analysis
Author: Security Analyst
Purpose: Parse .evtx files to extract security events, login attempts, and alerts
"""

import argparse
import csv
import json
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import re

try:
    import evtx
    from evtx import PyEvtxParser
except ImportError:
    print("Error: python-evtx library not installed.")
    print("Install with: pip install python-evtx")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    # Fallback if colorama not installed
    COLOR_ENABLED = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = RESET = ''
    Style = Fore


class WindowsEventLogParser:
    """Professional Windows Event Log Parser for SOC Analysis"""
    
    # Critical Event IDs for Security Monitoring
    SECURITY_EVENTS = {
        # Logon Events
        4624: {"name": "Successful Logon", "severity": "INFO"},
        4625: {"name": "Failed Logon", "severity": "HIGH"},
        4648: {"name": "Explicit Credential Logon", "severity": "MEDIUM"},
        4672: {"name": "Special Privileges Assigned", "severity": "HIGH"},
        
        # Account Management
        4720: {"name": "User Account Created", "severity": "MEDIUM"},
        4722: {"name": "User Account Enabled", "severity": "MEDIUM"},
        4723: {"name": "Password Change Attempt", "severity": "MEDIUM"},
        4724: {"name": "Password Reset", "severity": "HIGH"},
        4725: {"name": "User Account Disabled", "severity": "MEDIUM"},
        4726: {"name": "User Account Deleted", "severity": "HIGH"},
        4732: {"name": "Member Added to Security Group", "severity": "MEDIUM"},
        4733: {"name": "Member Removed from Security Group", "severity": "MEDIUM"},
        
        # Process Creation
        4688: {"name": "Process Creation", "severity": "INFO"},
        4689: {"name": "Process Termination", "severity": "INFO"},
        
        # Service Events
        4697: {"name": "Service Installation", "severity": "HIGH"},
        4698: {"name": "Scheduled Task Created", "severity": "HIGH"},
        4699: {"name": "Scheduled Task Deleted", "severity": "MEDIUM"},
        
        # Object Access
        4656: {"name": "Handle to Object Requested", "severity": "MEDIUM"},
        4663: {"name": "Object Access Attempt", "severity": "MEDIUM"},
        
        # Policy Changes
        4719: {"name": "System Audit Policy Changed", "severity": "HIGH"},
        4902: {"name": "Per-User Audit Policy Created", "severity": "MEDIUM"},
        
        # Firewall
        4946: {"name": "Firewall Rule Added", "severity": "HIGH"},
        4947: {"name": "Firewall Rule Modified", "severity": "MEDIUM"},
        4948: {"name": "Firewall Rule Deleted", "severity": "MEDIUM"},
        
        # PowerShell
        4103: {"name": "PowerShell Script Block Logging", "severity": "MEDIUM"},
        4104: {"name": "PowerShell Remote Session", "severity": "MEDIUM"},
    }
    
    # Additional events for comprehensive analysis
    ADDITIONAL_EVENTS = {
        # System Events
        1: {"name": "System Startup", "severity": "INFO"},
        12: {"name": "System Shutdown", "severity": "INFO"},
        6005: {"name": "Event Log Service Started", "severity": "INFO"},
        6006: {"name": "Event Log Service Stopped", "severity": "INFO"},
        6008: {"name": "Unexpected Shutdown", "severity": "HIGH"},
        
        # Application Events
        1000: {"name": "Application Error", "severity": "MEDIUM"},
        1001: {"name": "Application Crash", "severity": "MEDIUM"},
    }
    
    ALL_EVENTS = {**SECURITY_EVENTS, **ADDITIONAL_EVENTS}
    
    def __init__(self, input_file: str, output_dir: str = "output"):
        """
        Initialize the parser with input file and output directory
        
        Args:
            input_file: Path to .evtx file or directory containing .evtx files
            output_dir: Directory to store output files
        """
        self.input_path = Path(input_file)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Data storage
        self.events = []
        self.login_attempts = []
        self.security_events = []
        self.alerts = []
        self.summary_stats = {
            "total_events": 0,
            "security_events": 0,
            "login_attempts": 0,
            "critical_alerts": 0,
            "failed_logons": 0,
            "successful_logons": 0,
            "account_changes": 0,
            "process_creations": 0,
            "unique_users": set(),
            "unique_sources": set(),
            "time_range": {"start": None, "end": None}
        }
    
    def parse_evtx_file(self, evtx_file: Path) -> List[Dict]:
        """
        Parse a single .evtx file
        
        Args:
            evtx_file: Path to .evtx file
            
        Returns:
            List of parsed events
        """
        print(f"{Fore.CYAN}[*] Parsing: {evtx_file}")
        
        try:
            parser = PyEvtxParser(str(evtx_file))
            events = []
            
            for record in parser.records():
                try:
                    event_data = self.process_event_record(record, evtx_file)
                    if event_data:
                        events.append(event_data)
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error processing record: {e}")
                    continue
            
            print(f"{Fore.GREEN}[+] Parsed {len(events)} events from {evtx_file.name}")
            return events
            
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to parse {evtx_file}: {e}")
            return []
    
    def process_event_record(self, record: Dict, source_file: Path) -> Optional[Dict]:
        """
        Process a single event record and extract relevant information
        
        Args:
            record: Raw event record from parser
            source_file: Source file path
            
        Returns:
            Processed event dictionary or None if invalid
        """
        try:
            event = record.get("data", {})
            if not event:
                return None
            
            # Extract basic event information
            event_id = event.get("EventID", {}).get("#text", 0)
            if isinstance(event_id, str):
                event_id = int(event_id) if event_id.isdigit() else 0
            
            event_time = event.get("System", {}).get("TimeCreated", {}).get("@SystemTime", "")
            
            # Parse event data
            processed_event = {
                "source_file": source_file.name,
                "event_id": event_id,
                "event_name": self.ALL_EVENTS.get(event_id, {}).get("name", "Unknown Event"),
                "severity": self.ALL_EVENTS.get(event_id, {}).get("severity", "INFO"),
                "timestamp": self.parse_timestamp(event_time),
                "raw_data": event
            }
            
            # Extract event-specific details
            if event_id == 4624:  # Successful logon
                self.process_logon_event(processed_event, event)
                self.login_attempts.append(processed_event)
                self.summary_stats["successful_logons"] += 1
                
            elif event_id == 4625:  # Failed logon
                self.process_failed_logon(processed_event, event)
                self.login_attempts.append(processed_event)
                self.summary_stats["failed_logons"] += 1
                
            elif event_id in [4720, 4722, 4723, 4724, 4725, 4726, 4732, 4733]:
                self.process_account_event(processed_event, event)
                self.summary_stats["account_changes"] += 1
                
            elif event_id == 4688:  # Process creation
                self.process_process_event(processed_event, event)
                self.summary_stats["process_creations"] += 1
            
            # Categorize events
            if event_id in self.SECURITY_EVENTS or event_id in self.ADDITIONAL_EVENTS:
                self.security_events.append(processed_event)
                self.summary_stats["security_events"] += 1
            
            # Check for alerts (High severity events)
            if processed_event["severity"] == "HIGH":
                self.alerts.append(processed_event)
                self.summary_stats["critical_alerts"] += 1
            
            # Update summary statistics
            self.summary_stats["total_events"] += 1
            self.update_summary_stats(processed_event)
            
            return processed_event
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error processing record: {e}")
            return None
    
    def process_logon_event(self, processed_event: Dict, event_data: Dict):
        """Extract logon event details"""
        try:
            event = event_data.get("EventData", {}).get("Data", [])
            data_dict = {item.get("@Name", ""): item.get("#text", "") for item in event}
            
            processed_event.update({
                "username": data_dict.get("TargetUserName", "N/A"),
                "domain": data_dict.get("TargetDomainName", "N/A"),
                "logon_type": self.get_logon_type(data_dict.get("LogonType", "")),
                "logon_id": data_dict.get("TargetLogonId", "N/A"),
                "source_ip": data_dict.get("IpAddress", "N/A"),
                "source_host": data_dict.get("WorkstationName", "N/A"),
                "process_name": data_dict.get("ProcessName", "N/A"),
                "authentication_package": data_dict.get("AuthenticationPackageName", "N/A"),
                "key_length": data_dict.get("KeyLength", "N/A")
            })
            
            # Track unique users and sources
            if processed_event["username"] not in ["N/A", "-", ""]:
                self.summary_stats["unique_users"].add(f"{processed_event['domain']}\\{processed_event['username']}")
            if processed_event["source_ip"] not in ["N/A", "-", "", "::1", "127.0.0.1"]:
                self.summary_stats["unique_sources"].add(processed_event["source_ip"])
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error processing logon event: {e}")
    
    def process_failed_logon(self, processed_event: Dict, event_data: Dict):
        """Extract failed logon event details"""
        try:
            event = event_data.get("EventData", {}).get("Data", [])
            data_dict = {item.get("@Name", ""): item.get("#text", "") for item in event}
            
            processed_event.update({
                "username": data_dict.get("TargetUserName", "N/A"),
                "domain": data_dict.get("TargetDomainName", "N/A"),
                "logon_type": self.get_logon_type(data_dict.get("LogonType", "")),
                "source_ip": data_dict.get("IpAddress", "N/A"),
                "source_host": data_dict.get("WorkstationName", "N/A"),
                "failure_reason": data_dict.get("Status", "N/A"),
                "sub_status": data_dict.get("SubStatus", "N/A"),
                "authentication_package": data_dict.get("AuthenticationPackageName", "N/A")
            })
            
            # Track unique sources for failed logons
            if processed_event["source_ip"] not in ["N/A", "-", ""]:
                self.summary_stats["unique_sources"].add(processed_event["source_ip"])
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error processing failed logon: {e}")
    
    def process_account_event(self, processed_event: Dict, event_data: Dict):
        """Extract account management event details"""
        try:
            event = event_data.get("EventData", {}).get("Data", [])
            data_dict = {item.get("@Name", ""): item.get("#text", "") for item in event}
            
            processed_event.update({
                "target_user": data_dict.get("TargetUserName", "N/A"),
                "target_domain": data_dict.get("TargetDomainName", "N/A"),
                "subject_user": data_dict.get("SubjectUserName", "N/A"),
                "subject_domain": data_dict.get("SubjectDomainName", "N/A"),
                "subject_logon_id": data_dict.get("SubjectLogonId", "N/A")
            })
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error processing account event: {e}")
    
    def process_process_event(self, processed_event: Dict, event_data: Dict):
        """Extract process creation event details"""
        try:
            event = event_data.get("EventData", {}).get("Data", [])
            data_dict = {item.get("@Name", ""): item.get("#text", "") for item in event}
            
            processed_event.update({
                "process_name": data_dict.get("NewProcessName", "N/A"),
                "creator_process": data_dict.get("CreatorProcessName", "N/A"),
                "process_id": data_dict.get("NewProcessId", "N/A"),
                "creator_id": data_dict.get("CreatorProcessId", "N/A"),
                "username": data_dict.get("TargetUserName", "N/A"),
                "domain": data_dict.get("TargetDomainName", "N/A")
            })
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error processing process event: {e}")
    
    @staticmethod
    def get_logon_type(logon_type: str) -> str:
        """Convert logon type number to description"""
        logon_types = {
            "2": "Interactive (Local Logon)",
            "3": "Network (Remote Logon)",
            "4": "Batch (Scheduled Tasks)",
            "5": "Service (Service Account)",
            "7": "Unlock (Workstation Unlock)",
            "8": "NetworkCleartext (Network with Cleartext)",
            "9": "NewCredentials (RunAs)",
            "10": "RemoteInteractive (RDP)",
            "11": "CachedInteractive (Cached Credentials)"
        }
        return logon_types.get(logon_type, f"Unknown ({logon_type})")
    
    @staticmethod
    def parse_timestamp(timestamp_str: str) -> str:
        """Parse and format timestamp"""
        try:
            if timestamp_str:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
        return "Unknown"
    
    def update_summary_stats(self, event: Dict):
        """Update summary statistics with event data"""
        timestamp = event.get("timestamp")
        if timestamp != "Unknown":
            try:
                dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                if not self.summary_stats["time_range"]["start"] or dt < self.summary_stats["time_range"]["start"]:
                    self.summary_stats["time_range"]["start"] = dt
                if not self.summary_stats["time_range"]["end"] or dt > self.summary_stats["time_range"]["end"]:
                    self.summary_stats["time_range"]["end"] = dt
            except:
                pass
    
    def parse_all(self) -> bool:
        """
        Parse all .evtx files from input path
        
        Returns:
            True if successful, False otherwise
        """
        evtx_files = []
        
        if self.input_path.is_file() and self.input_path.suffix.lower() == '.evtx':
            evtx_files = [self.input_path]
        elif self.input_path.is_dir():
            evtx_files = list(self.input_path.glob("*.evtx"))
            if not evtx_files:
                print(f"{Fore.RED}[!] No .evtx files found in {self.input_path}")
                return False
        else:
            print(f"{Fore.RED}[!] Invalid input: {self.input_path}")
            return False
        
        print(f"{Fore.CYAN}[*] Found {len(evtx_files)} .evtx file(s) to process")
        
        for evtx_file in evtx_files:
            events = self.parse_evtx_file(evtx_file)
            self.events.extend(events)
        
        print(f"{Fore.GREEN}[+] Total events parsed: {len(self.events)}")
        return True
    
    def export_csv(self):
        """Export parsed events to CSV files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export all events
        all_events_file = self.output_dir / f"all_events_{timestamp}.csv"
        self._write_csv(all_events_file, self.events, "all_events")
        
        # Export security events
        security_file = self.output_dir / f"security_events_{timestamp}.csv"
        self._write_csv(security_file, self.security_events, "security_events")
        
        # Export login attempts
        login_file = self.output_dir / f"login_attempts_{timestamp}.csv"
        self._write_csv(login_file, self.login_attempts, "login_attempts")
        
        # Export alerts
        alerts_file = self.output_dir / f"alerts_{timestamp}.csv"
        self._write_csv(alerts_file, self.alerts, "alerts")
        
        print(f"{Fore.GREEN}[+] CSV exports completed in {self.output_dir}")
    
    def _write_csv(self, filename: Path, data: List[Dict], data_type: str):
        """Write data to CSV file"""
        if not data:
            print(f"{Fore.YELLOW}[!] No {data_type} data to export")
            return
        
        try:
            # Collect all keys from all dictionaries
            all_keys = set()
            for item in data:
                all_keys.update(item.keys())
            
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=sorted(all_keys))
                writer.writeheader()
                writer.writerows(data)
            
            print(f"{Fore.GREEN}[+] Exported {len(data)} {data_type} to {filename}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error exporting {data_type} to CSV: {e}")
    
    def export_json(self):
        """Export parsed events to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = self.output_dir / f"parsed_events_{timestamp}.json"
        
        export_data = {
            "summary": self.get_summary(),
            "events": self.events
        }
        
        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            print(f"{Fore.GREEN}[+] Exported JSON data to {json_file}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error exporting to JSON: {e}")
    
    def generate_report(self):
        """Generate HTML report for SOC analysis"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"soc_report_{timestamp}.html"
        
        summary = self.get_summary()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SOC Analysis Report - Windows Event Logs</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: auto;
                    background-color: white;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }}
                h1 {{
                    color: #333;
                    border-bottom: 3px solid #4CAF50;
                    padding-bottom: 10px;
                }}
                h2 {{
                    color: #555;
                    margin-top: 20px;
                }}
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 15px;
                    margin: 20px 0;
                }}
                .card {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 10px;
                    text-align: center;
                }}
                .card.high {{
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                }}
                .card.medium {{
                    background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                }}
                .card h3 {{
                    margin: 0 0 10px 0;
                    font-size: 14px;
                    opacity: 0.9;
                }}
                .card .number {{
                    font-size: 32px;
                    font-weight: bold;
                    margin: 10px 0;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                th, td {{
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                }}
                th {{
                    background-color: #4CAF50;
                    color: white;
                }}
                tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                .alert {{
                    background-color: #ffeb3b;
                    padding: 10px;
                    border-left: 4px solid #f44336;
                    margin: 10px 0;
                }}
                .timestamp {{
                    color: #666;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 SOC Analysis Report - Windows Event Logs</h1>
                <p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                
                <h2>📊 Executive Summary</h2>
                <div class="summary">
                    <div class="card">
                        <h3>Total Events</h3>
                        <div class="number">{summary['total_events']:,}</div>
                    </div>
                    <div class="card medium">
                        <h3>Security Events</h3>
                        <div class="number">{summary['security_events']:,}</div>
                    </div>
                    <div class="card high">
                        <h3>Critical Alerts</h3>
                        <div class="number">{summary['critical_alerts']:,}</div>
                    </div>
                    <div class="card">
                        <h3>Login Attempts</h3>
                        <div class="number">{summary['login_attempts']:,}</div>
                    </div>
                </div>
                
                <div class="summary">
                    <div class="card">
                        <h3>✅ Successful Logons</h3>
                        <div class="number">{summary['successful_logons']:,}</div>
                    </div>
                    <div class="card high">
                        <h3>❌ Failed Logons</h3>
                        <div class="number">{summary['failed_logons']:,}</div>
                    </div>
                    <div class="card">
                        <h3>Account Changes</h3>
                        <div class="number">{summary['account_changes']:,}</div>
                    </div>
                    <div class="card">
                        <h3>Process Creations</h3>
                        <div class="number">{summary['process_creations']:,}</div>
                    </div>
                </div>
                
                <h2>👥 User Statistics</h2>
                <p><strong>Unique Users:</strong> {summary['unique_users']}</p>
                <p><strong>Unique Source IPs:</strong> {summary['unique_sources']}</p>
                
                <h2>⏰ Time Range</h2>
                <p><strong>Start:</strong> {summary['time_range']['start'] or 'N/A'}</p>
                <p><strong>End:</strong> {summary['time_range']['end'] or 'N/A'}</p>
                
                <h2>⚠️ Critical Alerts</h2>
                <table>
                    <thead>
                        <tr><th>Timestamp</th><th>Event ID</th><th>Event Name</th><th>Details</th></tr>
                    </thead>
                    <tbody>
        """
        
        # Add top 20 alerts to report
        for alert in self.alerts[:20]:
            details = ""
            if alert.get('username'):
                details += f"User: {alert.get('username')} | "
            if alert.get('source_ip'):
                details += f"Source: {alert.get('source_ip')} | "
            if alert.get('process_name'):
                details += f"Process: {alert.get('process_name')}"
            
            html_content += f"""
                <tr>
                    <td>{alert.get('timestamp', 'N/A')}</td>
                    <td>{alert.get('event_id', 'N/A')}</td>
                    <td>{alert.get('event_name', 'N/A')}</td>
                    <td>{details}</td>
                </tr>
            """
        
        html_content += """
                    </tbody>
                </table>
                
                <h2>🔐 Top Failed Logons</h2>
                <table>
                    <thead>
                        <tr><th>Timestamp</th><th>Username</th><th>Source IP</th><th>Failure Reason</th></tr>
                    </thead>
                    <tbody>
        """
        
        # Add failed logons to report
        failed_logons = [l for l in self.login_attempts if l.get('event_id') == 4625]
        for logon in failed_logons[:20]:
            html_content += f"""
                <tr>
                    <td>{logon.get('timestamp', 'N/A')}</td>
                    <td>{logon.get('username', 'N/A')}</td>
                    <td>{logon.get('source_ip', 'N/A')}</td>
                    <td>{logon.get('failure_reason', 'N/A')}</td>
                </tr>
            """
        
        html_content += """
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"{Fore.GREEN}[+] HTML report generated: {report_file}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error generating HTML report: {e}")
    
    def get_summary(self) -> Dict:
        """Get summary statistics as dictionary"""
        return {
            "total_events": self.summary_stats["total_events"],
            "security_events": self.summary_stats["security_events"],
            "login_attempts": len(self.login_attempts),
            "critical_alerts": self.summary_stats["critical_alerts"],
            "failed_logons": self.summary_stats["failed_logons"],
            "successful_logons": self.summary_stats["successful_logons"],
            "account_changes": self.summary_stats["account_changes"],
            "process_creations": self.summary_stats["process_creations"],
            "unique_users": len(self.summary_stats["unique_users"]),
            "unique_sources": len(self.summary_stats["unique_sources"]),
            "time_range": {
                "start": self.summary_stats["time_range"]["start"].strftime("%Y-%m-%d %H:%M:%S") if self.summary_stats["time_range"]["start"] else None,
                "end": self.summary_stats["time_range"]["end"].strftime("%Y-%m-%d %H:%M:%S") if self.summary_stats["time_range"]["end"] else None
            }
        }
    
    def print_summary(self):
        """Print summary statistics to console"""
        summary = self.get_summary()
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Windows Event Log Analysis Summary")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"{Fore.GREEN}Total Events Parsed: {summary['total_events']:,}")
        print(f"{Fore.YELLOW}Security Events: {summary['security_events']:,}")
        print(f"{Fore.RED}Critical Alerts: {summary['critical_alerts']:,}")
        print(f"{Fore.BLUE}Login Attempts: {summary['login_attempts']:,}")
        print(f"  - Successful: {summary['successful_logons']:,}")
        print(f"  - Failed: {summary['failed_logons']:,}")
        print(f"\nAccount Changes: {summary['account_changes']:,}")
        print(f"Process Creations: {summary['process_creations']:,}")
        print(f"\nUnique Users: {summary['unique_users']}")
        print(f"Unique Source IPs: {summary['unique_sources']}")
        
        if summary['time_range']['start']:
            print(f"\nTime Range:")
            print(f"  Start: {summary['time_range']['start']}")
            print(f"  End: {summary['time_range']['end']}")
        
        print(f"{Fore.CYAN}{'='*60}\n")


def main():
    """Main function to run the parser"""
    parser = argparse.ArgumentParser(
        description="Professional Windows Event Log Parser for SOC Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse a single .evtx file
  python evtx_parser.py -i security.evtx
  
  # Parse all .evtx files in a directory
  python evtx_parser.py -i C:\\Windows\\Logs\\Security\\ -o output
  
  # Generate JSON output only
  python evtx_parser.py -i security.evtx -f json
  
  # Generate all outputs (CSV, JSON, HTML)
  python evtx_parser.py -i security.evtx -f all
        """
    )
    
    parser.add_argument("-i", "--input", required=True, help="Input .evtx file or directory")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: output)")
    parser.add_argument("-f", "--format", choices=['csv', 'json', 'html', 'all'], 
                       default='all', help="Output format (default: all)")
    
    args = parser.parse_args()
    
    # Check if input exists
    if not os.path.exists(args.input):
        print(f"{Fore.RED}[!] Input path does not exist: {args.input}")
        sys.exit(1)
    
    # Create parser instance
    log_parser = WindowsEventLogParser(args.input, args.output)
    
    # Parse events
    if not log_parser.parse_all():
        print(f"{Fore.RED}[!] Parsing failed")
        sys.exit(1)
    
    # Print summary
    log_parser.print_summary()
    
    # Export based on format
    if args.format in ['csv', 'all']:
        log_parser.export_csv()
    
    if args.format in ['json', 'all']:
        log_parser.export_json()
    
    if args.format in ['html', 'all']:
        log_parser.generate_report()
    
    print(f"{Fore.GREEN}[+] Analysis complete! Output saved to: {args.output}")


if __name__ == "__main__":
    main()