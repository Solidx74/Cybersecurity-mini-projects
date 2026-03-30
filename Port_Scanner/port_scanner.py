#!/usr/bin/env python3
"""
Simple Port Scanner - Cybersecurity Mini Project
A fast, multi-threaded TCP port scanner with service detection.

Author: Kareeb Sadab
License: MIT
Version: 1.0
"""

import socket
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional

class Colors:
    """Terminal colors for better readability"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'

class PortScanner:
    """Simple and efficient TCP port scanner"""
    
    # Common services for better readability
    COMMON_SERVICES = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
        445: 'smb', 993: 'imaps', 995: 'pop3s', 3306: 'mysql', 3389: 'rdp',
        5432: 'postgresql', 5900: 'vnc', 8080: 'http-alt', 8443: 'https-alt'
    }
    
    def __init__(self, target: str, timeout: float = 1.0, threads: int = 50):
        self.target = self._resolve_target(target)
        self.timeout = timeout
        self.threads = min(threads, 200)  # Cap at 200 threads
        self.open_ports: List[Tuple[int, str]] = []
        
    def _resolve_target(self, target: str) -> str:
        """Convert domain to IP address"""
        try:
            # Check if it's already an IP
            socket.inet_aton(target)
            return target
        except socket.error:
            # Resolve domain name
            try:
                ip = socket.gethostbyname(target)
                print(f"{Colors.BLUE}[*] {target} → {ip}{Colors.END}")
                return ip
            except socket.gaierror:
                print(f"{Colors.RED}[!] Failed to resolve {target}{Colors.END}")
                sys.exit(1)
    
    def _get_service(self, port: int) -> str:
        """Get service name for a port"""
        try:
            return socket.getservbyport(port)
        except:
            return self.COMMON_SERVICES.get(port, 'unknown')
    
    def scan_port(self, port: int) -> Optional[Tuple[int, str]]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self._get_service(port)
                return (port, service)
        except:
            pass
        return None
    
    def scan(self, port_range: str) -> None:
        """Scan a range of ports"""
        try:
            start, end = map(int, port_range.split('-'))
            if start < 1 or end > 65535 or start > end:
                raise ValueError
        except:
            print(f"{Colors.RED}[!] Invalid port range. Use format: start-end (e.g., 1-1000){Colors.END}")
            sys.exit(1)
        
        total = end - start + 1
        print(f"{Colors.BLUE}[*] Scanning {self.target} (ports {start}-{end}){Colors.END}")
        print(f"{Colors.BLUE}[*] Threads: {self.threads} | Timeout: {self.timeout}s{Colors.END}")
        print(f"{Colors.YELLOW}[*] Total ports: {total}{Colors.END}\n")
        
        start_time = time.time()
        scanned = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, port): port 
                      for port in range(start, end + 1)}
            
            for future in futures:
                scanned += 1
                result = future.result()
                if result:
                    port, service = result
                    self.open_ports.append(result)
                    print(f"{Colors.GREEN}[+] OPEN{Colors.END}     {port:5d}/{service}")
                
                # Show progress
                if scanned % 50 == 0 or scanned == total:
                    percent = (scanned / total) * 100
                    print(f"\r{Colors.BLUE}[*] Progress: {scanned}/{total} ({percent:.1f}%){Colors.END}", 
                          end='', flush=True)
        
        elapsed = time.time() - start_time
        self._print_summary(elapsed)
    
    def _print_summary(self, elapsed: float) -> None:
        """Display scan results"""
        print(f"\n\n{Colors.GREEN}=== Scan Complete ==={Colors.END}")
        print(f"Target: {self.target}")
        print(f"Open ports: {len(self.open_ports)}")
        print(f"Time: {elapsed:.2f} seconds")
        
        if self.open_ports:
            print(f"\n{Colors.GREEN}Open Ports:{Colors.END}")
            for port, service in self.open_ports:
                print(f"  {port:5d}  {service}")
        else:
            print(f"\n{Colors.YELLOW}No open ports found{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description="Simple Port Scanner - Fast TCP port scanner with service detection",
        epilog="""
Examples:
  %(prog)s example.com                    # Scan common ports (1-1024)
  %(prog)s 192.168.1.1 -p 1-1000         # Scan specific range
  %(prog)s target.com -t 100 -to 2       # Fast scan with custom settings
        """
    )
    
    parser.add_argument('target', help='Target IP address or domain name')
    parser.add_argument('-p', '--ports', default='1-1024', 
                       help='Port range (default: 1-1024)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('-to', '--timeout', type=float, default=1.0,
                       help='Connection timeout in seconds (default: 1.0)')
    
    args = parser.parse_args()
    
    # Validate inputs
    if args.threads < 1:
        args.threads = 50
    if args.timeout < 0.1:
        args.timeout = 0.1
    
    print(f"\n{Colors.BLUE}=== Port Scanner v1.0 ==={Colors.END}\n")
    
    scanner = PortScanner(args.target, args.timeout, args.threads)
    
    try:
        scanner.scan(args.ports)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan cancelled{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
        sys.exit(1)

if __name__ == '__main__':
    main()