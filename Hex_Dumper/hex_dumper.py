#!/usr/bin/env python3
"""
Professional Hex Dumper Utility
A comprehensive hex dumping tool with multiple output formats and advanced features.
"""

import argparse
import os
import sys
from typing import Optional, List, Tuple
import textwrap
from datetime import datetime

class HexDumper:
    """Professional hex dumper with multiple output formats."""
    
    def __init__(self, bytes_per_line: int = 16, uppercase: bool = False, 
                 show_ascii: bool = True, show_offset: bool = True,
                 offset_format: str = 'hex', color: bool = False):
        """
        Initialize hex dumper with configuration.
        
        Args:
            bytes_per_line: Number of bytes to display per line
            uppercase: Use uppercase for hex digits
            show_ascii: Show ASCII representation
            show_offset: Show offset column
            offset_format: 'hex' or 'dec' for offset format
            color: Enable colored output
        """
        self.bytes_per_line = bytes_per_line
        self.uppercase = uppercase
        self.show_ascii = show_ascii
        self.show_offset = show_offset
        self.offset_format = offset_format
        self.color = color
        
        # ANSI color codes
        self.colors = {
            'offset': '\033[36m',      # Cyan
            'hex': '\033[0m',          # Default
            'ascii': '\033[32m',       # Green
            'reset': '\033[0m'
        } if color else {k: '' for k in ['offset', 'hex', 'ascii', 'reset']}
    
    def format_offset(self, offset: int) -> str:
        """Format offset value based on configuration."""
        if self.offset_format == 'hex':
            return f'{offset:08x}'
        else:
            return f'{offset:08d}'
    
    def format_hex_byte(self, byte: int) -> str:
        """Format a single hex byte."""
        hex_str = f'{byte:02x}'
        if self.uppercase:
            hex_str = hex_str.upper()
        return hex_str
    
    def dump_bytes(self, data: bytes, start_offset: int = 0) -> List[str]:
        """
        Dump bytes in formatted lines.
        
        Args:
            data: Bytes to dump
            start_offset: Starting offset for display
            
        Returns:
            List of formatted lines
        """
        lines = []
        total_bytes = len(data)
        
        for i in range(0, total_bytes, self.bytes_per_line):
            offset = start_offset + i
            chunk = data[i:i + self.bytes_per_line]
            
            # Build the line
            line_parts = []
            
            # Offset column
            if self.show_offset:
                offset_str = self.format_offset(offset)
                line_parts.append(f"{self.colors['offset']}{offset_str}{self.colors['reset']}")
            
            # Hex bytes column
            hex_bytes = []
            for j, byte in enumerate(chunk):
                hex_bytes.append(self.format_hex_byte(byte))
                # Add extra space after half the bytes for readability
                if j == self.bytes_per_line // 2 - 1:
                    hex_bytes.append(' ')
            
            hex_str = ' '.join(hex_bytes)
            # Pad with spaces for missing bytes
            padding_needed = (self.bytes_per_line - len(chunk)) * 3
            if len(chunk) <= self.bytes_per_line // 2:
                padding_needed += 1  # Extra space for half-line alignment
            hex_str = hex_str.ljust(self.bytes_per_line * 3 + 1)
            
            line_parts.append(f"{self.colors['hex']}{hex_str}{self.colors['reset']}")
            
            # ASCII column
            if self.show_ascii:
                ascii_str = ''
                for byte in chunk:
                    if 32 <= byte <= 126:  # Printable ASCII
                        ascii_str += chr(byte)
                    else:
                        ascii_str += '.'
                ascii_str = ascii_str.ljust(self.bytes_per_line)
                line_parts.append(f"{self.colors['ascii']}{ascii_str}{self.colors['reset']}")
            
            lines.append(' '.join(line_parts))
        
        return lines
    
    def dump_file(self, filepath: str, offset: int = 0, length: Optional[int] = None) -> None:
        """
        Dump contents of a file.
        
        Args:
            filepath: Path to the file
            offset: Starting offset in file
            length: Number of bytes to dump (None for entire file)
        """
        try:
            with open(filepath, 'rb') as f:
                # Seek to offset
                f.seek(offset)
                
                # Read specified length or entire file
                if length is not None:
                    data = f.read(length)
                else:
                    data = f.read()
                
                # Print header
                self._print_header(filepath, len(data), offset)
                
                # Dump the data
                lines = self.dump_bytes(data, offset)
                for line in lines:
                    print(line)
                
                # Print footer
                if len(data) == 0:
                    print("(Empty file or no data in specified range)")
                
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.", file=sys.stderr)
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied for '{filepath}'.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    
    def dump_stdin(self) -> None:
        """Dump data from standard input."""
        try:
            data = sys.stdin.buffer.read()
            self._print_header("stdin", len(data), 0)
            lines = self.dump_bytes(data, 0)
            for line in lines:
                print(line)
        except KeyboardInterrupt:
            print("\nInterrupted by user.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading stdin: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _print_header(self, source: str, size: int, offset: int) -> None:
        """Print dump header information."""
        print(f"{'=' * 80}")
        print(f"Hex Dump: {source}")
        print(f"Size: {size} bytes")
        print(f"Offset: {self.format_offset(offset)}")
        print(f"Bytes per line: {self.bytes_per_line}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 80}")
        print()

def main():
    """Main entry point for the hex dumper."""
    parser = argparse.ArgumentParser(
        description='Professional Hex Dumper - Display file contents in hexadecimal',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        Examples:
          %(prog)s file.bin                    # Dump entire file
          %(prog)s -o 0x100 -n 256 file.bin    # Dump 256 bytes from offset 0x100
          %(prog)s -b 8 file.bin               # Display 8 bytes per line
          %(prog)s -U file.bin                 # Uppercase hex digits
          %(prog)s -a                          # Show only hex (hide ASCII)
          cat file.bin | %(prog)s              # Read from stdin
          %(prog)s -c file.bin                 # Enable colored output
        ''')
    )
    
    parser.add_argument(
        'file',
        nargs='?',
        help='File to dump (if not provided, reads from stdin)'
    )
    
    parser.add_argument(
        '-o', '--offset',
        type=lambda x: int(x, 0),
        default=0,
        help='Starting offset (decimal or hex with 0x prefix)'
    )
    
    parser.add_argument(
        '-n', '--length',
        type=lambda x: int(x, 0),
        help='Number of bytes to dump'
    )
    
    parser.add_argument(
        '-b', '--bytes-per-line',
        type=int,
        default=16,
        help='Bytes per line (default: 16)'
    )
    
    parser.add_argument(
        '-U', '--uppercase',
        action='store_true',
        help='Use uppercase hex digits'
    )
    
    parser.add_argument(
        '-a', '--no-ascii',
        action='store_true',
        help='Hide ASCII column'
    )
    
    parser.add_argument(
        '-A', '--offset-format',
        choices=['hex', 'dec'],
        default='hex',
        help='Offset format: hex or dec (default: hex)'
    )
    
    parser.add_argument(
        '--no-offset',
        action='store_true',
        help='Hide offset column'
    )
    
    parser.add_argument(
        '-c', '--color',
        action='store_true',
        help='Enable colored output'
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Validate bytes per line
    if args.bytes_per_line < 1:
        print("Error: Bytes per line must be at least 1", file=sys.stderr)
        sys.exit(1)
    
    # Create dumper instance
    dumper = HexDumper(
        bytes_per_line=args.bytes_per_line,
        uppercase=args.uppercase,
        show_ascii=not args.no_ascii,
        show_offset=not args.no_offset,
        offset_format=args.offset_format,
        color=args.color
    )
    
    # Dump file or stdin
    try:
        if args.file:
            dumper.dump_file(args.file, args.offset, args.length)
        else:
            if args.offset != 0:
                print("Warning: --offset is ignored when reading from stdin", file=sys.stderr)
            if args.length is not None:
                print("Warning: --length is ignored when reading from stdin", file=sys.stderr)
            dumper.dump_stdin()
    except BrokenPipeError:
        # Handle pipe being closed (e.g., when piping to head)
        sys.stderr.close()
        sys.exit(0)

if __name__ == '__main__':
    main()