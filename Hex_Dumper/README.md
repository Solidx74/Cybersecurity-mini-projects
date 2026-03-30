# Hex Dumper - Professional Binary Analysis Tool

A powerful, feature-rich hex dumper written in Python for analyzing binary files and data streams. Perfect for reverse engineering, debugging, forensic analysis, and cybersecurity education.

## 📋 Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Examples](#examples)
- [Output Format](#output-format)
- [Use Cases](#use-cases)
- [Technical Details](#technical-details)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

- **Multiple Output Formats**: Clean hex display with ASCII representation
- **Flexible Input**: Read from files or stdin (pipe support for command chains)
- **Offset Control**: Specify starting offset and dump length
- **Customizable Display**: Adjustable bytes per line (1-64+)
- **Color Support**: Optional colored output for better readability
- **Uppercase/Lowercase**: Choose your preferred hex digit case
- **Multiple Offset Formats**: Display offsets in hex or decimal
- **Professional Output**: Clear headers with file info and timestamps
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Error Handling**: Graceful handling of file errors, permission issues, and interrupts

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- No additional dependencies required (uses only standard library)

### Method : Direct Download


# Download the script
curl -O https://raw.githubusercontent.com/Solidx74/Hex_Dumper/main/hex_dumper.py

# Make it executable (Linux/macOS)
chmod +x hex_dumper.py

# Optional: Move to PATH for system-wide access
sudo mv hex_dumper.py /usr/local/bin/hexdump


## Quick Start

# Basic usage - dump a file
./hex_dumper.py file.bin

# Dump first 256 bytes from offset 0x100
./hex_dumper.py -o 0x100 -n 256 file.bin

# Read from stdin (pipe)
cat file.bin | ./hex_dumper.py

# Enable colored output
./hex_dumper.py -c file.bin

# Usage Guide

## Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `file` | File to dump (optional, reads from stdin if omitted) | `./hex_dumper.py data.bin` |
| `-o, --offset` | Starting offset (supports hex with 0x prefix) | `-o 0x100` or `-o 1024` |
| `-n, --length` | Number of bytes to dump | `-n 512` |
| `-b, --bytes-per-line` | Bytes per line (default: 16) | `-b 8` |
| `-U, --uppercase` | Use uppercase hex digits | `-U` |
| `-a, --no-ascii` | Hide ASCII column | `-a` |
| `-A, --offset-format` | Offset format: hex or dec | `-A dec` |
| `--no-offset` | Hide offset column | `--no-offset` |
| `-c, --color` | Enable colored output | `-c` |
| `-v, --version` | Show version information | `-v` |


# Advanced Usage Patterns

## Forensic analysis with colored output
./hex_dumper.py -c -b 16 -U suspicious_file.exe

## Compact view with 32 bytes per line, no offset
./hex_dumper.py --no-offset -b 32 large_file.bin

## Decimal offsets for easier correlation
./hex_dumper.py -A dec -n 1000 data.bin

## Hex only (no ASCII) for machine processing
./hex_dumper.py -a binary.dat | grep "FF FF"

## Dump specific range and save to file
./hex_dumper.py -o 0x200 -n 1024 firmware.bin > extracted_region.hex


# Examples
Example 1: Analyzing File Headers

# Check magic numbers of an executable
./hex_dumper.py -n 64 -U /bin/ls
Output:

text
================================================================================
Hex Dump: /bin/ls
Size: 137896 bytes
Offset: 00000000
Bytes per line: 16
Time: 2024-01-15 14:30:45
================================================================================

00000000  7F 45 4C 46 02 01 01 00  00 00 00 00 00 00 00 00  .ELF............
00000010  03 00 3E 00 01 00 00 00  30 6A 02 00 00 00 00 00  ..>.....0j......
Example 2: Network Packet Analysis

# Capture and analyze packets
tcpdump -c 10 -w - | ./hex_dumper.py -b 8 -c

Example 3: Forensics Investigation

# Examine suspicious file for patterns
./hex_dumper.py -c -b 16 malware_sample.exe | grep -A 5 -B 5 "MZ"

Example 4: Binary Comparison

# Dump two files and compare
diff <(./hex_dumper.py file1.bin) <(./hex_dumper.py file2.bin)

# Output Format
The hex dumper produces professional, easy-to-read output:

text
================================================================================
Hex Dump: example.bin
Size: 256 bytes
Offset: 00000000
Bytes per line: 16
Time: 2024-01-15 14:30:45
================================================================================

00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21 0a 00 00 00  Hello World!....
00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020  54 68 69 73 20 69 73 20  61 20 74 65 73 74 20 66  This is a test f
Color Coding (when enabled with -c)
🔵 Cyan: Offset values

⚪ White: Hex bytes

🟢 Green: ASCII representation

### Use Cases

# Cybersecurity & Forensics

2.Analyze malware binaries

3.Examine file headers and magic numbers

4.Investigate network packet captures

5.Recover deleted file signatures

# Reverse Engineering

7.Analyze binary executables

8.Study file formats and structures

9.Debug embedded systems firmware

10.Examine memory dumps

# Software Development

12.Debug binary data formats

13.Analyze protocol implementations

14.Inspect serialized data

15.Verify file integrity

# Education
Learn about binary representation

Understand file structures

Study data encoding

Practice hex analysis skills

# System Administration
Analyze log files

Examine system binaries

Debug configuration files

Inspect disk images

## Technical Details

# Performance Characteristics
Memory Efficient: Processes files in chunks without loading entire file

Large File Support: Handles files > 1GB efficiently

Buffer Size: Optimized 4KB read buffer

Line Buffering: Real-time output for streaming data

# Error Handling
The script gracefully handles:

File not found errors

Permission denied issues

Invalid offset specifications

Pipe interrupts (SIGPIPE)

Keyboard interrupts (Ctrl+C)

# Supported Platforms
Linux: Full support (tested on Ubuntu, Debian, Fedora)

macOS: Full support (tested on Catalina and newer)

Windows: Works in Command Prompt, PowerShell, WSL

BSD: Tested on FreeBSD and OpenBSD