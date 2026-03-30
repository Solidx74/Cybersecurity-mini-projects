# Hash Calculator - Cryptographic Hash Tool

**Author:** Kareeb Sadab

A lightweight command-line tool for generating and verifying cryptographic hashes of files, strings, and directories. Ideal for **forensics, integrity checks, and IOC verification**. Works seamlessly with Hex Dumper for binary analysis workflows.
---

## Features

- Supports multiple algorithms: MD5, SHA1, SHA256, SHA512, SHA3, BLAKE2  
- Hash strings, files, directories, or stdin  
- Verify files against known hash values  
- Generate checksum files (MD5SUM style)  
- Recursive directory processing  
- Optional HMAC support  
- Color-coded and JSON output  
- Efficient for large files (multi-GB)

---

## Installation

Requires **Python 3.6+**, no external dependencies.


# Clone repository
git clone https://github.com/Solidx74/cybersecurity-mini-projects.git
cd cybersecurity-mini-projects/hash_calculator
chmod +x hash_calc.py

## Functionalities

# Hash a string
./hash_calc.py -s "Hello World"

# Hash a file
./hash_calc.py -f document.pdf -a md5 sha256

# Verify a hash
./hash_calc.py -f file.iso --verify md5=5d41402abc4b2a76b9719d911017c592

# Hash all files in a directory recursively
./hash_calc.py -d ./evidence -r -a sha256 --json

# Command Line Options

| Option                | Description                     | Example               |
| --------------------- | ------------------------------- | --------------------- |
| `-s, --string`        | Hash a string                   | `-s "Hello"`          |
| `-f, --file`          | Hash a file                     | `-f file.bin`         |
| `-d, --directory`     | Hash all files in a directory   | `-d ./folder`         |
| `-a, --algorithm`     | Hash algorithms                 | `-a md5 sha256`       |
| `--verify`            | Verify against expected hashes  | `--verify md5=abc123` |
| `--generate-checksum` | Generate checksum file          | `--generate-checksum` |
| `--json`              | Output in JSON format           | `--json`              |
| `--color`             | Enable color-coded output       | `--color`             |
| `-r, --recursive`     | Process directories recursively | `-r`                  |



