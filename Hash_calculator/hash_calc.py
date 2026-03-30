#!/usr/bin/env python3
"""
Professional Hash Calculator
A comprehensive hash calculation tool for forensic and IOC analysis.
Supports MD5, SHA1, SHA256, and more for strings and files.
"""

import argparse
import hashlib
import os
import sys
import json
from typing import Dict, List, Optional, Tuple, Union
from pathlib import Path
from datetime import datetime
import base64
import hmac

class HashCalculator:
    """Professional hash calculator with multiple algorithms and formats."""
    
    # Supported hash algorithms
    SUPPORTED_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'sha3_224': hashlib.sha3_224,
        'sha3_256': hashlib.sha3_256,
        'sha3_384': hashlib.sha3_384,
        'sha3_512': hashlib.sha3_512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s,
    }
    
    def __init__(self, algorithms: List[str] = None, buffer_size: int = 8192):
        """
        Initialize hash calculator.
        
        Args:
            algorithms: List of algorithms to use (default: all)
            buffer_size: Buffer size for file reading
        """
        if algorithms:
            self.algorithms = [a.lower() for a in algorithms if a.lower() in self.SUPPORTED_ALGORITHMS]
        else:
            self.algorithms = ['md5', 'sha1', 'sha256']
        
        self.buffer_size = buffer_size
        self.color = False
        self.colors = {
            'header': '\033[36m',
            'algorithm': '\033[33m',
            'hash': '\033[32m',
            'error': '\033[31m',
            'reset': '\033[0m'
        }
    
    def enable_color(self):
        """Enable colored output."""
        self.color = True
    
    def _colorize(self, text: str, color: str) -> str:
        """Add color to text if enabled."""
        if self.color:
            return f"{self.colors[color]}{text}{self.colors['reset']}"
        return text
    
    def hash_string(self, text: str, encoding: str = 'utf-8') -> Dict[str, str]:
        """
        Calculate hash of a string.
        
        Args:
            text: Input string
            encoding: Character encoding
            
        Returns:
            Dictionary of algorithm -> hash value
        """
        data = text.encode(encoding)
        results = {}
        
        for algo in self.algorithms:
            hash_obj = self.SUPPORTED_ALGORITHMS[algo]()
            hash_obj.update(data)
            results[algo] = hash_obj.hexdigest()
        
        return results
    
    def hash_file(self, filepath: str) -> Dict[str, str]:
        """
        Calculate hash of a file.
        
        Args:
            filepath: Path to the file
            
        Returns:
            Dictionary of algorithm -> hash value
            
        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If permission denied
            IOError: If read error occurs
        """
        results = {}
        
        # Initialize hash objects
        hash_objects = {}
        for algo in self.algorithms:
            hash_objects[algo] = self.SUPPORTED_ALGORITHMS[algo]()
        
        # Read file in chunks
        try:
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(self.buffer_size)
                    if not chunk:
                        break
                    for algo in self.algorithms:
                        hash_objects[algo].update(chunk)
            
            # Generate final hashes
            for algo in self.algorithms:
                results[algo] = hash_objects[algo].hexdigest()
            
            return results
            
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {filepath}")
        except PermissionError:
            raise PermissionError(f"Permission denied: {filepath}")
        except Exception as e:
            raise IOError(f"Error reading file: {e}")
    
    def hash_bytes(self, data: bytes) -> Dict[str, str]:
        """
        Calculate hash of bytes data.
        
        Args:
            data: Bytes data to hash
            
        Returns:
            Dictionary of algorithm -> hash value
        """
        results = {}
        
        for algo in self.algorithms:
            hash_obj = self.SUPPORTED_ALGORITHMS[algo]()
            hash_obj.update(data)
            results[algo] = hash_obj.hexdigest()
        
        return results
    
    def verify_string(self, text: str, expected_hashes: Dict[str, str]) -> Dict[str, bool]:
        """
        Verify string against expected hashes.
        
        Args:
            text: Input string
            expected_hashes: Dictionary of algorithm -> expected hash
            
        Returns:
            Dictionary of algorithm -> verification result
        """
        calculated = self.hash_string(text)
        results = {}
        
        for algo, expected in expected_hashes.items():
            if algo in calculated:
                results[algo] = calculated[algo].lower() == expected.lower()
            else:
                results[algo] = False
        
        return results
    
    def verify_file(self, filepath: str, expected_hashes: Dict[str, str]) -> Dict[str, bool]:
        """
        Verify file against expected hashes.
        
        Args:
            filepath: Path to the file
            expected_hashes: Dictionary of algorithm -> expected hash
            
        Returns:
            Dictionary of algorithm -> verification result
        """
        try:
            calculated = self.hash_file(filepath)
            results = {}
            
            for algo, expected in expected_hashes.items():
                if algo in calculated:
                    results[algo] = calculated[algo].lower() == expected.lower()
                else:
                    results[algo] = False
            
            return results
        except Exception as e:
            return {algo: False for algo in expected_hashes.keys()}
    
    def hash_directory(self, directory: str, recursive: bool = False) -> Dict[str, Dict[str, str]]:
        """
        Calculate hashes for all files in a directory.
        
        Args:
            directory: Directory path
            recursive: Include subdirectories
            
        Returns:
            Dictionary of filepath -> algorithm -> hash
        """
        results = {}
        path = Path(directory)
        
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")
        
        # Get all files
        if recursive:
            files = path.rglob('*')
        else:
            files = path.glob('*')
        
        for file_path in files:
            if file_path.is_file():
                try:
                    results[str(file_path)] = self.hash_file(str(file_path))
                except Exception as e:
                    results[str(file_path)] = {'error': str(e)}
        
        return results
    
    def generate_checksum_file(self, filepath: str, output: Optional[str] = None) -> str:
        """
        Generate a checksum file (like MD5SUM format).
        
        Args:
            filepath: Path to the file
            output: Output file path (optional)
            
        Returns:
            Checksum file content
        """
        hashes = self.hash_file(filepath)
        content = []
        
        for algo, hash_value in hashes.items():
            content.append(f"{hash_value}  {os.path.basename(filepath)}  #{algo}")
        
        output_content = '\n'.join(content)
        
        if output:
            with open(output, 'w') as f:
                f.write(output_content)
        
        return output_content
    
    def hmac_calculate(self, key: Union[str, bytes], message: Union[str, bytes], 
                       algorithm: str = 'sha256') -> str:
        """
        Calculate HMAC for a message.
        
        Args:
            key: Secret key
            message: Message to hash
            algorithm: Hash algorithm to use
            
        Returns:
            HMAC hex digest
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hash_func = self.SUPPORTED_ALGORITHMS[algorithm]
        hmac_obj = hmac.new(key, message, hash_func)
        
        return hmac_obj.hexdigest()

def print_header(source: str, source_type: str, algorithms: List[str]) -> None:
    """Print calculation header."""
    print("=" * 80)
    print(f"Hash Calculator - {source_type.upper()} Analysis")
    print(f"Source: {source}")
    print(f"Algorithms: {', '.join(algorithms).upper()}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    print()

def print_results(results: Dict[str, str], calculator: HashCalculator) -> None:
    """Print hash results in formatted output."""
    for algo, hash_value in results.items():
        print(f"{calculator._colorize(algo.upper() + ':', 'algorithm'):<12} "
              f"{calculator._colorize(hash_value, 'hash')}")
    print()

def print_verification_results(results: Dict[str, bool], calculator: HashCalculator) -> None:
    """Print verification results."""
    print("Verification Results:")
    print("-" * 40)
    
    all_valid = True
    for algo, is_valid in results.items():
        status = calculator._colorize("✓ VALID", "hash") if is_valid else calculator._colorize("✗ INVALID", "error")
        print(f"{algo.upper():<12}: {status}")
        if not is_valid:
            all_valid = False
    
    print("-" * 40)
    overall = "ALL VALID" if all_valid else "INVALID"
    overall_color = "hash" if all_valid else "error"
    print(f"Overall Status: {calculator._colorize(overall, overall_color)}")
    print()

def main():
    """Main entry point for hash calculator."""
    parser = argparse.ArgumentParser(
        description='Professional Hash Calculator - Calculate cryptographic hashes for strings and files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Hash a string
  %(prog)s -s "Hello World"
  
  # Hash a file with multiple algorithms
  %(prog)s -f document.pdf -a md5 sha256 sha512
  
  # Verify file integrity
  %(prog)s -f file.iso --verify md5=5d41402abc4b2a76b9719d911017c592
  
  # Generate checksum file
  %(prog)s -f firmware.bin --generate-checksum
  
  # Hash all files in directory
  %(prog)s -d /path/to/directory -r
  
  # Calculate HMAC
  %(prog)s -s "secret message" --hmac --key "mysecretkey"
  
  # JSON output for scripting
  %(prog)s -f data.bin --json
  
  # Read from stdin
  echo "test data" | %(prog)s
        """
    )
    
    # Input sources (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-s', '--string', help='Hash a string')
    input_group.add_argument('-f', '--file', help='Hash a file')
    input_group.add_argument('-d', '--directory', help='Hash all files in directory')
    
    # Options
    parser.add_argument('-a', '--algorithm', nargs='+', 
                       default=['md5', 'sha1', 'sha256'],
                       help='Hash algorithms to use (default: md5 sha1 sha256)')
    parser.add_argument('-b', '--buffer-size', type=int, default=8192,
                       help='Buffer size for file reading (default: 8192)')
    parser.add_argument('-e', '--encoding', default='utf-8',
                       help='String encoding (default: utf-8)')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Process directories recursively')
    parser.add_argument('--verify', nargs='+', 
                       help='Verify against expected hashes (format: algo=hash)')
    parser.add_argument('--generate-checksum', action='store_true',
                       help='Generate checksum file format')
    parser.add_argument('--output', '-o', help='Output file for checksum')
    parser.add_argument('--hmac', action='store_true',
                       help='Calculate HMAC instead of hash')
    parser.add_argument('--key', help='Key for HMAC calculation')
    parser.add_argument('--json', action='store_true',
                       help='Output in JSON format')
    parser.add_argument('--color', action='store_true',
                       help='Enable colored output')
    parser.add_argument('--version', action='version', 
                       version='%(prog)s 1.0.0')
    
    args = parser.parse_args()
    
    # Validate algorithms
    for algo in args.algorithm:
        if algo not in HashCalculator.SUPPORTED_ALGORITHMS:
            print(f"Error: Unsupported algorithm '{algo}'", file=sys.stderr)
            print(f"Supported: {', '.join(HashCalculator.SUPPORTED_ALGORITHMS.keys())}", 
                  file=sys.stderr)
            sys.exit(1)
    
    # Create calculator
    calculator = HashCalculator(args.algorithm, args.buffer_size)
    if args.color:
        calculator.enable_color()
    
    # Parse verification hashes
    expected_hashes = {}
    if args.verify:
        for item in args.verify:
            if '=' in item:
                algo, hash_value = item.split('=', 1)
                expected_hashes[algo.lower()] = hash_value
            else:
                print(f"Error: Invalid verify format: {item}", file=sys.stderr)
                sys.exit(1)
    
    try:
        # Handle HMAC mode
        if args.hmac:
            if not args.key:
                print("Error: --key required for HMAC calculation", file=sys.stderr)
                sys.exit(1)
            
            message = args.string if args.string else sys.stdin.buffer.read()
            if isinstance(message, bytes):
                message = message.decode(args.encoding, errors='ignore')
            
            hmac_result = calculator.hmac_calculate(args.key, message, args.algorithm[0])
            
            if args.json:
                output = {
                    'hmac': hmac_result,
                    'algorithm': args.algorithm[0],
                    'key': args.key
                }
                print(json.dumps(output, indent=2))
            else:
                print_header(f"HMAC ({args.algorithm[0].upper()})", "HMAC", args.algorithm)
                print(f"HMAC: {hmac_result}\n")
            return
        
        # Handle string input
        if args.string:
            if args.generate_checksum:
                print("Error: --generate-checksum only works with files", file=sys.stderr)
                sys.exit(1)
            
            results = calculator.hash_string(args.string, args.encoding)
            
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print_header(args.string, "string", args.algorithm)
                print_results(results, calculator)
                
                # Verify if requested
                if expected_hashes:
                    verification = calculator.verify_string(args.string, expected_hashes)
                    print_verification_results(verification, calculator)
        
        # Handle file input
        elif args.file:
            if args.directory:
                print("Error: Cannot specify both file and directory", file=sys.stderr)
                sys.exit(1)
            
            if args.generate_checksum:
                checksum_content = calculator.generate_checksum_file(args.file, args.output)
                if not args.output:
                    print(checksum_content)
                else:
                    print(f"Checksum file created: {args.output}")
                return
            
            results = calculator.hash_file(args.file)
            
            if args.json:
                output = {
                    'file': args.file,
                    'hashes': results
                }
                print(json.dumps(output, indent=2))
            else:
                print_header(args.file, "file", args.algorithm)
                print_results(results, calculator)
                
                # Verify if requested
                if expected_hashes:
                    verification = calculator.verify_file(args.file, expected_hashes)
                    print_verification_results(verification, calculator)
        
        # Handle directory input
        elif args.directory:
            if args.generate_checksum:
                print("Error: --generate-checksum only works with single files", file=sys.stderr)
                sys.exit(1)
            
            results = calculator.hash_directory(args.directory, args.recursive)
            
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print_header(args.directory, "directory", args.algorithm)
                for filepath, hashes in results.items():
                    print(f"\n{calculator._colorize(filepath, 'header')}:")
                    if 'error' in hashes:
                        print(f"  Error: {hashes['error']}")
                    else:
                        for algo, hash_value in hashes.items():
                            print(f"  {algo.upper():<8}: {hash_value}")
                print()
        
        # Handle stdin
        else:
            data = sys.stdin.buffer.read()
            results = calculator.hash_bytes(data)
            
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print_header("stdin", "stream", args.algorithm)
                print_results(results, calculator)
    
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()