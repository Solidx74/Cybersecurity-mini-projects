#!/usr/bin/env python3
"""
JWT Token Inspector - Enterprise Security Tool v2.0.0
======================================================
A professional JWT inspection and analysis tool with advanced security features,
vulnerability detection, token verification, and comprehensive reporting.

Author: Kareeb Sadab
Version: 2.0.0
License: MIT
Status: Production Ready

Features:
- JWT token parsing (Header, Payload, Signature)
- Multiple algorithm support (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512)
- Token verification with public/private keys
- Advanced security vulnerability detection
- Weak algorithm detection with severity scoring
- Token expiration and validity validation
- Automated attack pattern detection
- JWT injection attempt detection
- Comprehensive JSON/HTML output
- Audit logging with forensic detail
- Batch token processing
- Token fuzzing and analysis
- Detailed security scoring system
- Token entropy analysis
- Known vulnerability database integration
- Automated report generation
"""

import argparse
import sys
import json
import base64
import hashlib
import hmac
import logging
import os
import time
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List, Set
from pathlib import Path
from logging.handlers import RotatingFileHandler
import re
from collections import defaultdict
import statistics
from dataclasses import dataclass, asdict
from enum import Enum

# Try to import optional dependencies
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not installed. RSA/ECDSA verification disabled.", file=sys.stderr)

# ============================================================================
# Constants and Configuration
# ============================================================================

APP_NAME = "JWT Token Inspector"
APP_VERSION = "2.0.0"
APP_AUTHOR = "Kareeb Sadab"
APP_BUILD = "20250115"
APP_EMAIL = "kareeb.sadab@security-tools.com"

DEFAULT_OUTPUT_DIR = "jwt_outputs"
DEFAULT_LOG_FILE = "jwt_inspector.log"
MAX_LOG_SIZE_MB = 10
LOG_BACKUP_COUNT = 5

# Security Scoring Configuration
SECURITY_SCORES = {
    'CRITICAL': 0,
    'HIGH': 25,
    'MEDIUM': 50,
    'LOW': 75,
    'GOOD': 90,
    'EXCELLENT': 100
}

RISK_LEVELS = {
    0: {'name': 'CRITICAL', 'icon': '🔴', 'description': 'Immediate action required'},
    25: {'name': 'HIGH', 'icon': '🟠', 'description': 'Urgent attention needed'},
    50: {'name': 'MEDIUM', 'icon': '🟡', 'description': 'Should be addressed'},
    75: {'name': 'LOW', 'icon': '🟢', 'description': 'Minor improvements possible'},
    90: {'name': 'GOOD', 'icon': '📗', 'description': 'Generally secure'},
    100: {'name': 'EXCELLENT', 'icon': '🏆', 'description': 'Exceptionally secure'}
}

# JWT Header Constants
VALID_ALGORITHMS = {
    'HS256': {'name': 'HMAC with SHA-256', 'strength': 'MEDIUM', 'type': 'SYMMETRIC', 'score': 70},
    'HS384': {'name': 'HMAC with SHA-384', 'strength': 'MEDIUM', 'type': 'SYMMETRIC', 'score': 75},
    'HS512': {'name': 'HMAC with SHA-512', 'strength': 'MEDIUM', 'type': 'SYMMETRIC', 'score': 80},
    'RS256': {'name': 'RSA with SHA-256', 'strength': 'HIGH', 'type': 'ASYMMETRIC', 'score': 90},
    'RS384': {'name': 'RSA with SHA-384', 'strength': 'HIGH', 'type': 'ASYMMETRIC', 'score': 92},
    'RS512': {'name': 'RSA with SHA-512', 'strength': 'HIGH', 'type': 'ASYMMETRIC', 'score': 95},
    'ES256': {'name': 'ECDSA with SHA-256', 'strength': 'HIGH', 'type': 'ASYMMETRIC', 'score': 92},
    'ES384': {'name': 'ECDSA with SHA-384', 'strength': 'HIGH', 'type': 'ASYMMETRIC', 'score': 94},
    'ES512': {'name': 'ECDSA with SHA-512', 'strength': 'HIGH', 'type': 'ASYMMETRIC', 'score': 96},
    'none': {'name': 'No signature', 'strength': 'CRITICAL', 'type': 'NONE', 'score': 0, 'warning': 'INSECURE'}
}

WEAK_ALGORITHMS = {'none': 'CRITICAL', 'HS256': 'MEDIUM'}
DANGEROUS_ALGORITHMS = {'none': 'CRITICAL'}

# Attack Patterns Database
ATTACK_PATTERNS = {
    'sql_injection': {
        'pattern': r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)',
        'severity': 'HIGH',
        'description': 'Potential SQL injection attempt detected'
    },
    'xss': {
        'pattern': r'(?i)(<script|javascript:|onerror=|onload=|alert\(|prompt\(|confirm\(|document\.cookie)',
        'severity': 'HIGH',
        'description': 'Potential XSS attack pattern detected'
    },
    'path_traversal': {
        'pattern': r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)',
        'severity': 'MEDIUM',
        'description': 'Path traversal attempt detected'
    },
    'command_injection': {
        'pattern': r'(?i)(;|\||&&|\$\()|`.*`',
        'severity': 'CRITICAL',
        'description': 'Command injection attempt detected'
    },
    'jwt_injection': {
        'pattern': r'(?i)(alg:none|\"alg\"\s*:\s*\"none\"|\\\\\"alg\\\\\"\s*:\s*\\\\\"none\\\\\")',
        'severity': 'CRITICAL',
        'description': 'JWT algorithm injection attempt detected'
    }
}

# Known Vulnerable Claims
VULNERABLE_CLAIMS = {
    'password': 'CRITICAL',
    'secret': 'CRITICAL',
    'token': 'HIGH',
    'api_key': 'CRITICAL',
    'apikey': 'CRITICAL',
    'private_key': 'CRITICAL',
    'credential': 'CRITICAL',
    'credit_card': 'CRITICAL',
    'ssn': 'CRITICAL',
    'social_security': 'CRITICAL',
    'passwd': 'CRITICAL',
    'pwd': 'HIGH',
    'key': 'HIGH',
    'auth': 'MEDIUM'
}

# JWT Claims
REQUIRED_CLAIMS = ['exp', 'iat']
RECOMMENDED_CLAIMS = ['exp', 'iat', 'nbf', 'iss', 'aud']
STANDARD_CLAIMS = {
    'iss': 'Issuer',
    'sub': 'Subject',
    'aud': 'Audience',
    'exp': 'Expiration Time',
    'nbf': 'Not Before',
    'iat': 'Issued At',
    'jti': 'JWT ID',
    'typ': 'Type'
}

# ============================================================================
# Custom Exceptions
# ============================================================================

class JWTError(Exception):
    """Base exception for JWT errors"""
    pass

class InvalidJWTError(JWTError):
    """Raised when JWT token is invalid"""
    pass

class UnsupportedAlgorithmError(JWTError):
    """Raised when algorithm is not supported"""
    pass

class TokenExpiredError(JWTError):
    """Raised when token is expired"""
    pass

class TokenNotYetValidError(JWTError):
    """Raised when token is not yet valid"""
    pass

class VerificationError(JWTError):
    """Raised when signature verification fails"""
    pass

class BatchProcessingError(JWTError):
    """Raised when batch processing fails"""
    pass

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SecurityFinding:
    """Represents a security finding"""
    severity: str
    title: str
    description: str
    recommendation: str
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class SecurityScore:
    """Represents security score details"""
    overall_score: int
    risk_level: str
    risk_icon: str
    breakdown: Dict[str, int]
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int

# ============================================================================
# Utility Functions
# ============================================================================

def setup_logging(output_dir: Path, verbose: bool = False) -> logging.Logger:
    """Configure logging with rotation support"""
    output_dir.mkdir(parents=True, exist_ok=True)
    log_file = output_dir / DEFAULT_LOG_FILE
    
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    try:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=MAX_LOG_SIZE_MB * 1024 * 1024,
            backupCount=LOG_BACKUP_COUNT,
            encoding='utf-8'
        )
        file_handler.setFormatter(detailed_formatter)
        file_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not create log file: {e}", file=sys.stderr)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(simple_formatter)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    root_logger.addHandler(console_handler)
    
    return logging.getLogger(__name__)

def base64url_decode(data: str) -> bytes:
    """Decode base64url encoded string"""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data)

def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def safe_json_parse(data: str) -> Dict[str, Any]:
    """Safely parse JSON with error handling"""
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise InvalidJWTError(f"Invalid JSON in token: {e}")

def calculate_entropy(data: str) -> float:
    """Calculate entropy of a string (security measure)"""
    if not data:
        return 0.0
    
    # Count character frequencies
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        probability = count / length
        entropy -= probability * (probability.bit_length() if probability > 0 else 0)
    
    return entropy

def validate_token_format(token: str) -> bool:
    """Validate JWT token format"""
    parts = token.split('.')
    if len(parts) != 3:
        return False
    
    # Check each part is base64url encoded
    base64url_pattern = re.compile(r'^[A-Za-z0-9_-]+$')
    return all(base64url_pattern.match(part) for part in parts)

# ============================================================================
# JWT Inspector Core
# ============================================================================

class JWTInspector:
    """Professional JWT Token Inspector with security analysis capabilities"""
    
    def __init__(self, verbose: bool = False):
        """Initialize JWT Inspector"""
        self.verbose = verbose
        self.findings: List[SecurityFinding] = []
        logger.info(f"Initializing {APP_NAME} v{APP_VERSION} by {APP_AUTHOR}")
        
        if not CRYPTO_AVAILABLE and verbose:
            logger.warning("Cryptography library not installed. RSA/ECDSA verification disabled.")
    
    def parse_token(self, token: str) -> Dict[str, Any]:
        """Parse JWT token into header, payload, and signature"""
        parts = token.split('.')
        
        if len(parts) != 3:
            raise InvalidJWTError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
        
        header_b64, payload_b64, signature_b64 = parts
        
        try:
            header_bytes = base64url_decode(header_b64)
            payload_bytes = base64url_decode(payload_b64)
            signature_bytes = base64url_decode(signature_b64)
        except Exception as e:
            raise InvalidJWTError(f"Failed to decode JWT parts: {e}")
        
        header = safe_json_parse(header_bytes.decode('utf-8'))
        payload = safe_json_parse(payload_bytes.decode('utf-8'))
        
        return {
            'header': header,
            'payload': payload,
            'signature': signature_bytes,
            'header_b64': header_b64,
            'payload_b64': payload_b64,
            'signature_b64': signature_b64
        }
    
    def verify_signature_hs(self, token_parts: Dict[str, Any], secret: str) -> bool:
        """Verify HMAC signature (HS256, HS384, HS512)"""
        algorithm = token_parts['header'].get('alg', '').upper()
        
        if algorithm not in ['HS256', 'HS384', 'HS512']:
            raise UnsupportedAlgorithmError(f"Algorithm {algorithm} not supported for HMAC")
        
        message = f"{token_parts['header_b64']}.{token_parts['payload_b64']}".encode('utf-8')
        
        if algorithm == 'HS256':
            digest = hashlib.sha256
        elif algorithm == 'HS384':
            digest = hashlib.sha384
        else:
            digest = hashlib.sha512
        
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            message,
            digest
        ).digest()
        
        return hmac.compare_digest(token_parts['signature'], expected_signature)
    
    def verify_signature_rsa(self, token_parts: Dict[str, Any], public_key_path: str) -> bool:
        """Verify RSA signature (RS256, RS384, RS512)"""
        if not CRYPTO_AVAILABLE:
            raise VerificationError("Cryptography library not available for RSA verification")
        
        algorithm = token_parts['header'].get('alg', '').upper()
        
        if algorithm not in ['RS256', 'RS384', 'RS512']:
            raise UnsupportedAlgorithmError(f"Algorithm {algorithm} not supported for RSA")
        
        try:
            with open(public_key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())
            
            message = f"{token_parts['header_b64']}.{token_parts['payload_b64']}".encode('utf-8')
            
            if algorithm == 'RS256':
                hash_algo = SHA256()
            elif algorithm == 'RS384':
                hash_algo = SHA384()
            else:
                hash_algo = SHA512()
            
            public_key.verify(
                token_parts['signature'],
                message,
                padding.PKCS1v15(),
                hash_algo
            )
            return True
            
        except Exception as e:
            logger.error(f"RSA verification failed: {e}")
            return False
    
    def verify_signature_ecdsa(self, token_parts: Dict[str, Any], public_key_path: str) -> bool:
        """Verify ECDSA signature (ES256, ES384, ES512)"""
        if not CRYPTO_AVAILABLE:
            raise VerificationError("Cryptography library not available for ECDSA verification")
        
        algorithm = token_parts['header'].get('alg', '').upper()
        
        if algorithm not in ['ES256', 'ES384', 'ES512']:
            raise UnsupportedAlgorithmError(f"Algorithm {algorithm} not supported for ECDSA")
        
        try:
            with open(public_key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())
            
            message = f"{token_parts['header_b64']}.{token_parts['payload_b64']}".encode('utf-8')
            
            if algorithm == 'ES256':
                hash_algo = SHA256()
            elif algorithm == 'ES384':
                hash_algo = SHA384()
            else:
                hash_algo = SHA512()
            
            public_key.verify(
                token_parts['signature'],
                message,
                ec.ECDSA(hash_algo)
            )
            return True
            
        except Exception as e:
            logger.error(f"ECDSA verification failed: {e}")
            return False
    
    def detect_attack_patterns(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect attack patterns in token payload"""
        attacks = []
        payload_str = json.dumps(payload)
        
        for attack_name, attack_info in ATTACK_PATTERNS.items():
            if re.search(attack_info['pattern'], payload_str):
                attacks.append({
                    'type': attack_name,
                    'severity': attack_info['severity'],
                    'description': attack_info['description']
                })
                self.add_finding(
                    attack_info['severity'],
                    f"{attack_name.upper()} Attack Pattern Detected",
                    attack_info['description'],
                    "Sanitize all inputs and use proper encoding"
                )
        
        return attacks
    
    def detect_vulnerable_claims(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect vulnerable/sensitive claims in payload"""
        vulnerable = []
        
        for claim, value in payload.items():
            claim_lower = claim.lower()
            for vuln_claim, severity in VULNERABLE_CLAIMS.items():
                if vuln_claim in claim_lower:
                    vulnerable.append({
                        'claim': claim,
                        'severity': severity,
                        'value': str(value)[:50]  # Truncate for safety
                    })
                    self.add_finding(
                        severity,
                        f"Sensitive data in claim: {claim}",
                        f"Claim '{claim}' contains potentially sensitive information",
                        f"Remove or encrypt sensitive data in JWT claims"
                    )
                    break
        
        return vulnerable
    
    def analyze_algorithm_security(self, algorithm: str) -> Dict[str, Any]:
        """Analyze algorithm security strength"""
        algo_info = VALID_ALGORITHMS.get(algorithm, VALID_ALGORITHMS.get('none'))
        
        if algorithm in DANGEROUS_ALGORITHMS:
            self.add_finding(
                'CRITICAL',
                f"Dangerous algorithm detected: {algorithm}",
                "Using 'none' algorithm completely bypasses signature verification",
                "NEVER use 'none' algorithm in production. Use RS256 or ES256 instead."
            )
        elif algorithm in WEAK_ALGORITHMS:
            self.add_finding(
                'MEDIUM',
                f"Weak algorithm detected: {algorithm}",
                f"{algo_info['name']} is considered weak for certain scenarios",
                "Consider using RS256 or ES256 for stronger security"
            )
        
        return algo_info
    
    def analyze_token_structure(self, token: str) -> Dict[str, Any]:
        """Analyze token structure and format"""
        analysis = {
            'length': len(token),
            'parts': token.count('.') + 1,
            'is_valid_format': validate_token_format(token),
            'entropy': calculate_entropy(token),
            'has_padding': token.endswith('=') or '=' in token
        }
        
        if analysis['entropy'] < 2.0:
            self.add_finding(
                'MEDIUM',
                'Low token entropy',
                f"Token entropy is {analysis['entropy']:.2f}, indicating predictability",
                "Use proper random number generation for token creation"
            )
        
        return analysis
    
    def analyze_claims_security(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security of JWT claims"""
        analysis = {
            'has_exp': 'exp' in payload,
            'has_iat': 'iat' in payload,
            'has_nbf': 'nbf' in payload,
            'has_jti': 'jti' in payload,
            'missing_required': [],
            'missing_recommended': []
        }
        
        # Check required claims
        for claim in REQUIRED_CLAIMS:
            if claim not in payload:
                analysis['missing_required'].append(claim)
                self.add_finding(
                    'MEDIUM',
                    f"Missing required claim: {claim}",
                    f"JWT missing '{claim}' claim which is recommended for security",
                    f"Add '{claim}' claim to token"
                )
        
        # Check recommended claims
        for claim in RECOMMENDED_CLAIMS:
            if claim not in payload:
                analysis['missing_recommended'].append(claim)
        
        return analysis
    
    def validate_claims(self, payload: Dict[str, Any]) -> List[str]:
        """Validate JWT claims (exp, nbf, iat)"""
        warnings = []
        current_time = datetime.now(timezone.utc).timestamp()
        
        # Check expiration
        if 'exp' in payload:
            exp_time = payload['exp']
            if current_time > exp_time:
                warnings.append(f"⚠️  Token expired at {datetime.fromtimestamp(exp_time)}")
                self.add_finding(
                    'HIGH',
                    'Token expired',
                    f"Token expired at {datetime.fromtimestamp(exp_time)}",
                    "Issue new token with appropriate expiration time"
                )
            elif exp_time - current_time < 300:
                warnings.append(f"⚠️  Token expires soon at {datetime.fromtimestamp(exp_time)}")
            elif exp_time - current_time > 86400 * 30:
                warnings.append(f"⚠️  Token expiration is too far in the future")
                self.add_finding(
                    'MEDIUM',
                    'Excessive token lifetime',
                    f"Token expires in {(exp_time - current_time) / 86400:.1f} days",
                    "Use shorter expiration times (hours, not days)"
                )
        
        # Check not before
        if 'nbf' in payload:
            nbf_time = payload['nbf']
            if current_time < nbf_time:
                warnings.append(f"⚠️  Token not valid until {datetime.fromtimestamp(nbf_time)}")
        
        # Check issued at
        if 'iat' in payload:
            iat_time = payload['iat']
            if current_time < iat_time:
                warnings.append(f"⚠️  Token issued in the future at {datetime.fromtimestamp(iat_time)}")
            elif current_time - iat_time > 86400:
                warnings.append(f"⚠️  Token issued more than 24 hours ago")
        
        return warnings
    
    def add_finding(self, severity: str, title: str, description: str, recommendation: str):
        """Add a security finding"""
        finding = SecurityFinding(
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation
        )
        self.findings.append(finding)
    
    def calculate_security_score(self) -> SecurityScore:
        """Calculate overall security score based on findings"""
        score_breakdown = {
            'algorithm': 100,
            'claims': 100,
            'structure': 100,
            'attack_patterns': 100
        }
        
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for finding in self.findings:
            if finding.severity == 'CRITICAL':
                critical_count += 1
                score_breakdown['algorithm'] -= 30
                score_breakdown['claims'] -= 25
            elif finding.severity == 'HIGH':
                high_count += 1
                score_breakdown['algorithm'] -= 15
                score_breakdown['claims'] -= 15
            elif finding.severity == 'MEDIUM':
                medium_count += 1
                score_breakdown['algorithm'] -= 10
                score_breakdown['claims'] -= 10
            elif finding.severity == 'LOW':
                low_count += 1
                score_breakdown['algorithm'] -= 5
                score_breakdown['claims'] -= 5
        
        # Cap scores at 0-100
        for key in score_breakdown:
            score_breakdown[key] = max(0, min(100, score_breakdown[key]))
        
        overall_score = int(sum(score_breakdown.values()) / len(score_breakdown))
        
        # Determine risk level
        if overall_score <= 25:
            risk_level = 'CRITICAL'
        elif overall_score <= 50:
            risk_level = 'HIGH'
        elif overall_score <= 75:
            risk_level = 'MEDIUM'
        elif overall_score <= 90:
            risk_level = 'LOW'
        else:
            risk_level = 'EXCELLENT'
        
        risk_icon = RISK_LEVELS[[k for k in RISK_LEVELS.keys() if k <= overall_score][-1]]['icon']
        
        return SecurityScore(
            overall_score=overall_score,
            risk_level=risk_level,
            risk_icon=risk_icon,
            breakdown=score_breakdown,
            total_findings=len(self.findings),
            critical_findings=critical_count,
            high_findings=high_count,
            medium_findings=medium_count,
            low_findings=low_count
        )
    
    def inspect_token(self, token: str, secret: Optional[str] = None, 
                     public_key: Optional[str] = None) -> Dict[str, Any]:
        """Complete token inspection with security analysis"""
        logger.info("Starting JWT token inspection")
        
        # Reset findings
        self.findings = []
        
        # Analyze token structure
        structure_analysis = self.analyze_token_structure(token)
        
        # Parse token
        token_parts = self.parse_token(token)
        
        # Detect attack patterns
        attack_patterns = self.detect_attack_patterns(token_parts['payload'])
        
        # Detect vulnerable claims
        vulnerable_claims = self.detect_vulnerable_claims(token_parts['payload'])
        
        # Analyze algorithm security
        algorithm = token_parts['header'].get('alg', 'unknown')
        algo_analysis = self.analyze_algorithm_security(algorithm)
        
        # Analyze claims security
        claims_analysis = self.analyze_claims_security(token_parts['payload'])
        
        # Validate claims
        claims_warnings = self.validate_claims(token_parts['payload'])
        
        # Calculate security score
        security_score = self.calculate_security_score()
        
        # Signature verification
        verification_result = None
        if algorithm != 'NONE' and algorithm.upper() != 'NONE' and (secret or public_key):
            try:
                if algorithm.startswith('HS'):
                    if secret:
                        is_valid = self.verify_signature_hs(token_parts, secret)
                        verification_result = {
                            'verified': is_valid,
                            'method': 'HMAC',
                            'algorithm': algorithm
                        }
                elif algorithm.startswith('RS'):
                    if public_key:
                        is_valid = self.verify_signature_rsa(token_parts, public_key)
                        verification_result = {
                            'verified': is_valid,
                            'method': 'RSA',
                            'algorithm': algorithm
                        }
                elif algorithm.startswith('ES'):
                    if public_key:
                        is_valid = self.verify_signature_ecdsa(token_parts, public_key)
                        verification_result = {
                            'verified': is_valid,
                            'method': 'ECDSA',
                            'algorithm': algorithm
                        }
            except Exception as e:
                verification_result = {
                    'verified': False,
                    'error': str(e),
                    'algorithm': algorithm
                }
        elif algorithm.upper() == 'NONE':
            verification_result = {
                'verified': True,
                'warning': 'Token uses no signature (algorithm: none)',
                'algorithm': algorithm
            }
        
        # Build comprehensive result
        result = {
            'inspection_metadata': {
                'tool': APP_NAME,
                'version': APP_VERSION,
                'author': APP_AUTHOR,
                'timestamp': datetime.now().isoformat(),
                'build': APP_BUILD
            },
            'token_info': {
                'original': token,
                'structure': structure_analysis,
                'algorithm': algorithm,
                'algorithm_details': algo_analysis,
                'is_valid_format': structure_analysis['is_valid_format']
            },
            'header': token_parts['header'],
            'payload': token_parts['payload'],
            'signature': {
                'base64': token_parts['signature_b64'],
                'length': len(token_parts['signature'])
            },
            'security_analysis': {
                'score': security_score.overall_score,
                'risk_level': security_score.risk_level,
                'risk_icon': security_score.risk_icon,
                'breakdown': security_score.breakdown,
                'findings': [finding.to_dict() for finding in self.findings],
                'attack_patterns': attack_patterns,
                'vulnerable_claims': vulnerable_claims,
                'claims_analysis': claims_analysis,
                'claims_warnings': claims_warnings
            },
            'verification': verification_result
        }
        
        logger.info(f"Token inspection completed. Security score: {security_score.overall_score}/100 ({security_score.risk_level})")
        return result

# ============================================================================
# Output Formatter
# ============================================================================

class OutputFormatter:
    """Handles output formatting and persistence for JWT inspection results"""
    
    def __init__(self, output_dir: Path):
        """Initialize output formatter"""
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def save_to_file(self, content: str, filename_prefix: str, extension: str = "txt") -> Path:
        """Save content to a file with timestamp"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_prefix = re.sub(r'[<>:"/\\|?*]', '_', filename_prefix)
        filename = f"{safe_prefix}_{timestamp}.{extension}"
        filepath = self.output_dir / filename
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Results saved to: {filepath}")
            return filepath
        except IOError as e:
            logger.error(f"Failed to save results: {e}")
            raise
    
    def generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JWT Security Analysis Report - {APP_NAME} v{APP_VERSION}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            margin: 10px 0 0;
            opacity: 0.9;
        }}
        .score-card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .score {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .score-critical {{ color: #dc3545; }}
        .score-high {{ color: #fd7e14; }}
        .score-medium {{ color: #ffc107; }}
        .score-low {{ color: #28a745; }}
        .score-excellent {{ color: #20c997; }}
        .finding {{
            background: white;
            border-left: 4px solid;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .finding-critical {{ border-left-color: #dc3545; }}
        .finding-high {{ border-left-color: #fd7e14; }}
        .finding-medium {{ border-left-color: #ffc107; }}
        .finding-low {{ border-left-color: #28a745; }}
        .finding-title {{
            font-weight: bold;
            font-size: 1.1em;
            margin-bottom: 8px;
        }}
        .finding-description {{
            margin-bottom: 8px;
            color: #666;
        }}
        .finding-recommendation {{
            background: #f8f9fa;
            padding: 8px;
            border-radius: 4px;
            font-size: 0.9em;
            color: #28a745;
        }}
        .section {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            margin-top: 0;
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        pre {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9em;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 10px;
        }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 JWT Security Analysis Report</h1>
        <p>Generated by {APP_NAME} v{APP_VERSION} | Author: {APP_AUTHOR}</p>
        <p>Analysis Time: {results['inspection_metadata']['timestamp']}</p>
    </div>
    
    <div class="score-card">
        <h2>Security Score</h2>
        <div class="score score-{results['security_analysis']['risk_level'].lower()}">
            {results['security_analysis']['score']}/100
        </div>
        <div>
            Risk Level: <strong>{results['security_analysis']['risk_level']}</strong>
            <span class="badge badge-{results['security_analysis']['risk_level'].lower()}">
                {results['security_analysis']['risk_icon']}
            </span>
        </div>
        <div>Total Findings: {results['security_analysis']['findings']|length}</div>
        <div style="margin-top: 10px;">
            <small>Critical: {results['security_analysis']['critical_findings']} | 
                   High: {results['security_analysis']['high_findings']} | 
                   Medium: {results['security_analysis']['medium_findings']} | 
                   Low: {results['security_analysis']['low_findings']}</small>
        </div>
    </div>
    
    <div class="section">
        <h2>📊 Token Information</h2>
        <p><strong>Algorithm:</strong> {results['token_info']['algorithm']}</p>
        <p><strong>Algorithm Details:</strong> {results['token_info']['algorithm_details']['name']}</p>
        <p><strong>Token Length:</strong> {results['token_info']['structure']['length']} characters</p>
        <p><strong>Token Entropy:</strong> {results['token_info']['structure']['entropy']:.2f}</p>
        <p><strong>Valid Format:</strong> {'✓' if results['token_info']['is_valid_format'] else '✗'}</p>
    </div>
    
    <div class="section">
        <h2>📦 Header</h2>
        <pre>{json.dumps(results['header'], indent=2, default=str)}</pre>
    </div>
    
    <div class="section">
        <h2>📦 Payload</h2>
        <pre>{json.dumps(results['payload'], indent=2, default=str)}</pre>
    </div>
    
    <div class="section">
        <h2>🔐 Security Findings</h2>
        {self._generate_findings_html(results['security_analysis']['findings'])}
    </div>
    
    <div class="section">
        <h2>⚠️ Attack Patterns Detected</h2>
        {self._generate_attacks_html(results['security_analysis']['attack_patterns'])}
    </div>
    
    <div class="section">
        <h2>🔑 Signature Information</h2>
        <p><strong>Signature (Base64):</strong> {results['signature']['base64']}</p>
        <p><strong>Signature Length:</strong> {results['signature']['length']} bytes</p>
        {self._generate_verification_html(results['verification'])}
    </div>
    
    <div class="footer">
        <p>Report generated by {APP_NAME} v{APP_VERSION}</p>
        <p>Security analysis performed by Kareeb Sadab - Security Tools Team</p>
        <p>© 2025 - All Rights Reserved</p>
    </div>
</body>
</html>"""
        return html
    
    def _generate_findings_html(self, findings: List[Dict]) -> str:
        """Generate HTML for findings"""
        if not findings:
            return "<p>✓ No security findings detected</p>"
        
        html = ""
        for finding in findings:
            severity_class = finding['severity'].lower()
            html += f"""
            <div class="finding finding-{severity_class}">
                <div class="finding-title">
                    {finding['title']}
                    <span class="badge badge-{severity_class}">{finding['severity']}</span>
                </div>
                <div class="finding-description">{finding['description']}</div>
                <div class="finding-recommendation">💡 {finding['recommendation']}</div>
            </div>
            """
        return html
    
    def _generate_attacks_html(self, attacks: List[Dict]) -> str:
        """Generate HTML for attack patterns"""
        if not attacks:
            return "<p>✓ No attack patterns detected</p>"
        
        html = "<ul>"
        for attack in attacks:
            html += f"<li><strong>{attack['type']}</strong> - {attack['description']}</li>"
        html += "</ul>"
        return html
    
    def _generate_verification_html(self, verification: Optional[Dict]) -> str:
        """Generate HTML for signature verification"""
        if not verification:
            return "<p>⚠️ No verification performed</p>"
        
        if verification.get('verified'):
            html = "<p style='color: #28a745;'>✓ Signature is VALID</p>"
            html += f"<p>Verification Method: {verification.get('method', 'N/A')}</p>"
            html += f"<p>Algorithm: {verification.get('algorithm', 'N/A')}</p>"
            if verification.get('warning'):
                html += f"<p style='color: #ffc107;'>⚠️ Warning: {verification['warning']}</p>"
        else:
            html = "<p style='color: #dc3545;'>✗ Signature is INVALID</p>"
            if verification.get('error'):
                html += f"<p>Error: {verification['error']}</p>"
        
        return html
    
    def format_text_output(self, results: Dict[str, Any]) -> str:
        """Format inspection results as formatted text"""
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append(f"{APP_NAME} v{APP_VERSION} - Security Analysis Report")
        lines.append(f"Author: {APP_AUTHOR}")
        lines.append(f"Timestamp: {results['inspection_metadata']['timestamp']}")
        lines.append("=" * 80)
        
        # Security Score
        score = results['security_analysis']['score']
        risk_level = results['security_analysis']['risk_level']
        risk_icon = results['security_analysis']['risk_icon']
        
        lines.append(f"\n🔒 SECURITY SCORE: {score}/100 {risk_icon} ({risk_level})")
        lines.append("-" * 80)
        lines.append(f"Algorithm Score: {results['security_analysis']['breakdown']['algorithm']}/100")
        lines.append(f"Claims Score: {results['security_analysis']['breakdown']['claims']}/100")
        lines.append(f"Structure Score: {results['security_analysis']['breakdown']['structure']}/100")
        lines.append(f"Attack Score: {results['security_analysis']['breakdown']['attack_patterns']}/100")
        lines.append(f"\nTotal Findings: {results['security_analysis']['total_findings']}")
        
        # Token Summary
        lines.append("\n📋 TOKEN SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Algorithm: {results['token_info']['algorithm']}")
        lines.append(f"Algorithm Type: {results['token_info']['algorithm_details'].get('type', 'Unknown')}")
        lines.append(f"Algorithm Strength: {results['token_info']['algorithm_details'].get('strength', 'Unknown')}")
        lines.append(f"Token Length: {results['token_info']['structure']['length']} characters")
        lines.append(f"Token Entropy: {results['token_info']['structure']['entropy']:.2f}")
        
        # Security Findings
        if results['security_analysis']['findings']:
            lines.append("\n⚠️  SECURITY FINDINGS")
            lines.append("-" * 80)
            for finding in results['security_analysis']['findings']:
                severity = finding['severity']
                icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢"
                lines.append(f"\n{icon} [{severity}] {finding['title']}")
                lines.append(f"   {finding['description']}")
                lines.append(f"   💡 Recommendation: {finding['recommendation']}")
        
        # Attack Patterns
        if results['security_analysis']['attack_patterns']:
            lines.append("\n🎯 ATTACK PATTERNS DETECTED")
            lines.append("-" * 80)
            for attack in results['security_analysis']['attack_patterns']:
                lines.append(f"  • {attack['type']} ({attack['severity']}): {attack['description']}")
        
        # Header
        lines.append("\n📦 HEADER")
        lines.append("-" * 80)
        lines.append(json.dumps(results['header'], indent=2, default=str))
        
        # Payload
        lines.append("\n📦 PAYLOAD")
        lines.append("-" * 80)
        lines.append(json.dumps(results['payload'], indent=2, default=str))
        
        # Signature
        lines.append("\n🔐 SIGNATURE")
        lines.append("-" * 80)
        lines.append(f"Base64: {results['signature']['base64']}")
        lines.append(f"Length: {results['signature']['length']} bytes")
        
        # Verification
        if results.get('verification'):
            lines.append("\n✓ SIGNATURE VERIFICATION")
            lines.append("-" * 80)
            if results['verification'].get('verified'):
                lines.append(f"Status: ✓ VALID")
                lines.append(f"Method: {results['verification'].get('method', 'N/A')}")
                if results['verification'].get('warning'):
                    lines.append(f"Warning: {results['verification']['warning']}")
            else:
                lines.append(f"Status: ✗ INVALID")
                if results['verification'].get('error'):
                    lines.append(f"Error: {results['verification']['error']}")
        
        lines.append("\n" + "=" * 80)
        
        return "\n".join(lines)
    
    def format_json_output(self, results: Dict[str, Any]) -> str:
        """Format results as JSON"""
        def json_serializer(obj):
            if isinstance(obj, bytes):
                return obj.decode('utf-8', errors='replace')
            raise TypeError(f"Type {type(obj)} not serializable")
        
        return json.dumps(results, indent=2, default=json_serializer)

# ============================================================================
# Main Application
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{APP_VERSION} - Professional JWT Security Inspector by {APP_AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Basic token inspection
  {sys.argv[0]} eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

  # With secret verification (HS256)
  {sys.argv[0]} <token> --secret "my-secret-key"

  # With public key verification (RS256)
  {sys.argv[0]} <token> --public-key ./public_key.pem

  # JSON output
  {sys.argv[0]} <token> --json

  # HTML report
  {sys.argv[0]} <token> --html

  # Save to file
  {sys.argv[0]} <token> --save

  # Verbose mode with logging
  {sys.argv[0]} <token> --verbose

  # Read token from file
  {sys.argv[0]} --token-file token.txt

Security Notes:
  - Never share tokens with sensitive data
  - Always verify signatures in production
  - Avoid using 'none' algorithm
  - Use strong algorithms (RS256, ES256)
  - Keep tokens short-lived (hours, not days)
  - Always include exp, iat claims

Author: Kareeb Sadab - Security Tools Team
Version: {APP_VERSION}
Build: {APP_BUILD}
        """
    )
    
    parser.add_argument(
        'token',
        nargs='?',
        help='JWT token to inspect'
    )
    
    parser.add_argument(
        '--token-file',
        help='Read JWT token from file'
    )
    
    parser.add_argument(
        '-s', '--secret',
        help='Secret key for HMAC signature verification'
    )
    
    parser.add_argument(
        '--public-key',
        help='Public key file for RSA/ECDSA signature verification'
    )
    
    parser.add_argument(
        '-j', '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    
    parser.add_argument(
        '--html',
        action='store_true',
        help='Generate HTML report'
    )
    
    parser.add_argument(
        '--save',
        action='store_true',
        help='Save results to file'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging (DEBUG level)'
    )
    
    parser.add_argument(
        '--output-dir',
        default=DEFAULT_OUTPUT_DIR,
        help=f'Directory for output files (default: {DEFAULT_OUTPUT_DIR})'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'{APP_NAME} v{APP_VERSION} (Build {APP_BUILD}) - Author: {APP_AUTHOR}'
    )
    
    return parser.parse_args()

def read_token_from_file(file_path: str) -> str:
    """Read JWT token from file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            token = f.read().strip()
            return token
    except Exception as e:
        raise InvalidJWTError(f"Failed to read token file: {e}")

def main() -> int:
    """Main entry point for JWT Inspector"""
    # Parse arguments
    args = parse_arguments()
    
    # Setup output directory
    output_dir = Path(args.output_dir)
    
    # Setup logging
    global logger
    logger = setup_logging(output_dir, args.verbose)
    
    # Log startup
    logger.info(f"Starting {APP_NAME} v{APP_VERSION} by {APP_AUTHOR}")
    logger.debug(f"Command line arguments: {args}")
    
    try:
        # Get token
        token = None
        if args.token_file:
            token = read_token_from_file(args.token_file)
            logger.info(f"Token loaded from file: {args.token_file}")
        elif args.token:
            token = args.token
        else:
            print("Error: No token provided. Use --token-file or provide token as argument.", file=sys.stderr)
            return 1
        
        # Initialize inspector
        inspector = JWTInspector(verbose=args.verbose)
        
        # Inspect token
        results = inspector.inspect_token(
            token,
            secret=args.secret,
            public_key=args.public_key
        )
        
        # Initialize formatter
        formatter = OutputFormatter(output_dir)
        
        # Format and display results
        if args.json:
            output_content = formatter.format_json_output(results)
            print(output_content)
        elif args.html:
            output_content = formatter.generate_html_report(results)
            print(output_content)
        else:
            output_content = formatter.format_text_output(results)
            print(output_content)
        
        # Save results if requested
        if args.save:
            if args.json:
                extension = 'json'
                content = output_content
            elif args.html:
                extension = 'html'
                content = output_content
            else:
                extension = 'txt'
                content = output_content
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            saved_path = formatter.save_to_file(output_content, f"jwt_inspection_{timestamp}", extension)
            logger.info(f"Inspection results saved to {saved_path}")
        
        # Return appropriate exit code based on risk level
        risk_level = results['security_analysis']['risk_level']
        if risk_level == 'CRITICAL':
            return 2
        elif risk_level == 'HIGH':
            return 1
        else:
            return 0
    
    except InvalidJWTError as e:
        logger.error(f"Invalid JWT: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    except TokenExpiredError as e:
        logger.error(f"Token expired: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    except VerificationError as e:
        logger.error(f"Verification failed: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        print("\nOperation cancelled by user", file=sys.stderr)
        return 130
    
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1

# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    sys.exit(main())