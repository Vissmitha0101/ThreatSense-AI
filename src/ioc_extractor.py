"""
ioc_extractor.py - IOC Extraction Engine for ThreatSense AI
"""

import re
import math
from typing import Dict, Set, Tuple

class IOCExtractor:
    """Extracts IPs, domains, and hashes from text."""
    
    def __init__(self):
        """Initialize with filtering lists."""
        
        # SAFE: Known good domains - IGNORE
        self.safe_domains = {
            'google.com', 'gmail.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'github.com', 'yahoo.com', 'bing.com',
            'duckduckgo.com', 'reddit.com', 'wikipedia.org'
        }
        
        # SUSPICIOUS: TLDs often used by attackers
        self.suspicious_tlds = {
            '.xyz', '.top', '.club', '.win', '.bid', '.date',
            '.download', '.review', '.science', '.trade', '.stream',
            '.men', '.loan', '.click', '.link', '.gq', '.ml', '.tk'
        }
        
        # BRANDS: Names impersonated in phishing
        self.brands = {
            'google', 'microsoft', 'apple', 'amazon', 'paypal',
            'bank', 'secure', 'login', 'verify', 'facebook'
        }
    
    def extract_ips(self, text: str) -> Set[str]:
        """Extract public IPs only (skip private)."""
        pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        matches = re.findall(pattern, text)
        
        public_ips = set()
        for ip in matches:
            if self._is_public_ip(ip):
                public_ips.add(ip)
        
        return public_ips
    
    def _is_public_ip(self, ip: str) -> bool:
        """Check if IP is public (not private)."""
        parts = ip.split('.')
        first = int(parts[0])
        second = int(parts[1])
        
        # Private IP ranges
        if first == 10: return False          # 10.0.0.0/8
        if first == 127: return False         # 127.0.0.0/8
        if first == 192 and second == 168: return False  # 192.168.0.0/16
        if first == 172 and 16 <= second <= 31: return False  # 172.16.0.0/12
        
        return True
    
    def extract_domains(self, text: str) -> Set[str]:
        """Extract domains (skip safe ones)."""
        pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        matches = re.findall(pattern, text, re.IGNORECASE)
        
        domains = set()
        for domain in matches:
            domain = domain.lower()
            if domain not in self.safe_domains:
                domains.add(domain)
        
        return domains
    
    def extract_hashes(self, text: str) -> Set[Tuple[str, str]]:
        """Extract MD5, SHA1, SHA256 hashes."""
        hashes = set()
        
        # MD5: 32 hex chars
        for match in re.finditer(r'\b[a-fA-F0-9]{32}\b', text):
            hashes.add(('MD5', match.group().lower()))
        
        # SHA1: 40 hex chars
        for match in re.finditer(r'\b[a-fA-F0-9]{40}\b', text):
            hashes.add(('SHA1', match.group().lower()))
        
        # SHA256: 64 hex chars
        for match in re.finditer(r'\b[a-fA-F0-9]{64}\b', text):
            hashes.add(('SHA256', match.group().lower()))
        
        return hashes
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate randomness - high = suspicious."""
        if not text:
            return 0.0
        entropy = 0.0
        for char in set(text):
            p = text.count(char) / len(text)
            entropy -= p * math.log2(p)
        return entropy
    
    def is_suspicious_domain(self, domain: str) -> Tuple[bool, str]:
        """Check if domain looks suspicious."""
        domain = domain.lower()
        
        # High entropy (DGA-like)
        entropy = self.calculate_entropy(domain)
        if entropy > 4.0:
            return True, f"High entropy ({entropy:.2f})"
        
        # Suspicious TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return True, f"Suspicious TLD: {tld}"
        
        # Brand impersonation
        domain_name = domain.split('.')[0]
        for brand in self.brands:
            if brand in domain_name and brand != domain_name:
                return True, f"Impersonating: {brand}"
        
        return False, "Looks clean"
    
    def extract_all(self, text: str) -> Dict[str, Set]:
        """Extract ALL IOCs."""
        if not text:
            return {'ips': set(), 'domains': set(), 'hashes': set()}
        
        return {
            'ips': self.extract_ips(text),
            'domains': self.extract_domains(text),
            'hashes': self.extract_hashes(text)
        }
    
    def get_summary(self, iocs: Dict[str, Set]) -> Dict[str, int]:
        """Get count summary of extracted IOCs."""
        return {
            'total_ips': len(iocs['ips']),
            'total_domains': len(iocs['domains']),
            'total_hashes': len(iocs['hashes']),
            'total_iocs': len(iocs['ips']) + len(iocs['domains']) + len(iocs['hashes'])
        }
    
    def print_results(self, iocs: Dict[str, Set]) -> None:
        """Pretty print results."""
        print("\n" + "="*60)
        print(" EXTRACTED IOCS")
        print("="*60)
        
        if iocs['ips']:
            print(f"\n IPs ({len(iocs['ips'])}):")
            for ip in sorted(iocs['ips']):
                print(f"  - {ip}")
        
        if iocs['domains']:
            print(f"\n Domains ({len(iocs['domains'])}):")
            for domain in sorted(iocs['domains']):
                suspicious, reason = self.is_suspicious_domain(domain)
                flag = "danger" if suspicious else "safe"
                print(f"  {flag} {domain}")
                if suspicious:
                    print(f"     └─ Reason: {reason}")
        
        if iocs['hashes']:
            print(f"\n Hashes ({len(iocs['hashes'])}):")
            for hash_type, hash_val in sorted(iocs['hashes']):
                print(f"  - {hash_type}: {hash_val}")
        
        if not any(iocs.values()):
            print("\n No IOCs found.")
        
        print("\n" + "="*60)