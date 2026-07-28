"""
api_clients.py - Threat Intelligence API Clients
For ThreatSense AI
"""

import os
import requests
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

class VirusTotalClient:
    """Client for VirusTotal API"""
    
    def __init__(self):
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check an IP address against VirusTotal"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            response = requests.get(
                f"{self.base_url}/ip_addresses/{ip}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0),
                    "total": sum(stats.values()) if stats else 0,
                    "reputation": attributes.get('reputation', 0)
                }
            elif response.status_code == 404:
                return {"error": "IP not found in VirusTotal"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check a domain against VirusTotal"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            response = requests.get(
                f"{self.base_url}/domains/{domain}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0),
                    "total": sum(stats.values()) if stats else 0,
                }
            elif response.status_code == 404:
                return {"error": "Domain not found in VirusTotal"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}


class OTXClient:
    """Client for AlienVault OTX API"""
    
    def __init__(self):
        self.api_key = os.getenv('OTX_API_KEY')
        self.base_url = "https://otx.alienvault.com/api/v1"
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check an IP against AlienVault OTX"""
        if not self.api_key:
            return {"error": "OTX API key not configured"}
        
        try:
            response = requests.get(
                f"{self.base_url}/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": self.api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                
                return {
                    "pulse_count": pulse_info.get('count', 0),
                    "reputation": data.get('reputation', 0),
                    "validation": data.get('validation', 'unknown'),
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check a domain against AlienVault OTX"""
        if not self.api_key:
            return {"error": "OTX API key not configured"}
        
        try:
            response = requests.get(
                f"{self.base_url}/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": self.api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                
                return {
                    "pulse_count": pulse_info.get('count', 0),
                    "reputation": data.get('reputation', 0),
                    "validation": data.get('validation', 'unknown')
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}


class AbuseIPDBClient:
    """Client for AbuseIPDB API"""
    
    def __init__(self):
        self.api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.base_url = "https://api.abuseipdb.com/api/v2"
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check an IP against AbuseIPDB"""
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        try:
            response = requests.get(
                f"{self.base_url}/check",
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    "abuse_score": data.get('abuseConfidenceScore', 0),
                    "total_reports": data.get('totalReports', 0),
                    "country": data.get('countryCode', 'unknown'),
                    "is_malicious": data.get('abuseConfidenceScore', 0) > 50
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}