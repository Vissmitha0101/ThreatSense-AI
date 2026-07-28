"""
main.py - ThreatSense AI Main Entry Point
"""

import os
import json
from datetime import datetime
from dotenv import load_dotenv

from src.ioc_extractor import IOCExtractor
from src.api_clients import VirusTotalClient, OTXClient, AbuseIPDBClient
from src.ai_summarizer import AISummarizer

load_dotenv()

class ThreatSenseAI:
    """Complete Threat Intelligence Platform"""
    
    def __init__(self):
        self.extractor = IOCExtractor()
        self.vt = VirusTotalClient()
        self.otx = OTXClient()
        self.abuse = AbuseIPDBClient()
        self.ai = AISummarizer()
    
    def analyze_text(self, text: str, source: str = "manual"):
        """Analyze text for IOCs and generate threat intelligence"""
        
        print()
        print(" THREATSENSEAI - THREAT ANALYSIS")
        print()
        print(f" Source: {source.upper()}")
        print(f" Text Preview: {text[:200]}")
        print()
        
        # Step 1: Extract IOCs
        print("\n Extracting IOCs")
        iocs = self.extractor.extract_all(text)
        summary = self.extractor.get_summary(iocs)
        print(f"    Found: {summary['total_iocs']} IOCs")
        print(f"      - {summary['total_ips']} IPs")
        print(f"      - {summary['total_domains']} Domains")
        print(f"      - {summary['total_hashes']} Hashes")
        
        if summary['total_iocs'] == 0:
            print("\n No IOCs found in this text.")
            return
        
        # Step 2: Enrich with Threat Intelligence
        print("\n Enriching with Threat Intelligence")
        all_results = []
        
        for ioc_type, ioc_set in iocs.items():
            if ioc_type == 'ips':
                for ioc in ioc_set:
                    print(f"   Checking IP: {ioc}")
                    result = {
                        "ioc": ioc,
                        "type": "ip",
                        "sources": {}
                    }
                    result["sources"]["virustotal"] = self.vt.check_ip(ioc)
                    result["sources"]["otx"] = self.otx.check_ip(ioc)
                    result["sources"]["abuseipdb"] = self.abuse.check_ip(ioc)
                    all_results.append(result)
            
            elif ioc_type == 'domains':
                for ioc in ioc_set:
                    print(f"   Checking Domain: {ioc}")
                    result = {
                        "ioc": ioc,
                        "type": "domain",
                        "sources": {}
                    }
                    result["sources"]["virustotal"] = self.vt.check_domain(ioc)
                    result["sources"]["otx"] = self.otx.check_domain(ioc)
                    all_results.append(result)
        
        # Step 3: Generate AI Summary
        print("\n  Generating AI Threat Summary")
        
        if len(all_results) == 1:
            result = all_results[0]
            summary_text = self.ai.generate_summary(
                result['ioc'],
                result['type'],
                result['sources']
            )
        else:
            summary_text = self.ai.generate_combined_summary(iocs, all_results)
        
        # Step 4: Display Results
        self._display_results(iocs, all_results, summary_text, source)
        
        # Step 5: Save Report
        self._save_report(iocs, all_results, summary_text, source, text[:500])
    
    def _display_results(self, iocs: dict, all_results: list, summary: str, source: str):
        """Display results in a nice format"""
        
        print()
        print(" THREAT INTELLIGENCE REPORT")
        print()
        
        print("\n EXTRACTED IOCS:")
        print()
        
        if iocs['ips']:
            print("\n IPs:")
            for ip in sorted(iocs['ips']):
                print(f"  - {ip}")
        
        if iocs['domains']:
            print("\n Domains:")
            for domain in sorted(iocs['domains']):
                suspicious, reason = self.extractor.is_suspicious_domain(domain)
                flag = " NO " if suspicious else " FOUND "
                print(f"  {flag} {domain}")
                if suspicious:
                    print(f"     └─ Reason: {reason}")
        
        if iocs['hashes']:
            print("\n Hashes:")
            for hash_type, hash_val in sorted(iocs['hashes']):
                print(f"  - {hash_type}: {hash_val[:16]}...")
        
        print()
        print("THREAT INTELLIGENCE RESULTS:")
        print()
        
        for result in all_results:
            print(f"\n  {result['ioc']} ({result['type']}):")
            
            vt = result['sources'].get('virustotal', {})
            if vt.get('error'):
                print(f"     VirusTotal: {vt['error']}")
            else:
                print(f"     VirusTotal: {vt.get('malicious', 0)}/{vt.get('total', 0)} vendors flag")
            
            otx = result['sources'].get('otx', {})
            if otx.get('error'):
                print(f"     OTX: {otx['error']}")
            else:
                print(f"     OTX: {otx.get('pulse_count', 0)} pulses")
            
            abuse = result['sources'].get('abuseipdb', {})
            if abuse and abuse.get('error'):
                print(f"     AbuseIPDB: {abuse['error']}")
            elif abuse:
                print(f"     AbuseIPDB: Score {abuse.get('abuse_score', 0)}/100")
        
        print()
        print(" AI THREAT SUMMARY:")
        print()
        print(summary)
        print()
        
        print("\n Analysis Complete!")
    
    def _save_report(self, iocs: dict, all_results: list, summary: str, source: str, text_preview: str):
        """Save results to JSON file"""
        
        os.makedirs("reports", exist_ok=True)
        filename = f"reports/threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "iocs": {k: list(v) if isinstance(v, set) else v for k, v in iocs.items()},
            "results": all_results,
            "ai_summary": summary,
            "text_preview": text_preview
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n Report saved to: {filename}")


def main():
    """Main entry point"""
    
    print()
    print("THREATSENSE AI")
    print("AI-Powered IOC Detection & Threat Hunting Platform")
    print()
    
    engine = ThreatSenseAI()
    
    # Sample alert text to analyze
    sample_text = """
    ALERT: Suspicious activity detected!
    
    Host 192.168.1.105 is communicating with external IP 5.5.5.5.
    The domain evil-domain.xyz was resolved.
    File hash: 44d88612fea8a8f36de82e1278abb02f
    
    Also saw traffic to google-secure-login.xyz - possible phishing!
    """
    
    engine.analyze_text(sample_text, source="sample_alert")


if __name__ == "__main__":
    main()