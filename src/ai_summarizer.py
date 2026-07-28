<<<<<<< HEAD
"""
ai_summarizer.py - FREE AI-Powered Threat Summaries
Uses Ollama - 100% FREE, runs locally!
"""

import requests
from typing import Dict, Any

class AISummarizer:
    """Generates AI-powered threat summaries using FREE Ollama"""
    
    def __init__(self):
        self.model = "tinyllama"
        self.ollama_url = "http://127.0.0.1:11434/api/generate"
        self.use_ollama = self._check_ollama()
        
        if not self.use_ollama:
            print("⚠️ Ollama not running. Start it with: ollama serve")
            print("   Using fallback mode (no AI).")
    
    def _check_ollama(self) -> bool:
        """Check if Ollama is running"""
        try:
            response = requests.get("http://127.0.0.1:11434/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def generate_summary(self, ioc: str, ioc_type: str, results: Dict[str, Any]) -> str:
        """Generate a threat summary using FREE Ollama"""
        
        if not self.use_ollama:
            return self._generate_fallback_summary(ioc, ioc_type, results)
        
        formatted_results = []
        for source, data in results.items():
            if data.get('error'):
                formatted_results.append(f"- {source}: Error - {data['error']}")
            else:
                clean_data = {k: v for k, v in data.items() if k != 'error'}
                formatted_results.append(f"- {source}: {clean_data}")
        
        prompt = f"""
You are a cybersecurity analyst. Analyze this IOC data:

IOC: {ioc}
Type: {ioc_type}

Results:
{chr(10).join(formatted_results)}

Give:
1. Verdict: [MALICIOUS/SUSPICIOUS/CLEAN/UNKNOWN]
2. Brief summary (2 sentences)
3. Recommended action

Format exactly like this:
VERDICT: [your answer]
SUMMARY: [your answer]
RECOMMENDATIONS: [your answer]
"""
        
        try:
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3,
                    "max_tokens": 300
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('response', 'No response from AI')
            else:
                return self._generate_fallback_summary(ioc, ioc_type, results)
                
        except Exception as e:
            print(f"⚠️ AI Error: {e}")
            return self._generate_fallback_summary(ioc, ioc_type, results)
    
    def generate_combined_summary(self, iocs: Dict[str, set], all_results: list) -> str:
        """Generate a combined summary for multiple IOCs"""
        
        total_ips = len(iocs.get('ips', set()))
        total_domains = len(iocs.get('domains', set()))
        total_hashes = len(iocs.get('hashes', set()))
        
        malicious_count = 0
        for result in all_results:
            vt = result.get('sources', {}).get('virustotal', {})
            if vt.get('malicious', 0) > 0:
                malicious_count += 1
        
        if not self.use_ollama:
            return f"""
THREAT LEVEL: {'HIGH' if malicious_count > 0 else 'LOW'}
SUMMARY: Found {total_ips + total_domains + total_hashes} IOCs. {malicious_count} are known malicious.
RECOMMENDATIONS: Investigate all IOCs. Block malicious ones at firewall.
"""
        
        prompt = f"""
Analyze these threat findings:

- Total IOCs: {total_ips + total_domains + total_hashes}
- Malicious: {malicious_count}
- IPs: {total_ips}
- Domains: {total_domains}
- Hashes: {total_hashes}

Give:
1. Threat Level: [CRITICAL/HIGH/MEDIUM/LOW]
2. Brief summary (2 sentences)
3. Recommended actions

Format exactly like this:
THREAT LEVEL: [your answer]
SUMMARY: [your answer]
RECOMMENDATIONS: [your answer]
"""
        
        try:
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3,
                    "max_tokens": 200
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('response', 'AI response unavailable')
            else:
                return "Threat analysis complete. Review the raw data above."
                
        except Exception as e:
            print(f" AI Error: {e}")
            return "Threat analysis complete. Review the raw data above."
    
    def _generate_fallback_summary(self, ioc: str, ioc_type: str, results: Dict[str, Any]) -> str:
        """Fallback summary (no AI needed)"""
        
        malicious_count = 0
        for provider, data in results.items():
            if data.get('error'):
                continue
            if data.get('malicious', 0) > 0 or data.get('abuse_score', 0) > 50:
                malicious_count += 1
        
        if malicious_count >= 2:
            verdict = " MALICIOUS"
            summary = f"{ioc} is confirmed malicious by multiple threat intelligence sources."
            actions = "Block immediately. Investigate any connections to this IOC."
        elif malicious_count >= 1:
            verdict = " SUSPICIOUS"
            summary = f"{ioc} has suspicious activity reported by some sources."
            actions = "Investigate further. Monitor for suspicious activity."
        else:
            verdict = " CLEAN"
            summary = f"No known threats associated with {ioc}."
            actions = "No action needed, but continue monitoring."
        
        return f"""
VERDICT: {verdict}
SUMMARY: {summary}
RECOMMENDATIONS: {actions}
=======
"""
ai_summarizer.py - FREE AI-Powered Threat Summaries
Uses Ollama - 100% FREE, runs locally!
"""

import requests
from typing import Dict, Any

class AISummarizer:
    """Generates AI-powered threat summaries using FREE Ollama"""
    
    def __init__(self):
        self.model = "tinyllama"
        self.ollama_url = "http://127.0.0.1:11434/api/generate"
        self.use_ollama = self._check_ollama()
        
        if not self.use_ollama:
            print("⚠️ Ollama not running. Start it with: ollama serve")
            print("   Using fallback mode (no AI).")
    
    def _check_ollama(self) -> bool:
        """Check if Ollama is running"""
        try:
            response = requests.get("http://127.0.0.1:11434/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def generate_summary(self, ioc: str, ioc_type: str, results: Dict[str, Any]) -> str:
        """Generate a threat summary using FREE Ollama"""
        
        if not self.use_ollama:
            return self._generate_fallback_summary(ioc, ioc_type, results)
        
        formatted_results = []
        for source, data in results.items():
            if data.get('error'):
                formatted_results.append(f"- {source}: Error - {data['error']}")
            else:
                clean_data = {k: v for k, v in data.items() if k != 'error'}
                formatted_results.append(f"- {source}: {clean_data}")
        
        prompt = f"""
You are a cybersecurity analyst. Analyze this IOC data:

IOC: {ioc}
Type: {ioc_type}

Results:
{chr(10).join(formatted_results)}

Give:
1. Verdict: [MALICIOUS/SUSPICIOUS/CLEAN/UNKNOWN]
2. Brief summary (2 sentences)
3. Recommended action

Format exactly like this:
VERDICT: [your answer]
SUMMARY: [your answer]
RECOMMENDATIONS: [your answer]
"""
        
        try:
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3,
                    "max_tokens": 300
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('response', 'No response from AI')
            else:
                return self._generate_fallback_summary(ioc, ioc_type, results)
                
        except Exception as e:
            print(f"⚠️ AI Error: {e}")
            return self._generate_fallback_summary(ioc, ioc_type, results)
    
    def generate_combined_summary(self, iocs: Dict[str, set], all_results: list) -> str:
        """Generate a combined summary for multiple IOCs"""
        
        total_ips = len(iocs.get('ips', set()))
        total_domains = len(iocs.get('domains', set()))
        total_hashes = len(iocs.get('hashes', set()))
        
        malicious_count = 0
        for result in all_results:
            vt = result.get('sources', {}).get('virustotal', {})
            if vt.get('malicious', 0) > 0:
                malicious_count += 1
        
        if not self.use_ollama:
            return f"""
THREAT LEVEL: {'HIGH' if malicious_count > 0 else 'LOW'}
SUMMARY: Found {total_ips + total_domains + total_hashes} IOCs. {malicious_count} are known malicious.
RECOMMENDATIONS: Investigate all IOCs. Block malicious ones at firewall.
"""
        
        prompt = f"""
Analyze these threat findings:

- Total IOCs: {total_ips + total_domains + total_hashes}
- Malicious: {malicious_count}
- IPs: {total_ips}
- Domains: {total_domains}
- Hashes: {total_hashes}

Give:
1. Threat Level: [CRITICAL/HIGH/MEDIUM/LOW]
2. Brief summary (2 sentences)
3. Recommended actions

Format exactly like this:
THREAT LEVEL: [your answer]
SUMMARY: [your answer]
RECOMMENDATIONS: [your answer]
"""
        
        try:
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3,
                    "max_tokens": 200
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('response', 'AI response unavailable')
            else:
                return "Threat analysis complete. Review the raw data above."
                
        except Exception as e:
            print(f" AI Error: {e}")
            return "Threat analysis complete. Review the raw data above."
    
    def _generate_fallback_summary(self, ioc: str, ioc_type: str, results: Dict[str, Any]) -> str:
        """Fallback summary (no AI needed)"""
        
        malicious_count = 0
        for provider, data in results.items():
            if data.get('error'):
                continue
            if data.get('malicious', 0) > 0 or data.get('abuse_score', 0) > 50:
                malicious_count += 1
        
        if malicious_count >= 2:
            verdict = " MALICIOUS"
            summary = f"{ioc} is confirmed malicious by multiple threat intelligence sources."
            actions = "Block immediately. Investigate any connections to this IOC."
        elif malicious_count >= 1:
            verdict = " SUSPICIOUS"
            summary = f"{ioc} has suspicious activity reported by some sources."
            actions = "Investigate further. Monitor for suspicious activity."
        else:
            verdict = " CLEAN"
            summary = f"No known threats associated with {ioc}."
            actions = "No action needed, but continue monitoring."
        
        return f"""
VERDICT: {verdict}
SUMMARY: {summary}
RECOMMENDATIONS: {actions}
>>>>>>> 24067d2deca5ddb513a9d049d9d76680279797fb
"""