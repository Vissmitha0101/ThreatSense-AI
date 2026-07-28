"""
test_extractor.py - Test the IOC Extractor
"""

import sys
import os

import sys
import os

# This tells Python where to find the src folder
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ioc_extractor import IOCExtractor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ioc_extractor import IOCExtractor

def test_ips():
    print(" Testing IP extraction...")
    extractor = IOCExtractor()
    text = "Private: 192.168.1.5, Public: 5.5.5.5, 8.8.8.8"
    iocs = extractor.extract_all(text)
    
    assert '5.5.5.5' in iocs['ips'], " 5.5.5.5 not found"
    assert '192.168.1.5' not in iocs['ips'], " Private IP found"
    print(" IP test passed!")

def test_domains():
    print(" Testing domain extraction...")
    extractor = IOCExtractor()
    text = "Safe: google.com, Suspicious: evil.xyz"
    iocs = extractor.extract_all(text)
    
    assert 'evil.xyz' in iocs['domains'], " evil.xyz not found"
    assert 'google.com' not in iocs['domains'], " Safe domain found"
    print(" Domain test passed!")

def test_suspicious():
    print(" Testing suspicious detection...")
    extractor = IOCExtractor()
    
    suspicious, reason = extractor.is_suspicious_domain("evil.xyz")
    assert suspicious == True, " Should be suspicious"
    
    suspicious, reason = extractor.is_suspicious_domain("google.com")
    assert suspicious == False, " Should be clean"
    
    print(" Suspicious test passed!")

def test_hashes():
    print(" Testing hash extraction...")
    extractor = IOCExtractor()
    text = "MD5: 44d88612fea8a8f36de82e1278abb02f"
    iocs = extractor.extract_all(text)
    
    assert len(iocs['hashes']) == 1, "❌ Hash not found"
    print(" Hash test passed!")

def main():
    print("="*60)
    print(" RUNNING IOC EXTRACTOR TESTS")
    print("="*60 + "\n")
    
    test_ips()
    test_domains()
    test_suspicious()
    test_hashes()
    
    print("\n" + "="*60)
    print(" ALL TESTS PASSED!")
    print("="*60)

if __name__ == "__main__":
    main()