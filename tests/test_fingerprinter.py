"""
Unit tests for Attack Surface Fingerprinter.
"""

from ai_sentinel.recon.fingerprinter import AttackSurfaceFingerprinter

def test_fingerprinter_structure():
    # Test against a local or mock URL structure
    result = AttackSurfaceFingerprinter.fingerprint("http://127.0.0.1:8000")
    assert "target" in result
    assert "security_score" in result
    assert "vulnerabilities" in result
    assert "discovered_endpoints" in result