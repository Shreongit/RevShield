import pytest
from app.core.security import validate_target_url_security, is_ip_blocked

def test_blocked_ip_ranges():
    # Loopback
    assert is_ip_blocked("127.0.0.1") is True
    assert is_ip_blocked("127.0.1.5") is True
    # Private RFC 1918
    assert is_ip_blocked("10.0.0.1") is True
    assert is_ip_blocked("172.16.0.1") is True
    assert is_ip_blocked("192.168.1.1") is True
    # Link-local / Cloud Metadata
    assert is_ip_blocked("169.254.169.254") is True
    # Public IPs
    assert is_ip_blocked("8.8.8.8") is False
    assert is_ip_blocked("1.1.1.1") is False

def test_url_ssrf_validation():
    # Should block dangerous schemes
    valid, _, msg = validate_target_url_security("file:///etc/passwd")
    assert valid is False
    assert "not allowed" in msg

    valid, _, msg = validate_target_url_security("ftp://example.com")
    assert valid is False

    # Should block localhost & metadata hostnames
    valid, _, msg = validate_target_url_security("http://localhost:8000")
    assert valid is False

    valid, _, msg = validate_target_url_security("http://127.0.0.1:3000")
    assert valid is False

    valid, _, msg = validate_target_url_security("http://169.254.169.254/latest/meta-data/")
    assert valid is False

    valid, _, msg = validate_target_url_security("http://metadata.google.internal")
    assert valid is False

    # Valid external domains should pass
    valid, norm, msg = validate_target_url_security("example.com")
    assert valid is True
    assert norm == "https://example.com"
