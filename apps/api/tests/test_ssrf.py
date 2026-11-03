
import pytest

from app.core.security import (
    is_ip_blocked,
    validate_target_url_security,
)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "127.0.1.5",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "fe80::1",
    ],
)
def test_blocked_ip_ranges(ip):
    assert is_ip_blocked(ip) is True


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
    ],
)
def test_public_ip_addresses_are_allowed(ip):
    assert is_ip_blocked(ip) is False


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com",
        "javascript:alert(1)",
        "data:text/html,test",
    ],
)
def test_dangerous_schemes_are_rejected(url):
    valid, _, message = validate_target_url_security(url)

    assert valid is False
    assert message


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal",
        "http://192.168.1.1",
        "http://10.0.0.1",
    ],
)
def test_local_and_metadata_targets_are_rejected(url):
    valid, _, _ = validate_target_url_security(url)

    assert valid is False


@pytest.mark.parametrize(
    "url",
    [
        "http://999.999.999.999",
        "http://127.0.0.1",
    ],
)
def test_invalid_or_private_ipv4_targets_are_rejected(url):
    valid, _, _ = validate_target_url_security(url)

    assert valid is False


def test_valid_external_domain_is_normalized():
    valid, normalized, message = validate_target_url_security("example.com")

    assert valid is True
    assert normalized == "https://example.com"


def test_public_https_target_is_allowed():
    valid, normalized, _ = validate_target_url_security(
        "https://example.com"
    )

    assert valid is True
    assert normalized == "https://example.com"


def test_unsupported_port_is_rejected():
    valid, _, _ = validate_target_url_security(
        "https://example.com:9999"
    )

    assert valid is False
