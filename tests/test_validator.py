from scanner.core.target_validator import is_same_domain, validate_target


def test_rejects_localhost_hostname():
    result = validate_target("http://localhost:8000")
    assert not result.is_valid


def test_rejects_loopback_ip():
    result = validate_target("http://127.0.0.1")
    assert not result.is_valid


def test_rejects_private_ip_ranges():
    for ip in ["http://10.0.0.1", "http://192.168.1.1", "http://172.16.0.1"]:
        result = validate_target(ip)
        assert not result.is_valid, f"{ip} should be blocked"


def test_rejects_cloud_metadata_endpoint():
    result = validate_target("http://169.254.169.254/latest/meta-data/")
    assert not result.is_valid


def test_rejects_non_http_scheme():
    result = validate_target("ftp://example.com")
    assert not result.is_valid


def test_rejects_blocked_ports():
    result = validate_target("http://example.com:3306")
    assert not result.is_valid


def test_accepts_valid_public_url():
    result = validate_target("https://example.com")
    assert result.is_valid
    assert result.normalized_url == "https://example.com"


def test_same_domain_check():
    assert is_same_domain("https://example.com/a", "https://example.com/b")
    assert not is_same_domain("https://example.com", "https://evil.com")
