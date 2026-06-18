from src.core.http_extractor import HTTPExtractor


def test_extract_host_from_http_payload():
    payload = b"GET / HTTP/1.1\r\nHost: www.facebook.com\r\nUser-Agent: test\r\n\r\n"

    assert HTTPExtractor.extract_host(payload) == "www.facebook.com"


def test_extract_host_ignores_non_http_payload():
    assert HTTPExtractor.extract_host(b"not an HTTP request") is None
