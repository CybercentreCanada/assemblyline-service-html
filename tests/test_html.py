"""HTML service unit tests."""

import pytest

import html_.html_


@pytest.mark.parametrize(
    ("uris", "tags"),
    [
        ([], {}),
        (
            ["https://example.com", "https://example.com/path"],
            {
                "network.protocol": ["https"],
                "network.static.uri": [
                    "https://example.com/",
                    "https://example.com/path",
                ],
                "network.static.domain": ["example.com"],
                "network.static.uri_path": ["/path"],
            },
        ),
        (
            ["mailto:username@example.com"],
            {
                "network.email.address": ["username@example.com"],
                "network.static.domain": ["example.com"],
            },
        ),
        (
            ["file://example.com/path-to/file"],
            {
                "network.protocol": ["file"],
                "network.static.domain": ["example.com"],
                "network.static.uri": ["file://example.com/path-to/file"],
                "network.static.uri_path": ["/path-to/file"],
            },
        ),
        (
            ["http://@example.com/"],
            {
                "network.protocol": ["http"],
                "network.static.domain": ["example.com"],
                "network.static.uri": ["http://example.com/"],
            },
        ),
        (
            ["   https://example.com   "],
            {
                "network.protocol": ["https"],
                "network.static.domain": ["example.com"],
                "network.static.uri": ["https://example.com/"],
            },
        ),
        # https://url.spec.whatwg.org/#url-parsing
        (
            ["https://exa\n\tmple.com"],
            {
                "network.protocol": ["https"],
                "network.static.domain": ["example.com"],
                "network.static.uri": ["https://example.com/"],
            },
        ),
        (
            ["whatsapp://send?text=test"],
            {
                "network.protocol": ["whatsapp"],
                "network.static.uri": ["whatsapp://send?text=test"],
                "file.string.extracted": ["send"],
            },
        ),
    ],
)
def test_tag_uris(uris: list[str], tags: dict[str, list[str]]) -> None:
    assert html_.html_.tag_urls(uris) == tags


@pytest.mark.parametrize(
    ("data", "section"),
    [
        (b"", False),
        (b"P&#97;&#115;&#115;&#119;&#111;&#114;d", True),
        (b"&#47;&#x2F;&#58;&#x3A;&#64;&#x40;&#91;&#x5B;&#96;&#x60;&#123;&#x7B;", False),
    ],
)
def test_check_html_entities(data: bytes, section: bool) -> None:
    assert bool(html_.html_.check_html_entities(data)) == section
