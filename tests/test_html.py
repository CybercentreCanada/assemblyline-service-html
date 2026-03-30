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
                    "https://example.com",
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
    ],
)
def test_tag_uris(uris: list[str], tags: dict[str, list[str]]) -> None:
    assert html_.html_.tag_uris(uris) == tags
