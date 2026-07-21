"""Static HTML analysis."""

import binascii
import hashlib
import ipaddress
import os
import re
from collections import defaultdict
from collections.abc import Iterable
from enum import Enum

import bs4
import pywhatwgurl
from assemblyline.common.net import find_top_level_domains
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import ResultTextSection, ResultSection
from urllib.parse import unquote_to_bytes, unquote


DEFAULT_SCHEME = "https:"
MIMETYPE_TO_EXT = {"image/png": ".png", "image/gif": ".gif"}

TOP_LEVEL_DOMAINS = find_top_level_domains()


class HostType(Enum):
    OTHER = 0
    IPV4 = 1
    DOMAIN = 2
    IPV6 = 3


def tag_urls(urls: Iterable[str], logger=None) -> dict[str, list[str]]:
    tags = defaultdict(set)
    for url in urls:
        if url.startswith("//"):
            # Assume a default scheme for relative urls with authority
            url = DEFAULT_SCHEME + url
        try:
            url = pywhatwgurl.URL(url)
        except ValueError as e:
            if logger and not url.strip().startswith("#"):
                logger.warning(e)
            continue
        hostname = url.hostname
        if url.protocol == "mailto:":
            # This can produce unicode placeholder characters, but so does outlook with invalid utf-8
            email = unquote(url.pathname).strip()
            if not email:
                continue
            if "@" in email:
                tags["network.email.address"].add(email)
                tags["network.static.domain"].add(email.rsplit("@", 1)[-1])
            else:
                tags["file.string.extracted"].add(email)

        elif hostname:
            if hostname.startswith("["):
                try:
                    ip_address = ipaddress.IPv6Address(hostname[1:-1])
                    tags["network.static.ip"].add(ip_address.compressed)
                    host_type = HostType.IPV6
                except ValueError as e:
                    if logger:
                        logger.warning(e)
                    host_type = HostType.OTHER
            else:
                try:
                    ip_address = ipaddress.IPv4Address(hostname)
                    tags["network.static.ip"].add(ip_address.compressed)
                    host_type = HostType.IPV4
                except ValueError:
                    if _is_valid_domain(hostname):
                        # Make sure there's a TLD
                        tags["network.static.domain"].add(hostname)
                        host_type = HostType.DOMAIN
                    else:
                        host_type = HostType.OTHER
                        # Not a domain, but probably an interesting keyword
                        tags["file.string.extracted"].add(hostname)
            tags["network.static.uri" if host_type != HostType.OTHER else "file.string.extracted"].add(str(url))
            if url.port:
                tags["network.port"].add(url.port)
            if url.pathname and url.pathname != "/":
                tags["network.static.uri_path"].add(url.pathname)
    return {label: sorted(values) for label, values in tags.items()}


def decode_data_url(url: pywhatwgurl.URL) -> tuple[str, bytes]:
    if url.protocol != "data:":
        raise ValueError("URL is not a data url")
    if "," not in url.pathname:
        raise ValueError("Invalid data URL: Missing comma")
    media_types, data = url.pathname.split(",", 1)
    media_types = media_types.split(";")
    data = unquote_to_bytes(data)
    if media_types[-1] == "base64":
        try:
            data = binascii.a2b_base64(data)
        except binascii.Error as e:
            raise RuntimeError("base64 data url failed to decode") from e
    return media_types[0], data


def check_html_entities(data: bytes) -> ResultSection | None:
    alphanumeric_html_entities = False
    for hex, number in re.findall(b"(?i)&#(x)?([0-9a-f]{1,7});", data):
        try:
            number = int(number, 16 if hex else 10)
        except ValueError:
            continue
        if number < 48 or number > 122 or (number > 57 and number < 65) or (number > 90 and number < 97):
            continue
        alphanumeric_html_entities = True
        break
    if alphanumeric_html_entities:
        return ResultSection("Unnecessary HTML entities")
    return None


class HTML(ServiceBase):
    """Assemblyline service for static HTML analysis."""

    def extract_data_urls(self, urls: list[str], request: ServiceRequest) -> None:
        for url in urls:
            try:
                url = pywhatwgurl.URL(url)
            except ValueError:
                continue
            if url.protocol != "data:":
                continue
            try:
                media_type, data = decode_data_url(url)
            except (ValueError, RuntimeError) as e:
                self.log.error(e)
                continue
            if not data:
                continue
            file_name = hashlib.sha256(data).hexdigest() + MIMETYPE_TO_EXT.get(media_type, "")
            file_path = os.path.join(self.working_directory, file_name)
            with open(file_path, "wb") as f:
                f.write(data)
            request.add_extracted(file_path, file_name, f"{media_type} data url")

    def execute(self, request: ServiceRequest) -> None:
        """Run the service."""
        file_contents = request.file_contents

        # Check for unnecessary HTML entities in the raw file
        if html_entity_res := check_html_entities(file_contents):
            request.result.add_section(html_entity_res)

        soup = bs4.BeautifulSoup(file_contents, features="lxml")

        form_actions = [form.get("action", "") for form in soup.find_all("form", action=True)]
        if form_actions:
            request.result.add_section(
                ResultTextSection(
                    "Form action URLs",
                    body="\n".join(form_actions),
                    tags=tag_urls(form_actions, self.log),
                )
            )
        hrefs = sorted({tag.get("href", "") for tag in soup.find_all(href=True)}.difference({"", "#", "/"}))
        if hrefs:
            request.result.add_section(
                ResultTextSection(
                    "href attributes",
                    body="\n".join(href for href in hrefs if not href.strip().lower().startswith("data:")),
                    tags=tag_urls(hrefs, self.log),
                )
            )
        srcs = [tag.get("src", "") for tag in soup.find_all(src=True)]
        if srcs:
            request.result.add_section(
                ResultTextSection(
                    "src attributes",
                    body="\n".join(src for src in srcs if not src.strip().lower().startswith("data:")),
                    tags=tag_urls(srcs, self.log),
                )
            )
        css_urls = []
        styles = soup.find_all("style")
        for style in styles:
            string = style.string
            if not string:
                continue
            urls = re.findall(r'url\("([^"]*)"\)', string)
            for url in urls:
                css_urls.append(url)
        if css_urls:
            request.result.add_section(
                ResultTextSection(
                    "URLs in CSS",
                    body="\n".join(css_url for css_url in css_urls if not css_url.strip().lower().startswith("data:")),
                    tags=tag_urls(css_urls, self.log),
                )
            )

        self.extract_data_urls(srcs + css_urls + hrefs, request)


def _is_valid_domain(domain: str) -> bool:
    segments = domain.split(".")
    return (
        len(segments) >= 2
        and segments[-1].upper() in TOP_LEVEL_DOMAINS
        and not any(segment.startswith("-") or segment.endswith("-") for segment in segments)
    )
