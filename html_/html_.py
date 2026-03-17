"""Static HTML analysis."""

from collections import defaultdict
import ipaddress
import re
import urllib

import bs4
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import ResultSection


def tag_uris(uris: list[str]) -> dict[str, list[str]]:
    tags = defaultdict(set)
    for uri in uris:
        split = urllib.parse.urlsplit(uri)
        if split.scheme and split.netloc:
            tags["network.static.uri"].add(uri)
            tags["network.protocol"].add(split.scheme)
            hostname = split.hostname
            if hostname:
                try:
                    ip_address = ipaddress.ip_address(hostname)
                    tags["network.static.ip"].add(ip_address.compressed)
                except ValueError:
                    tags["network.static.domain"].add(hostname)
            try:
                port = split.port
                if port is not None:
                    tags["network.port"].add(port)
            except ValueError:
                pass
            if split.path and split.path.startswith("/"):
                tags["network.static.uri_path"].add(split.path)
    return {label: list(values) for label, values in tags.items()}

class HTML(ServiceBase):
    """Assemblyline service for static HTML analysis."""

    def execute(self, request: ServiceRequest):
        """Run the service."""
        soup = bs4.BeautifulSoup(request.file_contents, features="lxml")

        form_actions = [form.get("action", "") for form in soup.find_all("form", action=True)]
        if form_actions:
            request.result.add_section(ResultSection("Form action URLs", form_actions, tags=tag_uris(form_actions)))
        hrefs = [tag.get("href", "") for tag in soup.find_all(href=True)]
        if hrefs:
            request.result.add_section(ResultSection("href attributes", hrefs, tags=tag_uris(hrefs)))
        srcs = [tag.get("src", "") for tag in soup.find_all(src=True)]
        if srcs:
            request.result.add_section(ResultSection("src attributes", srcs, tags=tag_uris(srcs)))
        css_urls = []
        styles = soup.find_all("style")
        for style in styles:
            urls = re.findall(r'url\("([^"]*)"\)', style.string)
            for url in urls:
                css_urls.append(url)
        if css_urls:
            request.result.add_section(ResultSection("URLs in CSS", css_urls, tags=tag_uris(css_urls)))
