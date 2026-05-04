"""Static HTML analysis."""

import binascii
import hashlib
import ipaddress
import os
import re
import urllib
from collections import defaultdict

import bs4
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import ResultSection


MIMETYPE_TO_EXT = {"image/png": ".png"}


def tag_uris(uris: list[str]) -> dict[str, list[str]]:
    tags = defaultdict(set)
    for uri in uris:
        uri = uri.strip()
        split = urllib.parse.urlsplit(uri)
        if split.scheme == "mailto":
            email = split.path
            tags["network.email.address"].add(email)
            tags["network.static.domain"].add(email.rsplit("@", 1)[-1])
        elif split.scheme and split.netloc:
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
            if split.path and split.path.startswith("/") and split.path != "/":
                tags["network.static.uri_path"].add(split.path)
    return {label: sorted(values) for label, values in tags.items()}


class HTML(ServiceBase):
    """Assemblyline service for static HTML analysis."""

    def extract_data_uris(self, uris: list[str], request: ServiceRequest):
        for uri in uris:
            split = urllib.parse.urlsplit(uri)
            if split.scheme != "data" or not split.path:
                continue
            media_types, data = split.path.split(",", 1)
            media_types = media_types.split(";")
            if media_types[-1] == "base64":
                try:
                    data = binascii.a2b_base64(data)
                except binascii.Error:
                    self.log.warning(f"base64 data url failed to decode in {request.sha256}")
            file_name = hashlib.sha256(data).hexdigest() + MIMETYPE_TO_EXT.get(media_types[0], "")
            file_path = os.path.join(self.working_directory, file_name)
            with open(file_path, "wb") as f:
                f.write(data)
            request.add_extracted(file_path, file_name, f"{media_types[0]} data url")

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

        self.extract_data_uris(srcs + css_urls + hrefs, request)
