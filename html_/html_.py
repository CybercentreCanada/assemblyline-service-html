"""Static HTML analysis."""

import binascii
import hashlib
import ipaddress
import os
import re
from collections import defaultdict

import bs4
import pywhatwgurl
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import ResultTextSection

MIMETYPE_TO_EXT = {"image/png": ".png"}


def tag_urls(urls: list[str], logger=None) -> dict[str, list[str]]:
    tags = defaultdict(set)
    for url in urls:
        try:
            url = pywhatwgurl.URL(url)
        except ValueError as e:
            if logger and not url.strip().startswith("#"):
                logger.warning(e)
            continue
        if url.protocol == "mailto:":
            email = url.pathname
            tags["network.email.address"].add(email)
            tags["network.static.domain"].add(email.rsplit("@", 1)[-1])
        elif url.hostname:
            tags["network.static.uri"].add(str(url))
            tags["network.protocol"].add(url.protocol.strip(":"))
            try:
                ip_address = ipaddress.ip_address(url.hostname)
                tags["network.static.ip"].add(ip_address.compressed)
            except ValueError:
                tags["network.static.domain"].add(url.hostname)
            if url.port:
                tags["network.port"].add(url.port)
            if url.pathname and url.pathname != "/":
                tags["network.static.uri_path"].add(url.pathname)
    return {label: sorted(values) for label, values in tags.items()}


class HTML(ServiceBase):
    """Assemblyline service for static HTML analysis."""

    def extract_data_urls(self, urls: list[str], request: ServiceRequest):
        for url in urls:
            try:
                url = pywhatwgurl.URL(url)
            except ValueError as e:
                # ignore fragments
                if not url.strip().startswith("#"):
                    self.log.warning(e)
                continue
            if url.protocol != "data:" or not url.pathname:
                continue
            media_types, data = url.pathname.split(",", 1)
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
            request.result.add_section(
                ResultTextSection(
                    "Form action URLs",
                    "\n".join(form_actions),
                    tags=tag_urls(form_actions, self.log),
                )
            )
        hrefs = [tag.get("href", "") for tag in soup.find_all(href=True)]
        if hrefs:
            request.result.add_section(
                ResultTextSection("href attributes", "\n".join(hrefs), tags=tag_urls(hrefs, self.log))
            )
        srcs = [tag.get("src", "") for tag in soup.find_all(src=True)]
        if srcs:
            request.result.add_section(
                ResultTextSection("src attributes", "\n".join(srcs), tags=tag_urls(srcs, self.log))
            )
        css_urls = []
        styles = soup.find_all("style")
        for style in styles:
            urls = re.findall(r'url\("([^"]*)"\)', style.string)
            for url in urls:
                css_urls.append(url)
        if css_urls:
            request.result.add_section(
                ResultTextSection(
                    "URLs in CSS",
                    "\n".join(css_urls),
                    tags=tag_urls(css_urls, self.log),
                )
            )

        self.extract_data_urls(srcs + css_urls + hrefs, request)
