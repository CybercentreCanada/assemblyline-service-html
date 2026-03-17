"""Static HTML analysis."""

import bs4
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import ResultSection


class HTML(ServiceBase):
    """Assemblyline service for static HTML analysis."""

    def execute(self, request: ServiceRequest):
        """Run the service."""
        soup = bs4.BeautifulSoup(request.file_contents, features="lxml")
        hrefs = soup.find_all(href=True)
        if hrefs:
            request.result.add_section(ResultSection("href attributes", [href.get("href", "") for href in hrefs]))
        srcs = soup.find_all(src=True)
        if srcs:
            request.result.add_section(ResultSection("src attributes", [src.get("src", "") for src in srcs]))
