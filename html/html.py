"""This Assemblyline service analyzes HTML documents."""

from assemblyline.common import forge
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result


class HTML(ServiceBase):
    """This Assemblyline service analyzes HTML documents."""

    def execute(self, request: ServiceRequest):
        """Run the service."""

        result = Result()
        request.result = result
