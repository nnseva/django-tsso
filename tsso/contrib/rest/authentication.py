"""
Provides various authentication policies.
"""

from django.core import exceptions as dex
from rest_framework import exceptions as rex
from rest_framework.authentication import BaseAuthentication

from tsso.mixins import TSSOAuthenticationMixin


class TSSOAuthentication(TSSOAuthenticationMixin, BaseAuthentication):
    """Implementing REST-specific"""

    def authenticate(self, request):
        """Override to make job"""
        try:
            return self._authenticate(request)
        except dex.PermissionDenied as ex:
            raise rex.AuthenticationFailed(*ex.args)

    def authenticate_header(self, request):
        """Override to make job"""
        return self._authenticate_header(request)
