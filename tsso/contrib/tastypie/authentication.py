from django.core import exceptions as dex
from tastypie.authentication import Authentication

from tsso.mixins import TSSOAuthenticationMixin


class TSSOAuthentication(TSSOAuthenticationMixin, Authentication):
    """Implementing Tastypie-specific"""

    def is_authenticated(self, request, **kwargs):
        """Overriden to implement authentication"""
        try:
            triple = self._authenticate(request)
            if triple:
                request.user, request.sso, request.backend = triple
                return True
        except dex.PermissionDenied:
            return False
        return False
