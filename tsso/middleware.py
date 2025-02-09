import logging

from django.core import exceptions
from django.utils.deprecation import MiddlewareMixin

from . import mixins


logger = logging.getLogger(__name__)


class TSSOMiddleware(mixins.TSSOAuthenticationMixin, MiddlewareMixin):
    """Django authentication middleware implementing TSSO"""

    def process_request(self, request):
        user = getattr(request, 'user', None)
        if user and not user.is_anonymous:
            return
        try:
            triple = self._authenticate(request)
        except exceptions.PermissionDenied as ex:
            logger.warning('TSSO authorization failed: %s', ex)
            return
        if not triple:
            return
        user, sso, backend = triple
        if user:
            logger.debug('TSSO authorization successful: %s, %s', user, backend)
            request.user = user
            request.sso = sso
            request.backend = backend
            # Ignore CSRF for TSSO authorized requests
            request.csrf_processing_done = True
