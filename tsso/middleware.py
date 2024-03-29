from django.middleware.csrf import CsrfViewMiddleware
from django.utils.deprecation import MiddlewareMixin

from . import mixins


class CSRFCheck(CsrfViewMiddleware):
    def _reject(self, request, reason):
        # Return the failure reason instead of an HttpResponse
        return reason


class TSSOMiddleware(mixins.TSSOAuthenticationMixin, MiddlewareMixin):
    """Django authentication middleware implementing TSSO"""

    def process_request(self, request):
        user = getattr(request, 'user', None)
        if user and not user.is_anonymous:
            return
        pair = self._authenticate(request)
        if not pair:
            return
        user, auth = pair
        if user:
            request.user = user
            request.auth = auth
            # Ignore CSRF for TSSO authorized requests
            request.csrf_processing_done = True
