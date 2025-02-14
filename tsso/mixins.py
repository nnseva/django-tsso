"""
Mixins providing TSSO Authorization
"""

import logging

from django.conf import settings
from django.core import exceptions
from django.utils import timezone
from social_django.utils import load_strategy

from .models import SSOToken


logger = logging.getLogger(__name__)

# Header encoding (see RFC5987), C&P from the REST framework
HTTP_HEADER_ENCODING = 'iso-8859-1'


class TSSOAuthenticationMixin:
    """
    Base Transparent SSO authentication mixin

    The client can authenticate itself by the token got from
    the known OAuth2 backend. It sends a token gor from the
    foreign system and identifies the system itself using
    request headers.

    The request headers should allow to identify the backend, and
    the token specifially for this backend.

    The Authentication header should look like:

    Authentication: SSO <backend-name>:Bearer:<backend-specific-token>
    """

    keyword = getattr(settings, 'TSSO_KEYWORD', 'SSO')

    def _authenticate(self, request):
        """Authenticates a request"""
        auth = self._get_sso_token(request)

        if not auth:
            return None

        auth = auth.split(getattr(settings, 'TSSO_TOKEN_SEPARATOR', ':'), 2)
        if len(auth) < 3:
            return None

        backend, token_type, token = auth
        return self._authenticate_credentials(backend, token_type, token, request=request)

    def _authenticate_credentials(self, backend_name, token_type, token, request=None):
        """Authenticates the request using extracted credentials"""

        strategy = load_strategy()
        try:
            backend = strategy.get_backend(backend_name)
        except Exception as ex:
            raise exceptions.PermissionDenied('Wrong backend key %s: %s' % (backend_name, ex))

        model = self._get_model(request)
        sso = model.objects.select_related('user').filter(backend=backend_name, token=token).first()

        if sso and not sso.is_expired:
            if not sso.user.is_active:
                raise exceptions.PermissionDenied('User inactive or deleted.')
            return (sso.user, sso, backend)

        try:
            user = backend.do_auth(token, token_type=token_type, request=request)
        except Exception as ex:
            raise exceptions.PermissionDenied(
                'Token is not authorized: %s:%s:%s: %s' % (backend_name, token_type, token, ex)
            )

        if not user:
            raise exceptions.PermissionDenied(
                'Token does not identify user: %s:%s:%s' % (backend_name, token_type, token)
            )

        if not user.is_active:
            raise exceptions.PermissionDenied('User inactive or deleted.')

        eperiod = getattr(settings, 'TSSO_EXPIRATION_PERIOD', 600)
        etime = timezone.now() + timezone.timedelta(seconds=eperiod)

        if sso:
            if sso.user != user:
                logger.warning('The user has been changed for the token since last check')
                sso.user = user
            sso.etime = etime
            sso.save(update_fields=['user', 'etime'])
        else:
            sso = model.objects.create(backend=backend_name, token=token, user=user, etime=etime)
        return (sso.user, sso, backend)

    def _authenticate_header(self, request):
        """Returns the authentication-specific header"""
        return self.keyword

    def _get_model(self, request):
        """Returns the model to store SSO tokens locally"""
        return SSOToken

    def _get_sso_token(self, request):
        """
        Extracts SSO token from 'Authorization: SSO' or GET/POST parameters.

        - settings.TSSO_FORBID_QUERY_AUTHENTICATION forbids authentication using HTTP query
        - settings.TSSO_FORBID_POST_AUTHENTICATION forbids authentication using HTTP POST query

        Using 'Authorization' header is always allowed
        """
        auth = request.META.get('HTTP_AUTHORIZATION', b'')
        if isinstance(auth, bytes):
            auth = auth.decode(HTTP_HEADER_ENCODING, errors='replace')

        auth = auth.split(' ', 1)
        if len(auth) < 2:
            auth = None
        else:
            scheme, token = auth
            if scheme.lower() != self._authenticate_header(request).lower():
                auth = None
            else:
                auth = token

        if not auth:
            if not getattr(settings, 'TSSO_FORBID_QUERY_AUTHENTICATION', None):
                auth = request.GET.get(self._authenticate_header(request), None)

        if not auth:
            if not getattr(settings, 'TSSO_FORBID_POST_AUTHENTICATION', None):
                if request.method.lower() == 'post':
                    content_type = request.content_type
                    if 'form' in content_type:
                        auth = request.POST.get(self._authenticate_header(request), None)

        return auth
