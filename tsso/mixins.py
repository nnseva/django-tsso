"""
Mixins providing TSSO Authorization
"""

import logging

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.core import exceptions
from social_django.utils import load_strategy

from .models import SSOToken


logger = logging.getLogger(__name__)

# Header encoding (see RFC5987), C&P from the REST framework
HTTP_HEADER_ENCODING = 'iso-8859-1'


def _get_authorization_header(request):
    """
    Return request's 'Authorization:' header, as a bytestring.

    Hide some test client ickyness where the header can be unicode.
    """
    # C&P from the REST framework
    auth = request.META.get('HTTP_AUTHORIZATION', b'')
    if isinstance(auth, str):
        # Work around django test client oddness
        auth = auth.encode(HTTP_HEADER_ENCODING)
    return auth


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

    keyword = getattr(settings, 'SSSO_KEYWORD', 'SSO')

    def _authenticate(self, request):
        """Authenticates a request"""
        auth = _get_authorization_header(request).decode(errors='replace').split(' ', 1)

        if not auth:
            return None

        if len(auth) < 2:
            return None

        scheme, token = auth
        if scheme.lower() != self._authenticate_header(request).lower():
            return None

        auth = token.split(getattr(settings, 'SSO_TOKEN_SEPARATOR', ':'), 2)
        if len(auth) < 3:
            return None

        backend, token_type, token = auth
        return self._authenticate_credentials(backend, token_type, token, request=request)

    def _authenticate_credentials(self, backend_name, token_type, token, request=None):
        """Authenticates the request using extracted credentials"""

        model = self._get_model(request)
        sso = model.objects.select_related('user').filter(backend=backend_name, token=token).first()

        if sso and not sso.is_expired:
            if not sso.user.is_active:
                raise exceptions.PermissionDenied(_('User inactive or deleted.'))
            return (sso.user, sso)

        strategy = load_strategy()
        try:
            backend = strategy.get_backend(backend_name)
        except Exception as ex:
            raise exceptions.PermissionDenied(_('Wrong backend key %s: %s') % (backend_name, ex))
        try:
            user = backend.do_auth(token, token_type=token_type)
        except Exception as ex:
            raise exceptions.PermissionDenied(
                _('Token is not authorized: %s:%s:%s: %s') % (backend_name, token_type, token, ex)
            )

        if not user:
            raise exceptions.PermissionDenied(
                _('Token does not identify user: %s:%s:%s') % (backend_name, token_type, token)
            )

        if not user.is_active:
            raise exceptions.PermissionDenied(_('User inactive or deleted.'))

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
        return (sso.user, sso)

    def _authenticate_header(self, request):
        """Returns the authentication-specific header"""
        return self.keyword

    def _get_model(self, request):
        """Returns the model to store SSO tokens locally"""
        return SSOToken
