from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import resolve_url
from django.views.decorators.cache import never_cache


@never_cache
def sso_login(request):
    """SSO simple login"""

    # The view assumes SSOAuthenticationMiddleware works and already recognized the user
    # So the view just authorizes this user for future use
    if request.user.is_authenticated:
        sso = getattr(request, 'sso', None)
        backend = getattr(request, 'backend', None)
        if sso and backend:
            backend_type = type(backend)
            backend_full_name = '%s.%s' % (backend_type.__module__, backend_type.__name__)
            auth_login(request, request.user, backend=backend_full_name)
        redirect_to = request.GET.get(
            REDIRECT_FIELD_NAME,
            resolve_url(settings.LOGIN_REDIRECT_URL) or '/'
        )
        return HttpResponseRedirect(redirect_to)
    response = HttpResponse(status=401)
    response['WWW-Authenticate'] = 'SSO'
    return response
