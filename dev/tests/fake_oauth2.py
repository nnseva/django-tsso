"""
the module defines a fake OAuth2 backend which just returns the user info
from the faked structured token like:

username:<username>|first_name:<first_name>|last_name:<last_name>...
"""

from social_core.backends.oauth import BaseOAuth2


class FakeOAuth2(BaseOAuth2):
    """
    Fake restricted functioning OAuth2 backend
    """
    name = 'fake'

    AUTHORIZATION_URL = '/fake/authorize'
    ACCESS_TOKEN_URL = '/fake/access_token'
    USER_URL = '/fake/user'
    ACCESS_TOKEN_METHOD = 'POST'
    SCOPE_SEPARATOR = ','
    EXTRA_DATA = [
        ('refresh_token', 'refresh_token'),
        ('expires_in', 'expires'),
        ('username', 'username'),
        ('user', 'user'),
        ('username', 'user'),
        ('user', 'username'),
        ('email', 'email'),
    ]
    USE_BASIC_AUTH = False
    STATE_PARAMETER = False
    REDIRECT_STATE = False

    def __init__(self, *av, **kw):
        super().__init__(*av, **kw)

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        # split fake token and return values directly back
        ret = dict(pair.split(':') for pair in access_token.split('|'))
        return ret

    def get_user_id(self, details, response):
        return details.get('username', response.get('username'))

    def get_user_details(self, response):
        return response
