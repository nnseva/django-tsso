"""
The application implements SSO-like protocol
basing on the OAuth2 client implemented in the
python-social-auth
"""
from .version import __version__  # noqa: F401

# Patching the social_core package
from .social_core_get_backend_patch import patch


patch()
del patch
