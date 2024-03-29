from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class Config(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'tsso'

    verbose_name = _('Transparent SSO')
