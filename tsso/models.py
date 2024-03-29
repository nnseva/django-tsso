"""
Models
"""

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class SSOToken(models.Model):
    """
    SSOToken is a token provided by the client to log in using foreign OAuth2 server.

    When the client provides a token to log in, the application checks it's presence
    in the database and its TTL and other parameters.
    """
    backend = models.CharField(
        max_length=80,
        verbose_name=_('Backend'), help_text=_('The backend id for the token')
    )
    token = models.CharField(
        max_length=255,
        verbose_name=_('Token'), help_text=_('The backend-specific token')
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sso_tokens',
        verbose_name=_('User'), help_text=_('User to whom the token belongs')
    )
    ctime = models.DateTimeField(
        auto_now_add=True, db_index=True,
        editable=False,
        verbose_name=_('Created'), help_text=_('When the instance has been created')
    )
    mtime = models.DateTimeField(
        auto_now=True, db_index=True,
        editable=False,
        verbose_name=_('Modified'), help_text=_('When the instance has been modified')
    )
    etime = models.DateTimeField(
        null=True,
        db_index=True,
        editable=False,
        verbose_name=_('Expired'), help_text=_('When the instance should be expired, or has been expired')
    )

    def is_expired(self):
        return self.etime and self.etime < timezone.now()
    is_expired.short_description = _('Is Expired')

    is_expired = property(is_expired)

    def __str__(self):
        """String representation"""
        return '%s @ %s [%s]' % (self.user, self.backend, '%s...%s' % (self.token[:3], self.token[-3:]))

    class Meta:
        verbose_name = _('SSO Token')
        verbose_name_plural = _('SSO Tokens')
        unique_together = (
            ('backend', 'token'),
        )
