"""
Admin interface
"""
from admin_auto_filters.filters import AutocompleteFilterFactory
from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import SSOToken


@admin.register(SSOToken)
class SSOTokenAdmin(admin.ModelAdmin):
    """
    Admin interface
    """
    list_display = ('id', 'backend', 'user', 'ctime',  'mtime', 'etime')
    search_fields = ('backend', 'token',)
    list_filter = (
        AutocompleteFilterFactory(_('User'), 'user'),
    )
    autocomplete_fields = ('user',)

    def has_add_permission(self, request):
        """Restrict add function"""
        return False

    def has_change_permission(self, request, obj=None):
        """Restrict change function"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Restrict delete function only for the superuser"""
        return request.user.is_superuser
