"""Tastypie resources"""
from django.contrib.auth import get_user_model
from tastypie.resources import ModelResource
from tastypie.api import Api
from tastypie.authentication import (
    BasicAuthentication,
    MultiAuthentication,
    SessionAuthentication,
)
from tsso.contrib.tastypie.authentication import TSSOAuthentication


User = get_user_model()


class SimpleAuthentication(SessionAuthentication):
    """Avoid csrf check while Django session authentification"""

    def is_authenticated(self, request, **kwargs):
        """Overriden to avoid csrf check"""
        return request.user.is_authenticated


class UserResource(ModelResource):
    class Meta:
        queryset = User.objects.all()
        authentication = MultiAuthentication(
            SimpleAuthentication(),
            BasicAuthentication(),
            TSSOAuthentication(),
        )

    def get_object_list(self, request):
        """Override to filter only owner if not superuser"""
        if not request.user.is_superuser:
            return super().get_object_list(request).filter(pk=request.user.pk)
        return super().get_object_list(request)


api = Api(api_name='tastypie')
api.register(UserResource())
