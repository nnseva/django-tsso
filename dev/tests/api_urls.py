"""
URLs
"""

from django.urls import include, path
from rest_framework import routers

from . import api_views


router = routers.DefaultRouter()
router.register(r'users', api_views.User)

urlpatterns = [
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework'))
]
