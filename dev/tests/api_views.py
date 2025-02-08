from django.contrib.auth import get_user_model
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from rest_framework import permissions

from . import serializers


UserModel = get_user_model()


class User(viewsets.ModelViewSet):
    http_method_names = ['get', 'options', 'patch', 'post', 'delete']
    queryset = UserModel.objects.all()
    serializer_class = serializers.User
    permission_classes = [permissions.DjangoModelPermissions]

    def get_queryset(self):
        """Override to filter only owner if not superuser"""
        if not self.request.user.is_superuser:
            return self.queryset.filter(pk=self.request.user.pk)
        return self.queryset

    @action(detail=False, methods=['options', 'get'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        """
        Get the current user using GET /api/users/me
        """
        if self.request.method == 'OPTIONS':
            return Response({})
        self.lookup_field = 'pk'
        self.kwargs = {'pk': request.user.pk}
        return self.retrieve(request)
