"""
Model serializers
"""

from django.contrib.auth import get_user_model
from rest_framework import serializers


UserModel = get_user_model()


class User(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        exclude = ['groups', 'user_permissions', 'password']
