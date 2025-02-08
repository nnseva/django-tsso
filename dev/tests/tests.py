from __future__ import absolute_import, print_function

import json

from django.contrib.auth.models import User
from django.test import TestCase, Client


class ModuleTest(TestCase):
    def setUp(self):
        self.u1 = User.objects.create(username='u1', email='u1@fake.me')
        self.u2 = User.objects.create(username='u2', email='u2@fake.me')

    def tearDown(self):
        pass

    def test_drf_sso_auth(self):
        """Test API authentication using SSO"""
        c = Client()
        response = c.get('/api/users/')
        self.assertEqual(response.status_code, 401, response.content)
        response = c.get(
            '/api/users/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u3|email:u3@fake.me',
        )
        self.assertEqual(response.status_code, 401, response.content)
        response = c.get(
            '/api/users/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u1|email:u1@fake.me',
        )
        self.assertEqual(response.status_code, 200, response.content)
        response = c.get(
            '/api/users/me/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u1|email:u1@fake.me',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)['username'], 'u1')

        response = c.get(
            '/api/users/me/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u2|email:u2@fake.me',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)['username'], 'u2')
