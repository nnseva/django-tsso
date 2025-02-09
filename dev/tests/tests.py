from __future__ import absolute_import, print_function

import json

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings


class ModuleTest(TestCase):
    def setUp(self):
        self.u1 = User.objects.create(username='u1', email='u1@fake.me', is_staff=True)
        self.u2 = User.objects.create(username='u2', email='u2@fake.me', is_staff=True)

    def tearDown(self):
        pass

    @override_settings(
        MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'tsso.middleware.TSSOMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
        ]
    )
    def test_drf_sso_auth(self):
        """Test API authentication using Django SSO Middleware"""
        c = Client()
        response = c.get('/api/drf/users/')
        self.assertEqual(response.status_code, 401, response.content)
        response = c.get(
            '/api/drf/users/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u3|email:u3@fake.me',
        )
        self.assertEqual(response.status_code, 401, response.content)
        response = c.get(
            '/api/drf/users/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u1|email:u1@fake.me',
        )
        self.assertEqual(response.status_code, 200, response.content)
        response = c.get(
            '/api/drf/users/me/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u1|email:u1@fake.me',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)['username'], 'u1')

        response = c.get(
            '/api/drf/users/me/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u2|email:u2@fake.me',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)['username'], 'u2')

    @override_settings(
        MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
        ],
    )
    def test_drf_sso_auth_only(self):
        """Test API authentication only with DRF SSO authenticator"""
        c = Client()
        response = c.get('/api/drf/users/')
        self.assertEqual(response.status_code, 401, response.content)
        response = c.get(
            '/api/drf/users/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u3|email:u3@fake.me',
        )
        self.assertEqual(response.status_code, 401, response.content)
        response = c.get(
            '/api/drf/users/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u1|email:u1@fake.me',
        )
        self.assertEqual(response.status_code, 200, response.content)
        response = c.get(
            '/api/drf/users/me/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u1|email:u1@fake.me',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)['username'], 'u1')

        response = c.get(
            '/api/drf/users/me/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u2|email:u2@fake.me',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)['username'], 'u2')

    @override_settings(
        MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'tsso.middleware.TSSOMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
        ],
    )
    def test_django_sso_auth(self):
        """Test Django authentication using Django SSO Middleware"""
        c = Client()
        response = c.get('/api/drf/users/')
        self.assertEqual(response.status_code, 401, response.content)
        response = c.get(
            '/admin/',
        )
        self.assertEqual(response.status_code, 302, response.content)
        response = c.get(
            '/sso/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u3|email:u3@fake.me',
        )
        self.assertEqual(response.status_code, 401, response.content)
        response = c.get(
            '/sso/?next=/api/drf/',
            HTTP_AUTHORIZATION='SSO fake:bearer:username:u1|email:u1@fake.me',
        )
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(response['location'], '/api/drf/')
        response = c.get(
            '/api/drf/users/',
        )
        self.assertEqual(response.status_code, 200, response.content)
        response = c.get(
            '/api/drf/users/me/',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)['username'], 'u1')
        response = c.get(
            '/admin/',
        )
        self.assertEqual(response.status_code, 200, response.content)

        c = Client()
        response = c.get(
            '/sso/?SSO=fake:bearer:username:u3|email:u3@fake.me',
        )
        self.assertEqual(response.status_code, 401, response.content)
        response = c.get(
            '/sso/?next=/api/drf/&SSO=fake:bearer:username:u1|email:u1@fake.me',
        )
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(response['location'], '/api/drf/')
        response = c.get(
            '/api/drf/users/',
        )
        self.assertEqual(response.status_code, 200, response.content)
        response = c.get(
            '/api/drf/users/me/',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)['username'], 'u1')
        response = c.get(
            '/admin/',
        )
        self.assertEqual(response.status_code, 200, response.content)

        c = Client()
        response = c.post(
            '/sso/',
            content_type='application/x-www-form-urlencoded',
            data='SSO=fake:bearer:username:u3|email:u3@fake.me',
        )
        self.assertEqual(response.status_code, 401, response.content)
        response = c.post(
            '/sso/?next=/api/drf/',
            content_type='application/x-www-form-urlencoded',
            data='SSO=fake:bearer:username:u1|email:u1@fake.me',
        )
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(response['location'], '/api/drf/')
        response = c.get(
            '/api/drf/users/',
        )
        self.assertEqual(response.status_code, 200, response.content)
        response = c.get(
            '/api/drf/users/me/',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)['username'], 'u1')
        response = c.get(
            '/admin/',
        )
        self.assertEqual(response.status_code, 200, response.content)
