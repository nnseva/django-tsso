[![Tests](https://github.com/nnseva/django-tsso/actions/workflows/test.yml/badge.svg)](https://github.com/nnseva/django-tsso/actions/workflows/test.yml)

# django-tsso

The django-tsso package provides a transparent and easy way to authenticate the external Client for
the Service Provider using common Authentication Server.

The package is installed on the Service Provider side.

## Installation

*Stable version* from the PyPi package repository
```bash
pip install django-tsso
```

*Last development version* from the GitHub source version control system
```bash
pip install git+git://github.com/nnseva/django-tsso.git
```

## Configuration

### Basic

Include the `tsso` applications into the `INSTALLED_APPS` list, like:

```python
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    ...
    'tsso',
    ...
]
```

Include one of the authentication middleware to the request processing pipeline.

If you prefer to have Transparent SSO authentication available on all URLs, it's probably better
to include the package authentication middleware to the common list of middleware,
near to the Django Authentication middleware:

```python
MIDDLEWARE = [
    ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    'tsso.middleware.TSSOMiddleware',
    ...
]
```

Switch necessary OAuth1/2 authorization backends on, using [Python Social Auth](https://github.com/python-social-auth)
library having enormously rich [set of provided backends](https://python-social-auth.readthedocs.io/en/latest/backends/index.html)
for different authentication servers.

```python
AUTHENTICATION_BACKENDS = (
    ...
    'social_core.backends.google.GoogleOAuth2',
    ...
)
```

You may skip setting the backend client key and secret values, if you won't plan to
activate your own Python Social Auth-provided login pipeline, and would like to have a Transparent SSO
authentication pipeline only.

The Transparent SSO login pipeline actually uses the
[Python Social Auth pipeline](https://python-social-auth.readthedocs.io/en/latest/pipeline.html)
to provide the authentication, so any customization of the Python Social Auth
pipeline will actually be applied to the Transparent SSO also.

### Django session SSO Login URL

Include the following code into your `urls.py` module:

```python
from tsso.views import sso_login
...
urlpatterns = [
    re_path('admin/', admin.site.urls),
    re_path('sso/', sso_login),
    ...
]
```

You can also provide any other prefix for your SSO Login URL.

Request `/sso/` URL providing SSO authorization as described in the [protocol](#sso-authentication-protocol)
and your browser will be signed in using Django session. The successful request
will redirect the browser to the `settings.LOGIN_REDIRECT_URL` by default, or
to the URL provided explicitly by the `next` GET query parameter of the request.

**NOTICE** that the [Django session SSO Login](#django-session-sso-login-url) works only if the
`TSSOMiddleware` is installed.

### API-provider-specific authentication backends

If you prefer to have SSO authentication only on the level of your API,
use the custom authentication middleware for the specific API provider, *instead*
of the common `TSSOMiddleware`.

Only URLs of the correspondent provider or resource will then use
SSO authentication protocol.

#### Django REST API

For the [Django REST API](https://www.django-rest-framework.org/) it may look like:

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'tsso.contrib.rest.authentication.TSSOAuthentication',
        ...
    ]
}
```

#### Tastypie

For the [Tastypie API](https://django-tastypie.readthedocs.io/en/latest/toc.html),
the authentication middleware may be provided for every Tasypie resource, like:

```python
from tsso.contrib.tastypie.authentication import TSSOAuthentication

...
class MyModelResource(ModelResource):
    ...
    class Meta:
        queryset = MyModel.objects.all()
        authentication = MultiAuthentication(
            TSSOAuthentication(),
            ...
        )
```

#### Custom authentication backend

If you use other API library, you should probably implement a specific
SSO authentication provider for this API. See `tsso/contrib` for
samples.

Pull requests for third-party API libraries with specific authentication
backends are appretiated.

#### Common TSSOMiddleware authentication vs. API-specific authentication

You don't actually need to use any API-specific authentication middleware,
if you use the common `TSSOMiddleware`. This sentence also relates to any other
API provider referring to the `request.user` attribute to authorize the request. The both
[Django REST API](https://www.django-rest-framework.org/) and
[Tastypie API](https://django-tastypie.readthedocs.io/en/latest/toc.html) do it
(after some basic tune).

### Other settings

- `settings.TSSO_FORBID_QUERY_AUTHENTICATION` - forbids SSO authentication using HTTP query parameter, `False` by default
- `settings.TSSO_FORBID_POST_AUTHENTICATION` - forbids SSO authentication using HTTP POST parameter, `False` by default
- `settings.TSSO_KEYWORD` - The protocol uses this string to identify itself in authorization header, query, or POST parameter. You may
  change this string to your own. The default value is `"SSO"`
- `settings.TSSO_TOKEN_SEPARATOR` - this character (substring) is used to separate parts of the SSO authorization from each other, `":"` by default
- `settings.TSSO_EXPIRATION_PERIOD` - this timeout (in seconds) determines how much time the validity of the SSO verification is not yet
  expired, `600` by default

## SSO Authentication protocol

### Three sides of the protocol

There are three sides of the authentication protocol.

- The Authentication Server provides a way to get a token and identify a current user by the token
- The Client requests a token from the Authentication server, and provides it to the Service Provider to authorize the current user
- The Service Provider agrees using the Authentication Server as an authentication and authorization server for the current user

The Authentication Server may be any token-based OAuth2 server, for which the correspondent backend is provided by the
Python Social Auth package, or third party using the Python Social Auth package to create its own backend.

The OAuth1 Authentication Servers, or any other providing the token and allowing to get the user info
may be also applicable, but it was not tested by the package's author yet. Please provide your own experience
with OAuth1, or other token-based authentication servers.

The Client shoud be able to interact with the selected Authentication Server, out of the scope of this protocol.
Finally, it should get an active access token and send it to the Service Provider to authorize the request.

The Service Provider is an application where this package should be used. It receives access token created
by the Authentication Server and sent to the Service Provider by the Client, and approves it requesting
the user info from the Authentication Server using the access token sent from the Client.

### Relation to the SSO RFC documents

***Important Note***: the protocol doesn't relate to any RFC descibing SSO, such as
[7642 System for Cross-domain Identity Management](https://www.rfc-editor.org/rfc/rfc7642),
[7521 Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7521),
[7522 Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7522) etc,

All of them require to have *changes and extensions* on the Authorization Server side,
while the following protocol is totally *transparent* for the Authorization Server.

That's a reason why the `Transparent` is a part of the package name.

The practical result is that you can use ***any*** existent OAuth1/2 authorization
server without any changes on their side.

Some of OAuth Authorization Servers provide additional, not yet standartized ways
to verify or introspect the provided token and get additional information about user's scope
on these servers. You can use these ways to restrict user's access to your
Service Provider server analyzing the additional user information. See also
[some proposals](https://www.rfc-editor.org/rfc/inline-errata/rfc7662.html) for the RFC.

###  Authorization steps

#### Getting an access token

The Client requests the access token from the authentication server using the OAuth-like protocol. The particular
way to do it is out of our scope. The only significant result, that the Client, at some moment, knows the
access token and token type, which is `Bearer` for the most OAuth2 cases.

#### Getting access to the Service Provider's resource

The client requests any Service Provider resource, using one of the following ways to send token:
- the `Authorization` header of the specific value structure
- the HTTP query string
- the HTTP POST form-based body

The Client provides the token to the Service Provider, using `authentication keyword` and `authentication value`.

The `authentication keyword` is determined by the `settings.TSSO_KEYWORD` string and is always the same for the
whole Service Provider instance, `"SSO"` by default.

The `authentication value` consists of three parts, separated by colon `:`, or another symbol determined by settings.

The first part is a name of the [Python Social Auth](https://python-social-auth.readthedocs.io/en/latest/backends/index.html) package
authorization backend on the Service Provider side. This name is determined by the `name` attribute of the backend. You
can see a sample of such backend (created for testing purposes) in `dev/tests/fake_oauth2.py`. Every such backend uses
unique name. Some samples of such a name are the following:

- `google-oauth2`
- `google-oauth`
- `google-openidconnect`
- `twitter`
- `twitter-oauth2`
- `github`
- etc...

The second part is an access token type, `Bearer` in most OAuth2 cases. It is passed as a token type
when the Service Provider requests the Authentication Server to get the user information.

The third part is an access token itself, which has just been received by the Client on the first step of the authentication protocol.

For example:
```
google-oauth2:Bearer:J24F65G2H4FK246F246F2K2F45F4GK5F24H6F2456H2F52KGF65HG6F
```

##### Using HTTP header

The `Authorization` header value consists of the `authentication keyword` and `authentication value` separated by a space character.

For example:

```
Authorization: SSO google-oauth2:Bearer:J24F65G2H4FK246F246F2K2F45F4GK5F24H6F2456H2F52KGF65HG6F
```

##### Using HTTP query string

The client provides the HTTP query string with the `authentication keyword` parameter, whose value is the `authentication value`.

For example:

```
http://example.com/resource-url/?SSO=google-oauth2:Bearer:J24F65G2H4FK246F246F2K2F45F4GK5F24H6F2456H2F52KGF65HG6F
```

The `TSSO_FORBID_QUERY_AUTHENTICATION=True` setting forbids this way of the authentication. It is allowed by default.


##### Using HTTP POST form-based body

The HTTP POST form-based body should contain the `authentication keyword` parameter, whose value is the `authentication value`.
The HTTP POST Content Type header should be one of used for the form output. Other formats are ignored.

For example:

```
Content-Type: application/x-www-form-urlencoded

SSO=google-oauth2:Bearer:J24F65G2H4FK246F246F2K2F45F4GK5F24H6F2456H2F52KGF65HG6F
```

The `TSSO_FORBID_POST_AUTHENTICATION` setting forbids this way of the authentication. It is allowed by default.

#### Verifying access token by the Service Provider

The Service Provider veryfies the token sending authorized request to the Authorization Server.

For this purpose, the TSSO asks the [Python Social Auth](https://python-social-auth.readthedocs.io/en/latest/backends/index.html) package
authorization backend to continue the pipeline. In case of the OAuth2, the package just requests User details
from the Authentication Server.

If the [Python Social Auth](https://python-social-auth.readthedocs.io/en/latest/backends/index.html) package pipeline
returns the correct user info, the TSSO thinks that the access to the Service Provider resource should be granted.

The TSSO caches the token check results to avoid unnecessary requests to the Authentication Server
every time when the resource is requested. The `TSSO_EXPIRATION_PERIOD` settings variable controls, how many
seconds the cached token is valid without additional check on the Authorization Server side. The `TSSO_EXPIRATION_PERIOD`
settings variable doesn't influence the user experience. It only controls, how much time the result of the last successfull
token verification will be cached.

## Controlling users in the Authentication Pipeline

You can control user creation and/or verification in the Authentication Pipeline, as it's described
in the [Python Social Auth](https://python-social-auth.readthedocs.io/en/latest/backends/index.html) documentation.

The behaviour which often is used as a default, allows automatic user creation. It means, that any external user who
goes successfully through the SSO authorization pipeline, will be authomatically created on the Service Provider side.

It may make some unexpected result in case of Transparent SSO solution.

Notice that your Service Provider doesn't know anything about the Client Application on the Authorization Server side.

It means, that if the Service Provider trusts the Authorization Server, **any** user getting proper token from this
Authorization Server will be authorized by the Service Provider using this token.

Therefore, if you use the Google server and restrict access to your Client Application by domain name (this restriction
is controlled by the Google on the stage of OAuth2 authorization), this restriction will not work for the Service Provider,
because originally, the only User request is used to verify the token (instead of the full Authorization pipeline of the OAuth2 protocol).
Any user, who is registered on the Google, may send his token and get access to the Service Provider data, if no additional checks
are provided.

Install your additional checks, for example the token introspection request, as described in the [draft](https://www.rfc-editor.org/rfc/inline-errata/rfc7662.html),
into the [Python Social Auth](https://python-social-auth.readthedocs.io/en/latest/backends/index.html) authorization pipeline,
for example:

```python
SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'myapp.authentication.introspect_token',
    'myapp.authentication.restrict_email_domain',
    'myapp.authentication.verify_client_id',
    ...
)
```
