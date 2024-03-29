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

If you prefer to have Transparent SSO authentication on all URLs, it's better to
include the package authentication middleware to the common list of middleware,
after the Django Authentication Middleware:

```python
MIDDLEWARE = [
    ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    'tsso.middleware.TSSOMiddleware',
    ...
]
```

If you prefer to have such an authentication only on the level of your API,
include the authentication middleware to the specific API provider, like Django REST:

```
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        ...
        'ssso.contrib.rest.authentication.TSSOAuthentication',
        ...
    ]
}

```

The authenticated user is not connected to the session, and the Transparent SSO authentication
protocol should be provided on every API call.

More authentication backends for different API providers are coming later.

Switch necessary OAuth1/2 authorization backends on.

```
AUTHENTICATION_BACKENDS = (
    ...
    'social_core.backends.google.GoogleOAuth2',
    ...
)
```

You may skip setting backend client key and secret, if you won't plan to
activate OAuth1/2 login pipeline, and would like to have a Transparent SSO
pipeline only.

## Authentication protocol

### Three sides of the protocol

There are three sides of the authentication protocol.

- The Authentication Server provides a way to get a token and identify a current user by the token
- The Client requests a token from the Authentication server, and provides it to the Service Provider to authorize the current user
- The Service Provider agrees using the Authentication Server as an authentication and authorization server for the current user

The Authentication Server may be any token-based OAuth2 server, for which the correspondent backend is provided by the
Python Social Auth package, or third party using the Python Social Auth package to create its own backend.

The OAuth1 Authentication Servers may be also applicable, but it was not tested by the package's author yet.
Please provide your own experience with OAuth1 Authentication Server, or even other token-based authentication servers.

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
server without any changes on its' side.

###  Authorization steps

#### Getting am access token

The Client requests the access token from the authentication server using the OAuth-like protocol. The particular
way to do it is out of our scope. The only significant result, that the Client. at some moment, knows the
access token and token type, which is `Bearer` for the most OAuth2 cases.

#### Getting access to the Service Provider's resource

The client requests any Service Provider resource, using the `Authorization` header of the specific value structure.

The `Authorization` header value consists of the `SSO` type, following by the specific SSO authorization value.

The authorization value consists of three parts, separated by colon `:`.

The first part is a name of the authorization backend on the Service Provider side. It is known to the Service Provider admin deploying
the Service Provider instance supporting Transparent SSO protocol.

The second part is an access token type, `Bearer` in most OAuth2 cases. It is a token type when accessing the Authentication Server.

The third part is an access token itself.

#### Verifying access token by the Service provider

The Service Provider veryfies the token sending authorized request to the Authorization Server. The request is absolutely same,
as for the User details in the OAuth protocol.

If the request returns the current user info, it means that the access to the Service Provider resource should be granted.

The Service Provider may cache the token check results to avoid unnecessary requests to the Authentication Server
every time when the ressource is requested. The `settings.TSSO_EXPIRATION_PERIOD` variable controls, how many
seconds the cached token is valid without additional check on the Authorization Server side.

## Controlling users in the Authentication Pipeline

You can control user creation and verifying in the Authentication Pipeline, as it's described
in the Python Social Auth documentation.

The behaviour which often is used as a default, allows automatic user creation. It means, that any external user who
goes successfully through the SSO authorization pipeline, will be authomatically created on the Service Provider side.

It may make some unexpected result in case of Transparent SSO solution.

Notice that your Service Provider doesn't know anything about the Client Application on the Authorization Server side.

So, if the Service Provider trusts the Authorization Server, **any** user getting proper token from this Authorization Server
can be authorized by the Service Provider using this token.

It means, f.e., that if you use the Google server and restrict access to your Client Application by domain name, this
restriction will not work for the Service Provider. Any user, who is registered on the Google, may send his token
and get access to the Service Provider data. It happens, because the SSO subsystem of the Service Provider
doesn't know about a Client ID used to generate this token, and as such, doesn't restrict access by the Client ID.

Therefore, if you want to restrict access to the Service Provider by some circumstances, these circumstances shoulc be controlled
by your own code in the Authentication Pipeline.
