OpenIDConnect Auth for Sentry
=============================

An SSO provider for Sentry which enables `OpenID Connect <http://openid.net/connect/>`_ Apps authentication.

Project Overview
----------------

This project is a Sentry authentication extension that registers an OpenID Connect
provider through Sentry's plugin app entry point. It is intended for self-hosted
Sentry deployments that want to use a standards-based OIDC identity provider such
as Google, GitLab, or other compatible providers.

The plugin supports standard OAuth 2.0 / OpenID Connect authorization code flows
and can optionally enable PKCE with the ``S256`` code challenge method via
``OIDC_PKCE_ENABLED``. Keeping PKCE disabled preserves compatibility with providers
that still expect the classic OAuth 2.0 flow.

This is a fork of `sentry-auth-google <https://github.com/getsentry/sentry-auth-google/>`_.

Why fork, instead of adapting sentry-auth-google to work with every OpenID Connect provider?
--------------------------------------------------------------------------------------------
The maintainer has different ideas with sentry-auth-google. See:

* https://github.com/getsentry/sentry-auth-google/pull/29
* https://github.com/getsentry/sentry/issues/5650

Install
-------

::

    $ pip install doda-sentry-auth-oidc

Example Setup for Google
------------------------

Start by `creating a project in the Google Developers Console <https://console.developers.google.com>`_.

In the **Authorized redirect URIs** add the SSO endpoint for your installation::

    https://sentry.example.com/auth/sso/

Naturally other providers, that are supporting OpenID-Connect can also be used (like GitLab).

Finally, obtain the API keys and the well-known account URL and plug them into your ``sentry.conf.py``:

.. code-block:: python

    OIDC_CLIENT_ID = ""

    OIDC_CLIENT_SECRET = ""

    OIDC_SCOPE = "openid email"

    OIDC_PKCE_ENABLED = False  # Set to True to use PKCE with S256

    OIDC_DOMAIN = "https://accounts.google.com"  # e.g. for Google

The ``OIDC_DOMAIN`` defines where the OIDC configuration is going to be pulled from.
Basically it specifies the OIDC server and adds the path ``.well-known/openid-configuration`` to it.
That's where different endpoint paths can be found.

Detailed information can be found in the `ProviderConfig <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig>`_ specification.

You can also define ``OIDC_ISSUER`` to change the default provider name in the UI, even when the ``OIDC_DOMAIN`` is set.

Set ``OIDC_PKCE_ENABLED = True`` to enable PKCE using the ``S256`` code challenge method. Leave it disabled to preserve OAuth 2.0 compatibility with providers that do not support PKCE.

If your provider doesn't support the ``OIDC_DOMAIN``, then you have to set these
required endpoints by yourself (autorization_endpoint, token_endpoint, userinfo_endpoint, issuer).

.. code-block:: python

    OIDC_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"  # e.g. for Google

    OIDC_TOKEN_ENDPOINT = "https://www.googleapis.com/oauth2/v4/token"  # e.g. for Google

    OIDC_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo" # e.g. for Google

    OIDC_ISSUER = "Google"

Development
-----------

For local development, this repository is usually tested together with an upstream
Sentry checkout in ``deps/sentry``. The ``make deps`` target installs the exported
Sentry test dependencies into ``.venv`` and writes a ``sentry.pth`` file so the
plugin tests can import Sentry directly from that checkout.

The focused provider test suite can then be run with::

    .venv/bin/pytest tests/test_provider.py

This is useful when iterating on OIDC configuration, login pipeline behavior, and
optional PKCE support.

FAQ
~~~~~

- If you are using macOS brew's openssl and you get a psycopg build error such as:
    ::

      ld: library not found for -lssl

  Please setup the following environment variables:
    .. code-block:: bash

      export LDFLAGS="-L/usr/local/opt/openssl/lib"
      export CPPFLAGS="-I/usr/local/opt/openssl/include"
