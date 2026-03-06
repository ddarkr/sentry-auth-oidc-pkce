from types import SimpleNamespace
from unittest import TestCase
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from django.test import RequestFactory, override_settings
from sentry.auth.exceptions import IdentityNotValid
from sentry.auth.providers.oauth2 import OAuth2Callback
from sentry.utils import json

from oidc.constants import DATA_VERSION
from oidc.provider import (
    OIDCLogin,
    OIDCPKCECallback,
    OIDCPKCELogin,
    OIDCProvider,
    PKCE_CODE_CHALLENGE_METHOD,
    PKCE_CODE_VERIFIER_STATE,
    _make_code_challenge,
)

class OIDCProviderTest(TestCase):
    def test_refresh_identity_without_refresh_token(self):
        auth_identity = SimpleNamespace(data={"access_token": "access_token"})
        provider = OIDCProvider()

        with pytest.raises(IdentityNotValid):
            provider.refresh_identity(auth_identity)

    def test_handles_multiple_domains(self):
        provider = OIDCProvider(domains=["example.com"])
        assert provider.domains == ["example.com"]

    def test_handles_legacy_single_domain(self):
        provider = OIDCProvider(domain="example.com")
        assert provider.domains == ["example.com"]

    def test_build_config(self):
        provider = OIDCProvider()
        state = {
            "domain": "example.com",
            "user": {
                "iss": "accounts.google.com",
                "at_hash": "HK6E_P6Dh8Y93mRNtsDB1Q",
                "email_verified": "true",
                "sub": "10769150350006150715113082367",
                "azp": "1234987819200.apps.googleusercontent.com",
                "email": "jsmith@example.com",
                "aud": "1234987819200.apps.googleusercontent.com",
                "iat": 1353601026,
                "exp": 1353604926,
                "hd": "example.com",
            },
        }
        result = provider.build_config(state)
        assert result == {"domains": ["example.com"], "version": DATA_VERSION}


class FakePipeline:
    def __init__(self, provider_key: str = "oidc"):
        self.provider = SimpleNamespace(key=provider_key)
        self.state: dict[str, str] = {}

    def bind_state(self, key: str, value: str) -> None:
        self.state[key] = value

    def fetch_state(self, key: str) -> str | None:
        return self.state.get(key)

    def next_step(self):
        return "next-step"


class OIDCPKCETest(TestCase):
    def setUp(self):
        self.request_factory = RequestFactory()

    @override_settings(OIDC_PKCE_ENABLED=True)
    def test_get_auth_pipeline_uses_pkce_steps(self):
        provider = OIDCProvider()

        login, callback, _ = provider.get_auth_pipeline()

        assert isinstance(login, OIDCPKCELogin)
        assert isinstance(callback, OIDCPKCECallback)

    @override_settings(OIDC_PKCE_ENABLED=False)
    def test_get_auth_pipeline_keeps_default_steps(self):
        provider = OIDCProvider()

        login, callback, _ = provider.get_auth_pipeline()

        assert isinstance(login, OIDCLogin)
        assert not isinstance(login, OIDCPKCELogin)
        assert isinstance(callback, OAuth2Callback)
        assert not isinstance(callback, OIDCPKCECallback)

    @mock.patch("oidc.provider._get_redirect_url", return_value="https://sentry.example.com/auth/sso/")
    def test_pkce_login_redirect_includes_challenge_and_stores_verifier(self, get_redirect_url):
        login = OIDCPKCELogin(client_id="client-id")
        login.authorize_url = "https://idp.example.com/authorize"
        request = self.request_factory.get("/auth/login/")
        request.subdomain = None
        pipeline = FakePipeline()

        response = login.dispatch(request, pipeline)
        redirect = urlparse(response["Location"])
        query = parse_qs(redirect.query)

        verifier = pipeline.fetch_state(PKCE_CODE_VERIFIER_STATE)

        assert redirect.scheme == "https"
        assert redirect.netloc == "idp.example.com"
        assert verifier is not None
        assert query["code_challenge_method"] == [PKCE_CODE_CHALLENGE_METHOD]
        assert query["code_challenge"] == [_make_code_challenge(verifier)]
        assert query["state"] == [pipeline.fetch_state("state")]
        assert query["redirect_uri"] == [get_redirect_url.return_value]
        assert "code_verifier" not in query

    @mock.patch("oidc.provider._get_redirect_url", return_value="https://sentry.example.com/auth/sso/")
    @mock.patch("oidc.provider.safe_urlread")
    @mock.patch("oidc.provider.safe_urlopen")
    def test_pkce_callback_sends_code_verifier(self, urlopen, urlread, get_redirect_url):
        callback = OIDCPKCECallback(
            access_token_url="https://idp.example.com/token",
            client_id="client-id",
            client_secret="client-secret",
        )
        request = self.request_factory.get("/auth/sso/")
        pipeline = FakePipeline()
        pipeline.bind_state(PKCE_CODE_VERIFIER_STATE, "verifier-123")
        urlopen.return_value = SimpleNamespace(headers={"Content-Type": "application/json"})
        urlread.return_value = json.dumps({"access_token": "token", "token_type": "Bearer"})

        result = callback.exchange_token(request, pipeline, "auth-code")

        assert result == {"access_token": "token", "token_type": "Bearer"}
        assert urlopen.call_args.kwargs["data"] == {
            "grant_type": "authorization_code",
            "code": "auth-code",
            "redirect_uri": get_redirect_url.return_value,
            "client_id": "client-id",
            "client_secret": "client-secret",
            "code_verifier": "verifier-123",
        }

    def test_pkce_callback_requires_verifier(self):
        callback = OIDCPKCECallback(
            access_token_url="https://idp.example.com/token",
            client_id="client-id",
            client_secret="client-secret",
        )
        request = self.request_factory.get("/auth/sso/")
        pipeline = FakePipeline()

        result = callback.exchange_token(request, pipeline, "auth-code")

        assert result == {"error_description": "Missing PKCE code verifier"}
