from __future__ import annotations

import base64
import hashlib
import secrets
import time
from collections.abc import Callable, Mapping
from urllib.parse import parse_qsl, urlencode

import orjson
from django.http import HttpRequest
import requests
from django.http.response import HttpResponseRedirect
from django.urls import reverse
from sentry.auth.provider import MigratingIdentityId
from sentry.auth.providers.oauth2 import OAuth2Callback, OAuth2Login, OAuth2Provider
from sentry.auth.services.auth.model import RpcAuthProvider
from sentry.http import safe_urlopen, safe_urlread
from sentry.organizations.services.organization.model import RpcOrganization
from sentry.plugins.base.response import DeferredResponse
from sentry.utils.http import absolute_uri

from .constants import (
    AUTHORIZATION_ENDPOINT,
    CLIENT_ID,
    CLIENT_SECRET,
    DATA_VERSION,
    ISSUER,
    SCOPE,
    TOKEN_ENDPOINT,
    USERINFO_ENDPOINT,
    is_pkce_enabled,
)
from .views import FetchUser, oidc_configure_view


PKCE_CODE_CHALLENGE_METHOD = "S256"
PKCE_CODE_VERIFIER_STATE = "pkce_code_verifier"


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_code_verifier() -> str:
    return _base64url_encode(secrets.token_bytes(32))


def _make_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _base64url_encode(digest)


def _get_redirect_url() -> str:
    return absolute_uri(reverse("sentry-auth-sso"))


class OIDCLogin(OAuth2Login):
    authorize_url = AUTHORIZATION_ENDPOINT
    client_id = CLIENT_ID
    scope = SCOPE

    def __init__(self, client_id, domains=None):
        self.domains = domains
        super().__init__(client_id=client_id)

    def get_authorize_params(self, state, redirect_uri):
        params = super().get_authorize_params(state, redirect_uri)
        # TODO(dcramer): ideally we could look at the current resulting state
        # when an existing auth happens, and if they're missing a refresh_token
        # we should re-prompt them a second time with ``approval_prompt=force``
        params["approval_prompt"] = "force"
        params["access_type"] = "offline"
        return params


class OIDCPKCELogin(OIDCLogin):
    def dispatch(self, request: HttpRequest, pipeline) -> HttpResponseRedirect:
        if "code" in request.GET:
            return pipeline.next_step()

        nonce = secrets.token_hex()
        state = f"{nonce}:{pipeline.provider.key}"
        verifier = _make_code_verifier()

        params = self.get_authorize_params(state=state, redirect_uri=_get_redirect_url())
        params["code_challenge"] = _make_code_challenge(verifier)
        params["code_challenge_method"] = PKCE_CODE_CHALLENGE_METHOD

        pipeline.bind_state("state", state)
        pipeline.bind_state(PKCE_CODE_VERIFIER_STATE, verifier)
        if request.subdomain:
            pipeline.bind_state("subdomain", request.subdomain)

        return HttpResponseRedirect(f"{self.get_authorize_url()}?{urlencode(params)}")


class OIDCPKCECallback(OAuth2Callback):
    def exchange_token(self, request: HttpRequest, pipeline, code: str) -> Mapping[str, object]:
        verifier = pipeline.fetch_state(PKCE_CODE_VERIFIER_STATE)
        if not verifier:
            return {"error_description": "Missing PKCE code verifier"}

        data = dict(self.get_token_params(code=code, redirect_uri=_get_redirect_url()))
        data["code_verifier"] = verifier

        req = safe_urlopen(self.access_token_url, data=data)
        body = safe_urlread(req)
        if req.headers["Content-Type"].startswith("application/x-www-form-urlencoded"):
            return dict(parse_qsl(body))
        return orjson.loads(body)


class OIDCProvider(OAuth2Provider):
    name = ISSUER
    key = "oidc"

    def __init__(self, domain=None, domains=None, version=None, **config):
        if domain:
            if domains:
                domains.append(domain)
            else:
                domains = [domain]
        self.domains = domains
        # if a domain is not configured this is part of the setup pipeline
        # this is a bit complex in Sentry's SSO implementation as we don't
        # provide a great way to get initial state for new setup pipelines
        # vs missing state in case of migrations.
        if domains is None:
            version = DATA_VERSION
        else:
            version = None
        self.version = version
        super().__init__(**config)

    def get_client_id(self):
        return CLIENT_ID

    def get_client_secret(self):
        return CLIENT_SECRET

    def get_configure_view(
        self,
    ) -> Callable[[HttpRequest, RpcOrganization, RpcAuthProvider], DeferredResponse]:
        return oidc_configure_view

    def get_auth_pipeline(self):
        pkce_enabled = is_pkce_enabled()
        login_cls = OIDCPKCELogin if pkce_enabled else OIDCLogin
        callback_cls = OIDCPKCECallback if pkce_enabled else OAuth2Callback
        return [
            login_cls(domains=self.domains, client_id=self.get_client_id()),
            callback_cls(
                access_token_url=TOKEN_ENDPOINT,
                client_id=self.get_client_id(),
                client_secret=self.get_client_secret(),
            ),
            FetchUser(domains=self.domains, version=self.version),
        ]

    def get_refresh_token_url(self):
        return TOKEN_ENDPOINT

    def build_config(self, state):
        return {"domains": [state["domain"]], "version": DATA_VERSION}

    def get_user_info(self, bearer_token: str) -> dict[str, object]:
        endpoint = USERINFO_ENDPOINT or ""
        bearer_auth = "Bearer " + bearer_token
        retry_codes = [429, 500, 502, 503, 504]
        for retry in range(10):
            if 10 < retry:
                return {}
            r = requests.get(
                endpoint + "?schema=openid",
                headers={"Authorization": bearer_auth},
                timeout=20.0,
            )
            if r.status_code in retry_codes:
                wait_time = 2**retry * 0.1
                time.sleep(wait_time)
                continue
            payload = r.json()
            return payload if isinstance(payload, dict) else {}

        return {}

    def build_identity(self, state):
        data = state["data"]
        user_data = state["user"]

        bearer_token = data["access_token"]
        user_info = self.get_user_info(bearer_token)

        # XXX(epurkhiser): We initially were using the email as the id key.
        # This caused account dupes on domain changes. Migrate to the
        # account-unique sub key.
        user_id = MigratingIdentityId(id=user_data["sub"], legacy_id=user_data["email"])

        return {
            "id": user_id,
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "data": self.get_oauth_data(data),
            "email_verified": user_info.get("email_verified"),
        }
