import requests
from django.conf import settings

authorization_endpoint = getattr(settings, "OIDC_AUTHORIZATION_ENDPOINT", None)
token_endpoint = getattr(settings, "OIDC_TOKEN_ENDPOINT", None)
CLIENT_ID = getattr(settings, "OIDC_CLIENT_ID", None)
CLIENT_SECRET = getattr(settings, "OIDC_CLIENT_SECRET", None)
userinfo_endpoint = getattr(settings, "OIDC_USERINFO_ENDPOINT", None)
SCOPE = getattr(settings, "OIDC_SCOPE", "openid email")
WELL_KNOWN_SCHEME = "/.well-known/openid-configuration"
ERR_INVALID_RESPONSE = (
    "Unable to fetch user information from provider.  Please check the log."
)
issuer = None

DATA_VERSION = "1"


def is_pkce_enabled() -> bool:
    return bool(getattr(settings, "OIDC_PKCE_ENABLED", False))

OIDC_DOMAIN = getattr(settings, "OIDC_DOMAIN", None)
if OIDC_DOMAIN:
    WELL_KNOWN_URL = OIDC_DOMAIN.strip("/") + WELL_KNOWN_SCHEME
    well_known_values = requests.get(WELL_KNOWN_URL, timeout=2.0).json()
    if well_known_values:
        userinfo_endpoint = well_known_values["userinfo_endpoint"]
        authorization_endpoint = well_known_values["authorization_endpoint"]
        token_endpoint = well_known_values["token_endpoint"]
        issuer = well_known_values["issuer"]


config_issuer = getattr(settings, "OIDC_ISSUER", None)
if config_issuer:
    issuer = config_issuer

AUTHORIZATION_ENDPOINT = authorization_endpoint
TOKEN_ENDPOINT = token_endpoint
USERINFO_ENDPOINT = userinfo_endpoint
ISSUER = issuer
