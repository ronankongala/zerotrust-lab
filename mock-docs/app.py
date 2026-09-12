"""mock-docs: a SAML 2.0 service provider for the Zero Trust lab.

A single protected page. Unauthenticated visitors are bounced to Keycloak's
SAML SSO endpoint for the zerotrust-lab realm; Keycloak POSTs an assertion back
to /saml/acs and the user lands on the page with their name filled in.

Pair this with mock-dashboard (port 9002) to demonstrate SSO: the second app
never prompts for credentials, because Keycloak already has a realm session.
"""

import os

from flask import Flask, redirect, render_template_string, request, session, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

APP_NAME = "mock-docs"
APP_TITLE = "Internal Docs"

# How the browser reaches this app. Everything the IdP is told about us must be
# phrased in these terms, not in docker-network terms.
SP_BASE_URL = os.environ.get("SP_BASE_URL", "http://localhost:9001").rstrip("/")
# Keycloak uses the SAML client's clientId as the SP entity ID.
SP_ENTITY_ID = os.environ.get("SP_ENTITY_ID", "mock-docs-saml")

# Two URLs for the same Keycloak: the browser is redirected to the public one,
# while the metadata (and with it the realm's signing certificate) is fetched
# over the docker network at startup.
IDP_PUBLIC_URL = os.environ.get("IDP_PUBLIC_URL", "http://localhost:8080").rstrip("/")
IDP_INTERNAL_URL = os.environ.get("IDP_INTERNAL_URL", "http://keycloak:8080").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "zerotrust-lab")

IDP_ENTITY_ID = "%s/realms/%s" % (IDP_PUBLIC_URL, REALM)
IDP_SSO_URL = "%s/realms/%s/protocol/saml" % (IDP_PUBLIC_URL, REALM)
IDP_DESCRIPTOR_URL = "%s/realms/%s/protocol/saml/descriptor" % (IDP_INTERNAL_URL, REALM)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-" + APP_NAME)
# Cookies are scoped to a host, not a port, so both mock apps share the
# "localhost" cookie jar. Distinct names keep mock-dashboard from reading this
# app's session and appearing logged in without ever talking to Keycloak --
# which would make the SSO demo prove nothing.
app.config["SESSION_COOKIE_NAME"] = APP_NAME.replace("-", "_") + "_session"

_idp_cert_cache = {}


def idp_x509cert():
    """Read the realm's SAML signing certificate from Keycloak's descriptor.

    The realm's key is generated on import, so it cannot be baked into the
    image. Fetched on first use (not at import time) so the container starts
    even if Keycloak is still booting, and cached once it succeeds.
    """
    if "cert" not in _idp_cert_cache:
        parsed = OneLogin_Saml2_IdPMetadataParser.parse_remote(
            IDP_DESCRIPTOR_URL, validate_cert=False
        )
        cert = parsed.get("idp", {}).get("x509cert")
        if not cert:
            raise RuntimeError(
                "no signing certificate in the IdP descriptor at %s" % IDP_DESCRIPTOR_URL
            )
        _idp_cert_cache["cert"] = cert
    return _idp_cert_cache["cert"]


def saml_settings():
    return {
        "strict": True,
        "debug": True,
        "sp": {
            "entityId": SP_ENTITY_ID,
            "assertionConsumerService": {
                "url": SP_BASE_URL + "/saml/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        },
        "idp": {
            "entityId": IDP_ENTITY_ID,
            "singleSignOnService": {
                "url": IDP_SSO_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": idp_x509cert(),
        },
        "security": {
            # The Keycloak client is created with client signature verification
            # off, so this SP needs no keypair of its own.
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantNameId": True,
            "requestedAuthnContext": False,
        },
    }


def prepare_request():
    """Translate the Flask request into what python3-saml expects.

    'server_port' is deliberately omitted: request.host already carries the
    published port (localhost:9001), and supplying both makes python3-saml warn
    about a duplicated port suffix.
    """
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
    }


def init_saml():
    return OneLogin_Saml2_Auth(prepare_request(), saml_settings())


PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{{ title }}</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 34rem; color: #1b1b1b; }
  h1 { margin-bottom: .25rem; }
  .who { font-size: 1.1rem; }
  .who strong { font-size: 1.3rem; }
  .meta { color: #666; font-size: .85rem; margin-top: 2rem; }
  a { color: #0b5fff; }
</style>
</head>
<body>
  <h1>{{ title }}</h1>
  <p class="who">Signed in as <strong>{{ name }}</strong></p>
  <p class="meta">
    Authenticated over SAML 2.0 against the <code>{{ realm }}</code> realm
    (SP entity ID <code>{{ entity_id }}</code>).<br>
    <a href="{{ url_for('logout') }}">Log out of this app</a>
  </p>
</body>
</html>
"""


def first_value(attributes, key):
    values = attributes.get(key) or []
    return values[0] if values else None


def display_name(attributes, name_id):
    """Prefer the person's real name, falling back to whatever we did get."""
    parts = [
        first_value(attributes, "givenName"),
        first_value(attributes, "surname"),
    ]
    full = " ".join(part for part in parts if part)
    return full or first_value(attributes, "username") or name_id or "unknown"


@app.get("/health")
def health():
    return {"service": APP_NAME, "status": "ok"}


@app.get("/")
def index():
    if "name" not in session:
        return redirect(url_for("saml_login", next=request.url))
    return render_template_string(
        PAGE,
        title=APP_TITLE,
        name=session["name"],
        realm=REALM,
        entity_id=SP_ENTITY_ID,
    )


@app.get("/saml/login")
def saml_login():
    # return_to travels as RelayState, so no pre-auth session state is needed --
    # which matters, because a SameSite=Lax cookie would not survive Keycloak's
    # cross-site POST back to /saml/acs.
    return redirect(init_saml().login(return_to=request.args.get("next") or SP_BASE_URL + "/"))


@app.post("/saml/acs")
def saml_acs():
    auth = init_saml()
    # request_id is None: the AuthnRequest ID was not stashed in a cookie (see
    # /saml/login), so InResponseTo is not checked. Fine for a lab SP.
    auth.process_response(request_id=None)

    errors = auth.get_errors()
    if errors:
        return (
            "SAML authentication failed: %s\n%s" % (", ".join(errors), auth.get_last_error_reason() or ""),
            401,
            {"Content-Type": "text/plain"},
        )
    if not auth.is_authenticated():
        return ("SAML authentication failed: not authenticated", 401, {"Content-Type": "text/plain"})

    session["name"] = display_name(auth.get_attributes(), auth.get_nameid())
    session["name_id"] = auth.get_nameid()

    relay_state = request.form.get("RelayState")
    # Keycloak echoes its own SSO URL as RelayState when we send none; bouncing
    # the browser back there would loop.
    if relay_state and relay_state.startswith(SP_BASE_URL):
        return redirect(relay_state)
    return redirect(url_for("index"))


@app.get("/saml/metadata")
def saml_metadata():
    settings = init_saml().get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        return ("invalid SP metadata: %s" % ", ".join(errors), 500, {"Content-Type": "text/plain"})
    return (metadata, 200, {"Content-Type": "text/xml"})


@app.get("/logout")
def logout():
    """Local logout only -- the Keycloak realm session is left alone, so the
    SSO demo can be repeated without re-entering credentials."""
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
