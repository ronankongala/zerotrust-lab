import json
import os
import ssl
import time
from datetime import datetime, timezone
from functools import wraps

import jwt
import requests
from flask import Flask, jsonify, request
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError

app = Flask(__name__)

ORDERS_URL = os.environ.get("ORDERS_URL", "https://orders:5000")
INVENTORY_URL = os.environ.get("INVENTORY_URL", "https://inventory:5000")
TIMEOUT = 5

CERT_DIR = os.environ.get("CERT_DIR", "/certs")
TLS_CERT = os.environ.get("TLS_CERT", f"{CERT_DIR}/gateway.crt")
TLS_KEY = os.environ.get("TLS_KEY", f"{CERT_DIR}/gateway.key")
TLS_CA = os.environ.get("TLS_CA", f"{CERT_DIR}/ca.crt")


# One JSON object per line on stdout, which is where `docker compose logs
# gateway` reads from. Deliberately minimal: no logging framework, no file
# handler, no shipping anywhere. The point is only that each of the three gates
# below leaves a record of what it decided and why, so an allow or a deny can be
# reconstructed afterwards instead of being visible only to whoever made the
# request. See ZERO_TRUST_MAPPING.md tenets 5 and 7 for what that does and does
# not amount to.
def audit(event, decision, reason, subject=None, **extra):
    """Record one decision.

    `event` is which gate spoke (token | policy | credential), `decision` is
    what it said (allow | deny | error). Never pass a credential, token or key
    in `extra` -- this goes to stdout and stays in the container's log.
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        "decision": decision,
        "subject": subject,
        "method": request.method,
        "path": request.path,
        "reason": reason,
    }
    record.update(extra)
    # flush=True because Python block-buffers stdout when it is a pipe, which is
    # exactly what Docker hands it; without this the lines arrive late or not at
    # all, which would make the log useless for watching a request go through.
    print(json.dumps(record, sort_keys=True), flush=True)


def realm_roles(claims):
    """The claim the policy actually turns on, logged so a deny is explicable."""
    return claims.get("realm_access", {}).get("roles", [])


def mtls_context():
    """Serve TLS with our own cert and refuse callers the lab CA didn't sign."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
    context.load_verify_locations(cafile=TLS_CA)
    # What makes this mutual rather than one-way: without CERT_REQUIRED the
    # server would happily complete a handshake with an anonymous client.
    context.verify_mode = ssl.CERT_REQUIRED
    return context


# The other half of mTLS: upstream calls present the gateway's own cert, and the
# upstream is only trusted if the lab CA signed it. Hostname checking stays on,
# so ORDERS_URL/INVENTORY_URL must use the names in the certs' SANs.
upstream = requests.Session()
upstream.cert = (TLS_CERT, TLS_KEY)
upstream.verify = TLS_CA

# Fetched over the docker network, so the internal hostname is used here. The
# issuer is whatever Keycloak stamps into the token, which is the address the
# client used to get it (localhost, from outside the network).
JWKS_URL = os.environ.get(
    "KEYCLOAK_JWKS_URL",
    "http://keycloak:8080/realms/zerotrust-lab/protocol/openid-connect/certs",
)
ISSUER = os.environ.get(
    "KEYCLOAK_ISSUER", "http://localhost:8080/realms/zerotrust-lab"
)

# Keeps the JWK set in memory and re-fetches it when a token presents a kid
# that isn't in the cache (e.g. after a Keycloak key rotation).
jwks_client = PyJWKClient(JWKS_URL, cache_jwk_set=True, lifespan=300, timeout=TIMEOUT)

# The policy decision point. Plain HTTP on the internal network and a session of
# its own: the gateway is OPA's client here, not an mTLS peer, so it must not
# reuse `upstream` (whose client cert and CA bundle are for orders/inventory).
OPA_URL = os.environ.get("OPA_URL", "http://opa:8181/v1/data/authz/allow")
opa = requests.Session()

class PolicyUnavailable(Exception):
    """OPA could not be reached or answered with something unusable."""


def opa_allows(claims):
    """Ask OPA whether these claims may perform this method+path.

    Authentication (is the token real?) has already happened; this is the
    separate authorization question, and the answer lives in policies/authz.rego
    rather than in this file.
    """
    payload = {
        "input": {
            "authenticated": True,
            "method": request.method,
            "path": request.path,
            "claims": claims,
        }
    }
    try:
        response = opa.post(OPA_URL, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        body = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise PolicyUnavailable(str(exc)) from exc

    # An undefined decision comes back as a body with no "result" at all. The
    # policy's `default allow := false` means that should not happen, but
    # treating a missing result as "allowed" would be exactly the wrong default.
    return body.get("result") is True


def bearer_token():
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def require_token_and_policy(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = bearer_token()
        if token is None:
            audit("token", "deny", "no bearer token in Authorization header")
            return jsonify(error="unauthorized", detail="missing bearer token"), 401

        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            request.token_claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=ISSUER,
                options={"verify_aud": False, "require": ["exp", "iss"]},
            )
        except jwt.ExpiredSignatureError:
            audit("token", "deny", "token expired")
            return jsonify(error="unauthorized", detail="token expired"), 401
        except (jwt.InvalidTokenError, PyJWKClientError) as exc:
            audit("token", "deny", str(exc))
            return jsonify(error="unauthorized", detail=str(exc)), 401

        subject = request.token_claims.get("preferred_username")
        roles = realm_roles(request.token_claims)
        audit(
            "token",
            "allow",
            "signature, issuer and expiry verified against %s" % ISSUER,
            subject=subject,
            roles=roles,
        )

        try:
            if not opa_allows(request.token_claims):
                audit(
                    "policy",
                    "deny",
                    "OPA returned allow=false",
                    subject=subject,
                    roles=roles,
                )
                return (
                    jsonify(
                        error="forbidden",
                        detail="policy denied %s %s" % (request.method, request.path),
                        subject=subject,
                    ),
                    403,
                )
        except PolicyUnavailable as exc:
            # Fail closed: no decision is not the same as an allow.
            audit("policy", "error", "OPA unreachable: %s" % exc, subject=subject)
            return jsonify(error="policy_unavailable", detail=str(exc)), 503

        audit("policy", "allow", "OPA returned allow=true", subject=subject, roles=roles)
        return view(*args, **kwargs)

    return wrapper


# The just-in-time privileged access layer. OPA answers "may this identity ever
# delete an order?"; Vault answers "did they obtain permission to do it *now*?"
# A standing manager role is no longer enough on its own.
#
# Another plain-HTTP internal client, and again a session of its own rather than
# `upstream`: Vault is not an mTLS peer of the gateway.
VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://vault:8200")
VAULT_ROLE_ID = os.environ.get("VAULT_ROLE_ID", "ztlab-gateway-delete-role")
VAULT_SECRET_ID = os.environ.get("VAULT_SECRET_ID", "ztlab-gateway-delete-secret")
# The Vault policy vault/setup.sh attaches to the minted token. A token without
# it may be perfectly valid and still not be a *delete* credential.
DELETE_POLICY = os.environ.get("VAULT_DELETE_POLICY", "delete-order")

vault = requests.Session()


class VaultUnavailable(Exception):
    """Vault could not be reached or answered with something unusable."""


class CredentialRejected(Exception):
    """The presented credential is not a usable delete credential.

    Carries its own error code so the gateway can tell the caller *why*: one
    Vault no longer recognises and one that is real but scoped to something else
    are different mistakes, and a caller debugging a 403 needs to know which.
    """

    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def mint_delete_credential():
    """Log in to Vault with the gateway's AppRole and return a fresh token.

    AppRole rather than userpass because the caller is a service: role_id is the
    public identifier, secret_id the proof, and the login is unauthenticated by
    design. Note what the gateway does *not* hold: no root token, no standing
    Vault privilege it could lend to a request. All it can do is buy itself a
    20-second credential that the role's TTL kills on its own.
    """
    try:
        response = vault.post(
            f"{VAULT_ADDR}/v1/auth/approle/login",
            json={"role_id": VAULT_ROLE_ID, "secret_id": VAULT_SECRET_ID},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        auth = response.json()["auth"]
    except (requests.RequestException, ValueError, KeyError) as exc:
        raise VaultUnavailable(str(exc)) from exc

    return auth["client_token"], auth["lease_duration"]


def verify_delete_credential(credential):
    """Check a presented credential against Vault, or raise CredentialRejected.

    The gateway does not trust the credential's shape, its own memory of having
    minted one, or a signature it could verify offline: it asks Vault, every
    time. Expiry is therefore Vault's answer and not a clock comparison here,
    which is what makes a revoked token fail just as fast as an expired one.
    """
    try:
        response = vault.get(
            f"{VAULT_ADDR}/v1/auth/token/lookup-self",
            headers={"X-Vault-Token": credential},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise VaultUnavailable(str(exc)) from exc

    try:
        body = response.json()
    except ValueError as exc:
        # Not even a Vault-shaped reply: something is wrong with Vault itself,
        # not with the credential.
        raise VaultUnavailable(str(exc)) from exc

    if response.status_code != 200 or "data" not in body:
        # Vault answered, in its own error format, and the answer was not yes.
        # Sorting its statuses by meaning is not worth it: an expired token, a
        # revoked one and one that never existed all come back as 403
        # "permission denied" (an expired token is simply gone), while a
        # malformed one trips a 500 during parsing. None of them are usable, and
        # Vault will not tell an unauthenticated caller which it was.
        errors = "; ".join(body.get("errors", [])) or response.reason
        raise CredentialRejected(
            "vault_credential_invalid",
            "vault rejected the credential in X-Vault-Credential (expired, "
            "revoked, malformed, or never issued): %s" % errors.strip(),
        )

    data = body["data"]

    # A live token is not automatically a *delete* token. Without this check the
    # root token, or any other credential in the lab, would sail through.
    if DELETE_POLICY not in data.get("policies", []):
        raise CredentialRejected(
            "vault_credential_out_of_scope",
            "credential is valid but not scoped to %s; it carries %s"
            % (DELETE_POLICY, data.get("policies", [])),
        )

    return data


def require_vault_credential(view):
    """Second gate on a destructive route, applied *after* OPA has allowed it.

    Ordering matters for the demo: a caller with no manager role never gets far
    enough to hear about Vault, so the two denials can never be confused.
    """

    @wraps(view)
    def wrapper(*args, **kwargs):
        subject = getattr(request, "token_claims", {}).get("preferred_username")
        credential = request.headers.get("X-Vault-Credential", "").strip()
        if not credential:
            audit(
                "credential",
                "deny",
                "no X-Vault-Credential header",
                subject=subject,
                error_code="vault_credential_required",
            )
            return (
                jsonify(
                    error="vault_credential_required",
                    detail="policy allowed this request, but %s %s also needs a "
                    "short-lived Vault credential in X-Vault-Credential; mint "
                    "one at GET /admin/mint-delete-credential"
                    % (request.method, request.path),
                ),
                403,
            )

        try:
            request.vault_credential = verify_delete_credential(credential)
        except CredentialRejected as exc:
            # exc.detail carries Vault's own error text, never the credential.
            audit(
                "credential",
                "deny",
                exc.detail,
                subject=subject,
                error_code=exc.code,
            )
            return jsonify(error=exc.code, detail=exc.detail), 403
        except VaultUnavailable as exc:
            # Same stance as a missing policy decision: no answer is not a yes.
            audit("credential", "error", "vault unreachable: %s" % exc, subject=subject)
            return jsonify(error="vault_unavailable", detail=str(exc)), 503

        audit(
            "credential",
            "allow",
            "vault confirmed a live credential carrying the %s policy" % DELETE_POLICY,
            subject=subject,
            ttl_remaining=request.vault_credential.get("ttl"),
        )
        return view(*args, **kwargs)

    return wrapper


@app.get("/health")
def health():
    return jsonify(service="gateway", status="ok")


def fetch(url):
    try:
        response = upstream.get(url, timeout=TIMEOUT)
        return {"status": response.status_code, "data": response.json()}
    except requests.RequestException as exc:
        return {"status": None, "error": str(exc)}


@app.get("/route-test")
@require_token_and_policy
def route_test():
    return jsonify(
        gateway="ok",
        orders=fetch(f"{ORDERS_URL}/orders"),
        inventory=fetch(f"{INVENTORY_URL}/inventory"),
    )


@app.get("/admin/mint-delete-credential")
@require_token_and_policy
def mint_delete_credential_route():
    """Hand a manager a credential good for the next ~20 seconds.

    Guarded by the same decorator as everything else, so OPA decides who may
    ask, and the policy grants this path to the manager role only. A user who
    cannot delete orders cannot mint the credential that permits it either.
    """
    subject = request.token_claims.get("preferred_username")
    try:
        credential, ttl = mint_delete_credential()
    except VaultUnavailable as exc:
        audit("credential", "error", "vault unreachable: %s" % exc, subject=subject)
        return jsonify(error="vault_unavailable", detail=str(exc)), 503

    # The issuance itself is worth a record: it is the moment a standing role
    # became a usable permission. The credential value stays out of the log.
    audit(
        "credential",
        "issue",
        "minted a %s-policy credential" % DELETE_POLICY,
        subject=subject,
        ttl_seconds=ttl,
    )
    return jsonify(
        credential=credential,
        ttl_seconds=ttl,
        expires_at=int(time.time()) + ttl,
        minted_for=request.token_claims.get("preferred_username"),
        usage="send as X-Vault-Credential on POST /orders/delete",
    )


@app.post("/orders/delete")
@require_token_and_policy
@require_vault_credential
def orders_delete():
    """A write-style action behind two independent gates: reaching this function
    means OPA saw a "manager" realm role in the caller's token *and* Vault
    confirmed an unexpired credential scoped to this operation."""
    body = request.get_json(silent=True) or {}
    order_id = body.get("id")
    if order_id is None:
        return jsonify(error="bad_request", detail="body must contain an order id"), 400

    try:
        response = upstream.delete(f"{ORDERS_URL}/orders/{order_id}", timeout=TIMEOUT)
        return jsonify(
            deleted_by=request.token_claims.get("preferred_username"),
            # Seconds the credential had left when it was spent, the number
            # that makes the expiry demo legible.
            credential_ttl_remaining=request.vault_credential.get("ttl"),
            orders={"status": response.status_code, "data": response.json()},
        ), response.status_code
    except requests.RequestException as exc:
        return jsonify(error="upstream_error", detail=str(exc)), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context=mtls_context())
