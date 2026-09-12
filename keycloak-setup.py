#!/usr/bin/env python3
"""Provision the Zero Trust lab's Keycloak realm via the Admin REST API.

Run once after `docker compose up`. Safe to re-run: the realm import is skipped
if the realm already exists, and everything else is reconciled in place.

Only the standard library is used so this can run without a virtualenv.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN", "admin")
ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")

REALM = "zerotrust-lab"
CLIENT_ID = "gateway-client"

# The realm role OPA looks for in a token before allowing a write/delete action.
# It is not in the realm export, so it is created here.
MANAGER_ROLE = "manager"
LAB_REALM_ROLES = [
    {
        "name": MANAGER_ROLE,
        "description": "May perform write/delete actions through the gateway",
    },
]

USER_PASSWORD = "Test1234!"

# Two accounts so both sides of the policy can be exercised: testuser has a
# perfectly valid token and is still refused POST /orders/delete, manageruser is
# allowed. That difference is the whole point of the OPA layer.
USERS = [
    {
        "profile": {
            "username": "testuser",
            "firstName": "Test",
            "lastName": "User",
            "email": "testuser@zerotrust.lab",
            "emailVerified": True,
            "enabled": True,
        },
        "password": USER_PASSWORD,
        "realm_roles": [],
    },
    {
        "profile": {
            "username": "manageruser",
            "firstName": "Manager",
            "lastName": "User",
            "email": "manageruser@zerotrust.lab",
            "emailVerified": True,
            "enabled": True,
        },
        "password": USER_PASSWORD,
        "realm_roles": [MANAGER_ROLE],
    },
]

# The two mock SAML service providers. Keycloak uses a SAML client's clientId as
# the SP entity ID, so these names are also what each app sends as its issuer.
SAML_CLIENTS = [
    {"client_id": "mock-docs-saml", "name": "Mock Docs (SAML)", "base_url": "http://localhost:9001"},
    {"client_id": "mock-dashboard-saml", "name": "Mock Dashboard (SAML)", "base_url": "http://localhost:9002"},
]

EXPORT_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "zerotrust-lab-realm-export.json"
)

WAIT_TIMEOUT = int(os.environ.get("KEYCLOAK_WAIT_TIMEOUT", "180"))
HTTP_TIMEOUT = 30


def log(message):
    print(message, flush=True)


def die(message):
    print("error: " + message, file=sys.stderr, flush=True)
    sys.exit(1)


def request(method, url, body=None, headers=None, form=False, timeout=HTTP_TIMEOUT):
    """Return (status, decoded_body). Non-2xx responses are returned, not raised."""
    headers = dict(headers or {})
    data = None
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code

    text = raw.decode("utf-8", "replace").strip()
    if not text:
        return status, None
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text


class Admin:
    """Admin REST client that re-authenticates as its token nears expiry.

    Tokens issued by the master realm are short-lived (60s by default), which is
    easily shorter than a first-time realm import takes.
    """

    def __init__(self):
        self._token = None
        self._expires_at = 0.0

    def login(self):
        status, body = request(
            "POST",
            BASE_URL + "/realms/master/protocol/openid-connect/token",
            body={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": ADMIN_USER,
                "password": ADMIN_PASSWORD,
            },
            form=True,
        )
        if status != 200 or not isinstance(body, dict) or "access_token" not in body:
            die(
                "could not get an admin token for realm 'master' as user "
                "'%s' (HTTP %s): %s" % (ADMIN_USER, status, body)
            )
        self._token = body["access_token"]
        # Renew early so a long call can't run past the token's lifetime.
        self._expires_at = time.time() + max(int(body.get("expires_in", 60)) - 15, 5)
        return self._token

    def token(self):
        if self._token is None or time.time() >= self._expires_at:
            return self.login()
        return self._token

    def call(self, method, path, body=None):
        url = BASE_URL + path
        headers = {"Authorization": "Bearer " + self.token()}
        return request(method, url, body=body, headers=headers)

    def expect(self, method, path, body=None, ok=(200, 201, 204), what=""):
        status, response = self.call(method, path, body)
        if status not in ok:
            die("%s failed (HTTP %s): %s" % (what or (method + " " + path), status, response))
        return response


def wait_for_keycloak():
    log("waiting for Keycloak at %s ..." % BASE_URL)
    deadline = time.time() + WAIT_TIMEOUT
    last = None
    while time.time() < deadline:
        try:
            status, _ = request("GET", BASE_URL + "/realms/master", timeout=5)
            if status == 200:
                log("  Keycloak is up")
                return
            last = "HTTP %s" % status
        except Exception as exc:  # connection refused / DNS / reset while booting
            last = type(exc).__name__ + ": " + str(exc)
        time.sleep(2)
    die("Keycloak was not reachable at %s within %ss (last: %s)" % (BASE_URL, WAIT_TIMEOUT, last))


def load_export():
    if not os.path.exists(EXPORT_FILE):
        die("realm export not found: %s" % EXPORT_FILE)
    try:
        with open(EXPORT_FILE, encoding="utf-8") as handle:
            realm = json.load(handle)
    except ValueError as exc:
        die("realm export is not valid JSON (%s): %s" % (EXPORT_FILE, exc))
    if realm.get("realm") != REALM:
        die(
            "realm export declares realm %r but this script provisions %r"
            % (realm.get("realm"), REALM)
        )
    return realm


def import_realm(admin, realm_export):
    status, _ = admin.call("GET", "/admin/realms/" + REALM)
    if status == 200:
        log("realm '%s' already exists, skipping import" % REALM)
        return False
    if status != 404:
        die("could not check whether realm '%s' exists (HTTP %s)" % (REALM, status))

    log("importing realm '%s' from %s ..." % (REALM, os.path.basename(EXPORT_FILE)))
    status, body = admin.call("POST", "/admin/realms", realm_export)
    if status == 409:
        # Created by a concurrent run between the check above and this call.
        log("  realm '%s' already exists, skipping import" % REALM)
        return False
    if status not in (201, 204):
        die("realm import failed (HTTP %s): %s" % (status, body))
    log("  realm '%s' created" % REALM)
    return True


def ensure_realm_roles(admin, realm_export):
    """Create any realm role that is missing.

    The export's own roles only matter when the realm pre-dates this script (a
    fresh import already carries them); LAB_REALM_ROLES is always created here,
    since "manager" exists for this lab rather than for Keycloak.
    """
    wanted = (realm_export.get("roles", {}).get("realm", []) or []) + LAB_REALM_ROLES
    existing = admin.expect(
        "GET", "/admin/realms/%s/roles?briefRepresentation=true&max=1000" % REALM,
        what="listing realm roles",
    ) or []
    have = {role["name"] for role in existing}
    for role in wanted:
        if role["name"] in have:
            continue
        payload = {"name": role["name"], "composite": False, "clientRole": False}
        if role.get("description"):
            payload["description"] = role["description"]
        status, body = admin.call("POST", "/admin/realms/%s/roles" % REALM, payload)
        if status in (201, 409):
            log("  realm role '%s' ensured" % role["name"])
        else:
            die("could not create realm role '%s' (HTTP %s): %s" % (role["name"], status, body))


def find_client(admin, client_id):
    found = admin.expect(
        "GET",
        "/admin/realms/%s/clients?clientId=%s" % (REALM, urllib.parse.quote(client_id)),
        what="looking up client '%s'" % client_id,
    ) or []
    for client in found:
        if client.get("clientId") == client_id:
            return client
    return None


def ensure_client(admin, realm_export):
    """Make sure gateway-client exists and has direct access grants enabled."""
    client = find_client(admin, CLIENT_ID)

    if client is None:
        template = None
        for candidate in realm_export.get("clients", []):
            if candidate.get("clientId") == CLIENT_ID:
                template = dict(candidate)
                break
        if template is None:
            die("client '%s' is missing from both Keycloak and the realm export" % CLIENT_ID)
        # Let Keycloak assign the id and the secret rather than reusing the
        # export's (the export masks secrets).
        template.pop("id", None)
        template.pop("secret", None)
        template["directAccessGrantsEnabled"] = True
        template["enabled"] = True
        admin.expect(
            "POST", "/admin/realms/%s/clients" % REALM, template,
            ok=(201,), what="creating client '%s'" % CLIENT_ID,
        )
        log("client '%s' created" % CLIENT_ID)
        client = find_client(admin, CLIENT_ID)
        if client is None:
            die("client '%s' was created but could not be read back" % CLIENT_ID)
        return client

    if client.get("directAccessGrantsEnabled") and client.get("enabled"):
        log("client '%s' already has direct access grants enabled" % CLIENT_ID)
        return client

    update = dict(client)
    update["directAccessGrantsEnabled"] = True
    update["enabled"] = True
    admin.expect(
        "PUT", "/admin/realms/%s/clients/%s" % (REALM, client["id"]), update,
        what="enabling direct access grants on '%s'" % CLIENT_ID,
    )
    log("client '%s': direct access grants enabled" % CLIENT_ID)
    return update


def ensure_client_roles(admin, realm_export, client):
    """Create any gateway-client role from the export that is missing."""
    wanted = realm_export.get("roles", {}).get("client", {}).get(CLIENT_ID, []) or []
    if not wanted:
        return
    base = "/admin/realms/%s/clients/%s/roles" % (REALM, client["id"])
    existing = admin.expect(
        "GET", base + "?briefRepresentation=true&max=1000",
        what="listing roles of '%s'" % CLIENT_ID,
    ) or []
    have = {role["name"] for role in existing}
    for role in wanted:
        if role["name"] in have:
            continue
        payload = {"name": role["name"], "composite": False, "clientRole": True}
        if role.get("description"):
            payload["description"] = role["description"]
        status, body = admin.call("POST", base, payload)
        if status in (201, 409):
            log("  client role '%s:%s' ensured" % (CLIENT_ID, role["name"]))
        else:
            die("could not create client role '%s' (HTTP %s): %s" % (role["name"], status, body))


def saml_client_payload(spec):
    """A SAML SP client the mock apps can authenticate against.

    Client signature verification is off, so neither app needs a keypair of its
    own; Keycloak still signs its assertions, which is what the apps verify.
    """
    acs_url = spec["base_url"] + "/saml/acs"
    return {
        "clientId": spec["client_id"],
        "name": spec["name"],
        "protocol": "saml",
        "enabled": True,
        "frontchannelLogout": True,
        "adminUrl": acs_url,
        "redirectUris": [spec["base_url"] + "/saml/*"],
        "attributes": {
            "saml_assertion_consumer_url_post": acs_url,
            "saml_assertion_consumer_url_redirect": acs_url,
            "saml.assertion.signature": "true",
            "saml.server.signature": "true",
            "saml.signature.algorithm": "RSA_SHA256",
            "saml.client.signature": "false",
            "saml.authnstatement": "true",
            "saml.force.post.binding": "true",
            "saml.encrypt": "false",
            "saml_name_id_format": "username",
            "saml_force_name_id_format": "true",
        },
    }


def saml_mappers():
    """Attributes the apps read to greet the user by name."""
    def prop(name, user_attribute, attribute_name):
        return {
            "name": name,
            "protocol": "saml",
            "protocolMapper": "saml-user-property-mapper",
            "config": {
                "user.attribute": user_attribute,
                "friendly.name": attribute_name,
                "attribute.name": attribute_name,
                "attribute.nameformat": "Basic",
            },
        }

    return [
        prop("username", "username", "username"),
        prop("given name", "firstName", "givenName"),
        prop("family name", "lastName", "surname"),
        prop("email", "email", "email"),
    ]


def ensure_protocol_mappers(admin, client, mappers):
    base = "/admin/realms/%s/clients/%s/protocol-mappers/models" % (REALM, client["id"])
    existing = admin.expect(
        "GET", base, what="listing protocol mappers of '%s'" % client["clientId"]
    ) or []
    have = {mapper["name"] for mapper in existing}
    for mapper in mappers:
        if mapper["name"] in have:
            continue
        status, body = admin.call("POST", base, mapper)
        if status not in (201, 409):
            die(
                "could not add mapper '%s' to '%s' (HTTP %s): %s"
                % (mapper["name"], client["clientId"], status, body)
            )
        log("  mapper '%s' added" % mapper["name"])


def ensure_single_role_attribute(admin):
    """Make the realm's SAML role mapper emit one multi-valued Role attribute.

    By default Keycloak emits a separate <Attribute Name="Role"> element per
    role. Strict SAML SPs (python3-saml among them) reject an assertion with
    duplicated attribute names, so the mock apps cannot log in until this is
    flipped. The realm has no other SAML clients, so this is safe to set here.
    """
    scopes = admin.expect(
        "GET", "/admin/realms/%s/client-scopes" % REALM, what="listing client scopes"
    ) or []
    scope = next((s for s in scopes if s.get("name") == "role_list"), None)
    if scope is None:
        log("client scope 'role_list' not found, skipping role attribute fix")
        return

    base = "/admin/realms/%s/client-scopes/%s/protocol-mappers/models" % (REALM, scope["id"])
    mappers = admin.expect("GET", base, what="listing 'role_list' mappers") or []
    for mapper in mappers:
        if mapper.get("protocolMapper") != "saml-role-list-mapper":
            continue
        config = dict(mapper.get("config") or {})
        if config.get("single") == "true":
            log("SAML role list already emits a single multi-valued attribute")
            return
        config["single"] = "true"
        update = dict(mapper, config=config)
        admin.expect(
            "PUT", base + "/" + mapper["id"], update,
            what="setting 'single' on the SAML role list mapper",
        )
        log("SAML role list set to a single multi-valued attribute")
        return


def ensure_saml_clients(admin):
    """Create/reconcile the SAML clients for mock-docs and mock-dashboard."""
    for spec in SAML_CLIENTS:
        client_id = spec["client_id"]
        payload = saml_client_payload(spec)
        existing = find_client(admin, client_id)

        if existing is None:
            admin.expect(
                "POST", "/admin/realms/%s/clients" % REALM, payload,
                ok=(201,), what="creating SAML client '%s'" % client_id,
            )
            log("SAML client '%s' created (ACS %s)" % (client_id, payload["adminUrl"]))
            existing = find_client(admin, client_id)
            if existing is None:
                die("SAML client '%s' was created but could not be read back" % client_id)
        else:
            # Merge onto what is there so unrelated settings Keycloak filled in
            # are kept, then push our ACS/entity-ID expectations back over them.
            update = dict(existing)
            update.update(payload)
            update["attributes"] = dict(existing.get("attributes") or {})
            update["attributes"].update(payload["attributes"])
            # Mappers are reconciled separately; a client PUT does not sync them.
            update.pop("protocolMappers", None)
            admin.expect(
                "PUT", "/admin/realms/%s/clients/%s" % (REALM, existing["id"]), update,
                what="updating SAML client '%s'" % client_id,
            )
            log("SAML client '%s' already exists, settings reconciled" % client_id)

        ensure_protocol_mappers(admin, existing, saml_mappers())


def realm_role(admin, name):
    """The full role representation, which is what a role mapping POST needs."""
    return admin.expect(
        "GET", "/admin/realms/%s/roles/%s" % (REALM, urllib.parse.quote(name)),
        what="reading realm role '%s'" % name,
    )


def ensure_realm_role_mapping(admin, user, role_names):
    if not role_names:
        return
    base = "/admin/realms/%s/users/%s/role-mappings/realm" % (REALM, user["id"])
    assigned = admin.expect(
        "GET", base, what="listing realm roles of '%s'" % user["username"]
    ) or []
    have = {role["name"] for role in assigned}
    missing = [realm_role(admin, name) for name in role_names if name not in have]
    if not missing:
        log("  realm roles already assigned: %s" % ", ".join(role_names))
        return
    admin.expect(
        "POST", base, missing, ok=(201, 204),
        what="assigning realm roles to '%s'" % user["username"],
    )
    log("  realm roles assigned: %s" % ", ".join(role["name"] for role in missing))


def ensure_user(admin, spec):
    profile = spec["profile"]
    username = profile["username"]
    query = "/admin/realms/%s/users?username=%s&exact=true" % (
        REALM, urllib.parse.quote(username),
    )
    matches = admin.expect("GET", query, what="looking up user '%s'" % username) or []
    user = next((u for u in matches if u.get("username") == username), None)

    if user is None:
        admin.expect(
            "POST", "/admin/realms/%s/users" % REALM, dict(profile),
            ok=(201,), what="creating user '%s'" % username,
        )
        matches = admin.expect("GET", query, what="re-reading user '%s'" % username) or []
        user = next((u for u in matches if u.get("username") == username), None)
        if user is None:
            die("user '%s' was created but could not be read back" % username)
        log("user '%s' created" % username)
    else:
        update = dict(user)
        update.update(profile)
        # Leftover actions such as UPDATE_PASSWORD would block a direct grant.
        update["requiredActions"] = []
        admin.expect(
            "PUT", "/admin/realms/%s/users/%s" % (REALM, user["id"]), update,
            what="updating user '%s'" % username,
        )
        log("user '%s' already exists, profile reconciled" % username)

    admin.expect(
        "PUT",
        "/admin/realms/%s/users/%s/reset-password" % (REALM, user["id"]),
        {"type": "password", "value": spec["password"], "temporary": False},
        what="setting the password for '%s'" % username,
    )
    log("  password set (permanent)")
    ensure_realm_role_mapping(admin, user, spec["realm_roles"])
    return user


def is_usable_secret(value):
    """A console partial-export masks secrets as '**********'.

    Imported verbatim, that becomes the client's literal secret, so treat any
    all-asterisk (or empty) value as unusable and regenerate.
    """
    if not value:
        return False
    return set(value) != {"*"}


def client_secret(admin, client):
    path = "/admin/realms/%s/clients/%s/client-secret" % (REALM, client["id"])

    if client.get("publicClient"):
        return None

    body = admin.expect("GET", path, what="reading the secret of '%s'" % CLIENT_ID)
    value = (body or {}).get("value")

    if not is_usable_secret(value):
        log(
            "client '%s' has a masked/empty secret (the realm export does not "
            "carry real secrets), regenerating ..." % CLIENT_ID
        )
        body = admin.expect(
            "POST", path, ok=(200, 201),
            what="regenerating the secret of '%s'" % CLIENT_ID,
        )
        value = (body or {}).get("value")
        if not is_usable_secret(value):
            die("Keycloak returned no usable secret for '%s'" % CLIENT_ID)

    return value


def main():
    wait_for_keycloak()

    realm_export = load_export()

    admin = Admin()
    admin.login()
    log("authenticated as '%s' on realm 'master'" % ADMIN_USER)

    import_realm(admin, realm_export)
    ensure_realm_roles(admin, realm_export)
    client = ensure_client(admin, realm_export)
    ensure_client_roles(admin, realm_export, client)
    ensure_single_role_attribute(admin)
    ensure_saml_clients(admin)
    for spec in USERS:
        ensure_user(admin, spec)

    secret = client_secret(admin, client)

    log("")
    log("=" * 62)
    log("Keycloak is provisioned.")
    log("")
    log("  realm:    %s" % REALM)
    log("  client:   %s" % CLIENT_ID)
    log("  SAML SPs: %s" % ", ".join(c["client_id"] for c in SAML_CLIENTS))
    for spec in USERS:
        roles = spec["realm_roles"]
        log(
            "  user:     %s / %s%s"
            % (
                spec["profile"]["username"],
                spec["password"],
                ("  (realm roles: %s)" % ", ".join(roles)) if roles else "",
            )
        )
    log("")
    if secret is None:
        log("  '%s' is a public client, so it has no secret." % CLIENT_ID)
    else:
        log("Copy this into your .env:")
        log("")
        log("  KEYCLOAK_CLIENT_ID=%s" % CLIENT_ID)
        log("  KEYCLOAK_CLIENT_SECRET=%s" % secret)
    log("=" * 62)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("interrupted")
