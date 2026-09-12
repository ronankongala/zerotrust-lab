# Setup

## 1. Start the stack

The services authenticate each other with mutual TLS, and `certs/` is **not in the
repository** — the private keys are deliberately gitignored, so a fresh clone has
none of that material and the stack cannot come up without it. Generate it first:

```bash
./certs/generate.sh
```

That mints the lab CA (`CN=ZeroTrustLab-CA`) and a 4096-bit key and certificate for
`gateway`, `orders` and `inventory`, each carrying the `subjectAltName` its compose
hostname is verified against. Re-running the script leaves existing certificates
alone, so it is safe to repeat; `--force` discards the CA and mints a new one, which
invalidates every certificate under it — restart the stack afterwards
(`docker compose restart gateway orders inventory`) or the containers keep serving
their old identities and every handshake fails verification.

With the certificates in place:

```bash
docker compose up --build
```

This brings up Keycloak (`localhost:8080`), the gateway (`https://localhost:8000`) and the
`orders` / `inventory` services behind it, Open Policy Agent (`localhost:8181`) as the
gateway's decision point, HashiCorp Vault (`localhost:8200`) as the just-in-time
credential issuer, plus two mock SAML service providers: `mock-docs`
(`localhost:9001`) and `mock-dashboard` (`localhost:9002`).

Unlike Keycloak, Vault needs no provisioning step of your own: a one-shot
`vault-init` service configures it on every `up`, and the gateway waits for that
to finish before it starts.

## 2. Provision Keycloak (run once)

`docker compose up` starts Keycloak with an **empty** realm list. The compose file
runs it in dev mode (`start-dev`), where realm configuration lives only in the
`keycloak-data` volume — it is not built from `zerotrust-lab-realm-export.json` at
boot. Nothing in the repo is read by Keycloak on startup, so the realm has to be
pushed in over the Admin REST API:

```bash
./keycloak-setup.py
```

The script waits for Keycloak, authenticates as `admin`/`admin` against the
`master` realm, and then:

- imports `zerotrust-lab-realm-export.json`, creating the `zerotrust-lab` realm,
  `gateway-client`, and the realm/client roles the export carries;
- ensures **Direct access grants** is enabled on `gateway-client` (so you can get
  a token with a plain username/password `POST`);
- creates the `mock-docs-saml` and `mock-dashboard-saml` SAML clients, each
  pointed at its app's ACS URL (`http://localhost:9001/saml/acs` and
  `http://localhost:9002/saml/acs`);
- switches the realm's SAML role mapper to a single multi-valued `Role`
  attribute (see below);
- creates the `manager` realm role that the OPA policy looks for;
- creates two accounts, both with the permanent password `Test1234!`:
  `testuser` (no extra roles) and `manageruser` (holds `manager`) — one for each
  side of the authorization policy;
- prints the `gateway-client` secret for your `.env`.

It is idempotent — re-running it skips the realm import and just reconciles the
client settings, roles and users, so it is safe to run whenever you are unsure of
the state.

### About the client secret

A partial export from the Keycloak admin console masks client secrets as
`**********`, and importing that verbatim would set the literal string as the
secret. The script detects a masked secret and generates a real one, then prints
it. **The secret therefore changes on the first provision of a fresh realm**, so
copy the printed value into `.env` rather than relying on an older one:

```
KEYCLOAK_CLIENT_ID=gateway-client
KEYCLOAK_CLIENT_SECRET=<printed by keycloak-setup.py>
```

Later runs keep the existing secret, since only a masked or empty one is
regenerated.

### When you need to run it again

The realm survives `docker compose restart` and `docker compose down`, because it
is stored in the `keycloak-data` volume. Re-run the script after anything that
discards that volume — `docker compose down -v`, a `docker volume rm`, or a fresh
clone of this repo on another machine.

Overridable via environment: `KEYCLOAK_URL` (default `http://localhost:8080`),
`KEYCLOAK_ADMIN`, `KEYCLOAK_ADMIN_PASSWORD`, `KEYCLOAK_WAIT_TIMEOUT`.

## 3. Smoke test

Get a token with the direct grant and call the gateway:

```bash
token() {  # token <username>
  curl -s -X POST \
    http://localhost:8080/realms/zerotrust-lab/protocol/openid-connect/token \
    -d grant_type=password \
    -d client_id=gateway-client \
    -d client_secret="$KEYCLOAK_CLIENT_SECRET" \
    -d username="$1" \
    -d password='Test1234!' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'
}

TOKEN=$(token testuser)
MANAGER_TOKEN=$(token manageruser)

CERT="--cacert certs/ca.crt --cert certs/gateway.crt --key certs/gateway.key"
GW="--resolve gateway:8000:127.0.0.1 https://gateway:8000"

curl -s $CERT $GW/route-test                                  # 401 (mTLS ok, no token)
curl -s $CERT -H "Authorization: Bearer $TOKEN" $GW/route-test # 200
```

Two things about that invocation:

- **A client cert is required.** `gateway`, `orders` and `inventory` all demand one
  signed by `certs/ca.crt`, so the caller needs an identity of its own. The lab has
  no separate operator cert, so the smoke test reuses `gateway.crt` — any cert the
  CA signed is accepted.
- **`--resolve`, not `localhost`.** `gateway.crt` only carries `DNS:gateway` in its
  SAN, so `https://localhost:8000` fails hostname verification. `--resolve` keeps
  the name the cert claims while still connecting to the published port.

mTLS and the OIDC token are independent layers and both have to pass. Requests that
skip TLS or the client cert now die in the handshake rather than returning a 401:

```bash
curl -s http://localhost:8000/route-test          # empty reply: plain HTTP, no TLS
curl -s --cacert certs/ca.crt $GW/route-test      # alert: certificate required
```

## 4. Fine-grained authorization with OPA

A valid token gets you in the door; it does not decide what you may *do*. That
second question is answered by Open Policy Agent, which runs as its own service
and loads `policies/authz.rego`:

```yaml
opa:
  image: openpolicyagent/opa:latest
  command: ["run", "--server", "--addr=0.0.0.0:8181", "--ignore=*_test.rego", "--watch",
            "--set=decision_logs.console=true", "/policies"]
```

For every request the gateway verifies the token first, then `POST`s the decoded
claims plus the requested method and path to
`http://opa:8181/v1/data/authz/allow`:

```json
{"input": {"authenticated": true, "method": "POST", "path": "/orders/delete",
           "claims": {"preferred_username": "manageruser",
                      "realm_access": {"roles": ["manager"]}}}}
```

The policy denies by default; only two things are allowed:

| Who                           | May do                                     |
| ----------------------------- | ------------------------------------------ |
| any authenticated user        | `GET /route-test` (reads orders + inventory) |
| a user with the `manager` realm role | `POST /orders/delete`                |
| a user with the `manager` realm role | `GET /admin/mint-delete-credential`  |

The three outcomes are deliberately distinguishable at the gateway:

| Status | Body `error`         | Means                                            |
| ------ | -------------------- | ------------------------------------------------ |
| 401    | `unauthorized`       | no token, expired, wrong issuer, bad signature    |
| 403    | `forbidden`          | token is fine, **policy** said no                 |
| 503    | `policy_unavailable` | OPA unreachable — fail closed, never fail open    |

Section 5 adds a second, independent gate in front of `POST /orders/delete` with
error codes of its own, so an OPA denial never gets confused with a Vault one.

### Testing both sides

```bash
# No space inside the JSON: $POST is expanded unquoted below, so a space in the
# body would word-split it into two curl arguments and the request would go out
# with no body at all.
BODY='{"id":1}'
POST="-H Content-Type:application/json -d $BODY"

# testuser: valid token, no manager role -> 403 forbidden
curl -s $CERT -H "Authorization: Bearer $TOKEN" $POST $GW/orders/delete

# manageruser: the policy allows it — but section 5 puts a second gate here, so
# this is now a 403 vault_credential_required, a different error from the one above
curl -s $CERT -H "Authorization: Bearer $MANAGER_TOKEN" $POST $GW/orders/delete

# no token at all -> 401, the policy is never consulted
curl -s $CERT $POST $GW/orders/delete
```

The 403 and the 401 are the point: the first caller proved who they are and was
still refused, because authentication and authorization are separate layers.

You can also query the decision directly, which is useful when a 403 is a
surprise:

```bash
curl -s localhost:8181/v1/data/authz/allow -d '{"input":
  {"authenticated": true, "method": "POST", "path": "/orders/delete",
   "claims": {"realm_access": {"roles": ["manager"]}}}}'   # {"result":true}
```

### Running the policy unit tests

The policy has its own tests in `policies/authz_test.rego` — seven of them, both
sides of each rule plus the default: authenticated read allowed, unauthenticated
read denied, manager delete allowed, non-manager delete denied, manager mint
allowed, non-manager mint denied, and an unknown path denied by the default. They
need no running stack.

With the `opa` binary on your PATH:

```bash
opa test policies/ -v
```

Or without installing anything, using the same image the lab runs:

```bash
docker run --rm -v "$PWD/policies:/policies:ro" openpolicyagent/opa:latest test /policies -v
```

```
PASS: 7/7
```

Edit `policies/authz.rego` and the running OPA picks the change up on its own
(it watches the mounted directory), so the loop is: change the rule, run the
tests, re-run the curl above — no rebuild of the gateway.

## 5. Just-in-time privileged access with Vault

OPA answers a question about identity: *may this user ever delete an order?* It
has no opinion about **when**. A manager therefore carries a standing permission
that a stolen token inherits in full.

HashiCorp Vault adds the missing half. After OPA allows the request, the gateway
demands a second credential in an `X-Vault-Credential` header — one the caller
has to mint deliberately, that lives for **20 seconds**, and that Vault issues
per request. Deleting an order now takes both a role you hold and a credential
you asked for moments ago.

```yaml
vault:
  image: hashicorp/vault:latest
  environment:
    VAULT_DEV_ROOT_TOKEN_ID: ztlab-root-token
  ports: ["8200:8200"]
```

Dev mode, with the root token pinned in the compose file. That is a lab
convenience and nothing else: storage is in memory, Vault starts unsealed, and
the root token is in version control. Every secret is gone when the container
stops.

### What `vault-init` sets up

Dev-mode Vault keeps nothing across restarts, so the configuration is applied by
a one-shot `vault-init` container running `vault/setup.sh` on every
`docker compose up` — you never run it yourself, and `gateway` blocks on it
(`condition: service_completed_successfully`) so it cannot start before the
AppRole exists. The script is idempotent, so re-running it against a live Vault
is safe.

It creates two things:

- a Vault policy named `delete-order`, granting read on `auth/token/lookup-self`
  **and nothing else**;
- an **AppRole** named `delete-order` with `token_ttl = token_max_ttl = 20s` and
  `token_no_default_policy=true`.

AppRole rather than userpass because the client is the gateway — a service, not
a human. `role_id` is the public "who" and `secret_id` the private proof, the
same split as an OAuth `client_id`/`client_secret`; both are pinned to fixed
values so the gateway can be configured from a static compose file.

Two details carry most of the security story:

- **The credential can do nothing.** Its one capability is to look itself up. It
  is not a key to a secret — it is evidence that someone with the manager role
  asked for permission in the last 20 seconds, and the gateway treats it as
  exactly that.
- **`token_max_ttl` equals `token_ttl`**, so it cannot be renewed past 20
  seconds. There is no way to hold one open.

The gateway holds no Vault token of its own — no root token, no standing
privilege it could lend to a request. All it has is the AppRole, and all the
AppRole buys is a credential that expires on its own.

### Minting a credential

`GET /admin/mint-delete-credential` goes through the *same* OPA decorator as
every other route, and the policy grants that path to the `manager` role only —
a user who may not delete orders may not mint the credential that permits it
either:

```bash
curl -s $CERT -H "Authorization: Bearer $TOKEN" $GW/admin/mint-delete-credential
# {"error":"forbidden","detail":"policy denied GET /admin/mint-delete-credential", ...}

curl -s $CERT -H "Authorization: Bearer $MANAGER_TOKEN" $GW/admin/mint-delete-credential
```

```json
{"credential": "hvs.CAESIIXaZ-KkqVshFehsspABDy0GTyQknzg2ZpGDYjkY...",
 "ttl_seconds": 20, "expires_at": 1789250536, "minted_for": "manageruser",
 "usage": "send as X-Vault-Credential on POST /orders/delete"}
```

### How the gateway checks it

On `POST /orders/delete`, once OPA has allowed the request, the gateway calls
Vault's `auth/token/lookup-self` with the presented credential and requires two
things: that Vault still recognises it, and that it carries the `delete-order`
policy. The second check is what stops any *other* live Vault credential — the
root token included — from standing in for one.

Expiry is Vault's answer, not a clock comparison in the gateway, so a credential
that was revoked early fails exactly as fast as one that timed out.

### Using one inside its TTL, and watching it expire

```bash
mint() {
  curl -s $CERT -H "Authorization: Bearer $MANAGER_TOKEN" \
    $GW/admin/mint-delete-credential \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["credential"])'
}

CRED=$(mint)

# Inside the TTL: both gates pass, order 2 is gone.
curl -s $CERT -H "Authorization: Bearer $MANAGER_TOKEN" \
     -H "X-Vault-Credential: $CRED" $POST $GW/orders/delete
```

```json
{"deleted_by": "manageruser", "credential_ttl_remaining": 20,
 "orders": {"status": 200, "data": {"deleted": {"id": 2, ...}, "remaining": 2}}}
```

`credential_ttl_remaining` is the seconds Vault had left on it at the moment it
was spent. Now wait for it to lapse and send **the same credential** again:

```bash
CRED=$(mint)
sleep 25
curl -s $CERT -H "Authorization: Bearer $MANAGER_TOKEN" \
     -H "X-Vault-Credential: $CRED" $POST $GW/orders/delete
```

```json
{"error": "vault_credential_invalid",
 "detail": "vault rejected the credential in X-Vault-Credential (expired, revoked, malformed, or never issued): 2 errors occurred:\n\t* permission denied\n\t* invalid token"}
```

Nothing about the caller changed between those two requests. The token is the
same, the manager role is the same, OPA allowed both — only the clock moved.
That is the property Vault is adding: *authorization with an expiry date*.

Vault will not say which of expired / revoked / never-issued it was, because it
does not disclose that to an unauthenticated caller. An expired token is simply
gone.

### Telling the denials apart

Every failure mode returns a distinct `error` code, so a 403 never leaves you
guessing which layer refused:

| Status | Body `error`                   | Means                                                        |
| ------ | ------------------------------ | ------------------------------------------------------------ |
| 401    | `unauthorized`                 | no/expired/bad OIDC token — never reaches OPA                 |
| 403    | `forbidden`                    | **OPA** said no: the identity lacks the `manager` role        |
| 403    | `vault_credential_required`    | OPA allowed it; no `X-Vault-Credential` header was sent       |
| 403    | `vault_credential_invalid`     | credential expired, revoked, malformed, or never issued       |
| 403    | `vault_credential_out_of_scope`| a live Vault token, but not one scoped to `delete-order`      |
| 503    | `policy_unavailable`           | OPA unreachable — fail closed                                 |
| 503    | `vault_unavailable`            | Vault unreachable — fail closed                               |

The ordering is deliberate: OPA runs first, so a non-manager never learns that a
Vault gate exists. Worth trying by hand:

```bash
# manager, no credential -> 403 vault_credential_required
curl -s $CERT -H "Authorization: Bearer $MANAGER_TOKEN" $POST $GW/orders/delete

# non-manager holding a perfectly valid credential -> 403 forbidden (OPA, first gate)
curl -s $CERT -H "Authorization: Bearer $TOKEN" \
     -H "X-Vault-Credential: $(mint)" $POST $GW/orders/delete

# manager presenting the root token -> 403 vault_credential_out_of_scope
curl -s $CERT -H "Authorization: Bearer $MANAGER_TOKEN" \
     -H "X-Vault-Credential: ztlab-root-token" $POST $GW/orders/delete

# both gates down-stack: stop Vault and watch it fail closed, not open
docker compose stop vault
curl -s $CERT -H "Authorization: Bearer $MANAGER_TOKEN" \
     -H "X-Vault-Credential: $CRED" $POST $GW/orders/delete   # 503 vault_unavailable
docker compose start vault && docker compose up -d vault-init
```

That last pair matters: restarting dev-mode Vault wipes the AppRole with
everything else, so `vault-init` has to run again before minting works. Any
credential minted before the restart is gone too.

### Poking at Vault directly

The root token is fixed, so the CLI works from the host without a login:

```bash
export VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=ztlab-root-token
vault read auth/approle/role/delete-order      # token_ttl / token_policies
vault policy read delete-order
vault token lookup "$CRED"                     # ttl counting down, policies
```

`vault token lookup` against a credential you just minted, run twice a few
seconds apart, shows the TTL falling — the clearest view of what the gateway is
checking on every delete.

## 6. Decision logging

Every gate the gateway applies now writes one JSON object per line to stdout, so
`docker compose logs gateway` shows what was decided and why. The emitter is
`audit()` in `gateway/app.py`; it is about twenty lines of `print(json.dumps(...))`
with `flush=True`, not a logging framework. The record it builds has this shape
(keys are sorted, so a line always reads in the same order):

```json
{"decision": "deny", "event": "policy", "method": "POST", "path": "/orders/delete",
 "reason": "OPA returned allow=false", "roles": ["default-roles-zerotrust-lab",
 "offline_access", "uma_authorization"], "subject": "testuser",
 "ts": "2026-09-12T20:31:04.882+00:00"}
```

`event` names the gate that spoke and `decision` is what it said:

| `event` | `decision` values | Emitted from |
| --- | --- | --- |
| `token` | `allow`, `deny` | `require_token_and_policy`, on signature/issuer/expiry |
| `policy` | `allow`, `deny`, `error` | the same decorator, around the OPA call |
| `credential` | `allow`, `deny`, `error`, `issue` | `require_vault_credential`, plus `issue` at the mint route |

A single `POST /orders/delete` by a manager therefore leaves three lines — `token
allow`, `policy allow`, `credential allow` — and a refusal leaves the prefix up to
whichever gate closed. `subject` is the token's `preferred_username`, and `roles`
carries `realm_access.roles`, which is the claim the policy actually turns on, so a
deny is explicable from the log alone.

**Tokens, credentials and keys are never logged.** The mint route records that a
credential was issued and its TTL, not its value.

OPA logs the other half. `--set=decision_logs.console=true` (section 4) makes it
emit the decision itself — the full input it was given and the result it returned —
rather than only the fact that `/v1/data/authz/allow` was served:

```bash
docker compose logs opa | grep decision_id
```

Watch both while you drive a request:

```bash
docker compose logs -f gateway opa
```

This is stdout and nothing more: no aggregation, no retention beyond the container's
lifetime, no alerting, no correlation ID tying a gateway line to its OPA counterpart.
See `ZERO_TRUST_MAPPING.md` tenets 5 and 7 for what it does and does not establish.

## 7. SAML single sign-on (mock-docs and mock-dashboard)

Two throwaway Flask apps sit alongside the gateway as SAML 2.0 **service
providers**. Both trust the same `zerotrust-lab` realm, so signing into one signs
you into the other.

| App              | URL                     | Keycloak client        | Shows            |
| ---------------- | ----------------------- | ---------------------- | ---------------- |
| `mock-docs`      | `http://localhost:9001` | `mock-docs-saml`       | "Internal Docs"  |
| `mock-dashboard` | `http://localhost:9002` | `mock-dashboard-saml`  | "Demo Dashboard" |

Keycloak uses a SAML client's **clientId as the SP entity ID**, so `mock-docs-saml`
is both the client name and the issuer the app sends. The port only shows up in
the ACS and redirect URLs.

Neither app ships a keypair: the clients are created with client signature
verification off, so Keycloak signs its assertions but does not expect signed
`AuthnRequest`s. Each app fetches the realm's signing certificate at runtime from
`http://keycloak:8080/realms/zerotrust-lab/protocol/saml/descriptor`, because that
key is regenerated every time the realm is imported and so cannot be baked into
the image.

### Testing SSO

Use a **fresh browser profile or a private window**, so you start with no
Keycloak session.

1. Visit <http://localhost:9001/>. You are redirected to Keycloak and prompted to
   log in. Use `testuser` / `Test1234!`.
2. You land back on **Internal Docs**, showing `Signed in as Test User`.
3. Now visit <http://localhost:9002/> in the *same* browser.
4. **No second login prompt appears.** The page renders straight as **Demo
   Dashboard**, again showing `Signed in as Test User`.

Step 4 is the whole point: the browser still bounces through Keycloak (watch the
address bar flick through `localhost:8080`), but because the realm session cookie
from step 1 is still valid, Keycloak issues a new assertion immediately instead of
asking for credentials. It works in either order — start on 9002 and 9001 becomes
the silent one.

To repeat the demo, clear cookies for `localhost` or open a new private window.
Each app's `/logout` only drops its *own* session, deliberately leaving the
Keycloak realm session intact — so after a local logout you will still be signed
back in silently.

### Why the apps have different session cookie names

Browser cookies are scoped to a host, not a port, so `localhost:9001` and
`localhost:9002` share one cookie jar. The apps therefore use distinct cookie
names (`mock_docs_session`, `mock_dashboard_session`) and distinct secret keys.
Without that, the second app would simply read the first app's session cookie and
look logged in without ever contacting Keycloak — which would make the SSO demo
prove nothing.

### The single `Role` attribute

Out of the box Keycloak's `role_list` mapper emits one `<Attribute Name="Role">`
element per role. Strict SAML SPs — `python3-saml` included — reject an assertion
containing duplicated attribute names, and login fails with *"Found an Attribute
element with duplicated Name"*. `keycloak-setup.py` sets that mapper's **Single
Role Attribute** option so all roles arrive in one multi-valued attribute. The
realm has no other SAML clients, so the change is safe realm-wide.

