# NIST SP 800-207 Tenet Mapping

Maps each of the seven Zero Trust Architecture tenets (NIST SP 800-207 §2.1) to the
mechanism that implements it in this repo, with the file and line that carries it.

**How the evidence was produced.** Responses quoted below were captured on
2026-09-12 against the running stack (`docker compose ps`: gateway, orders,
inventory, opa, vault, keycloak, mock-docs, mock-dashboard all up), using the
smoke-test invocation from `SETUP.md` §3: a CA-signed client cert plus
`--resolve gateway:8000:127.0.0.1`. Tokens were obtained by direct grant for
`testuser` and `manageruser`. Anything not verified that way is marked as such.

**Verified.** The audit logging described under tenets 5 and 7 (`audit()` in
`gateway/app.py`, and OPA's `--set=decision_logs.console=true`) was added after the run
above and has since been executed against a rebuilt gateway:

- `opa test policies/ -v` reported `PASS: 7/7`.
- One allowed `GET /route-test` and one denied `POST /orders/delete` were driven through
  the rebuilt gateway. The gateway's log carried the expected JSON lines:
  `{"decision":"allow","event":"token",...}` then `{"decision":"allow","event":"policy",...}`
  for the GET, and `{"decision":"allow","event":"token",...}` then
  `{"decision":"deny","event":"policy","reason":"OPA returned allow=false",...}` for the POST.
- `docker compose logs opa | grep decision_id` showed the matching decisions, with
  `"result":true` and `"result":false` respectively.

That confirms the two emitters produce the records described below, and that the PDP's
answer is auditable independently of the PEP that asked. It confirms nothing further:
this is still `print()` to stdout with no aggregation, retention or alerting, as tenet 7
states.

A later full re-run on the same date exercised the remaining paths, including the
`credential` events the earlier run never reached: `docker compose logs gateway`
recorded `credential`/`issue` on a mint, `credential`/`allow` on a delete inside the
TTL, and `credential`/`deny` both for a missing `X-Vault-Credential` header and for a
credential replayed after it expired.

Each tenet also records what is **not** implemented. Several tenets are only
partially met; tenets 5 and 7 are substantially unmet, and saying otherwise would
misrepresent the lab.

---

## Tenet 1: All data sources and computing services are considered resources

**Mechanism: per-service X.509 identity + no direct network reachability.**

`orders` and `inventory` publish no host ports at all. `docker-compose.yml:112-126`
declares them with only a `./certs:/certs:ro` mount and the `ztlab-net` bridge, and
`docker compose ps` reports them as `5000/tcp` (container-internal) while every other
service shows a `0.0.0.0:...->` mapping. They are reachable only as resources behind
the gateway, never as hosts on a network.

Each service carries its own identity rather than inheriting the network's:

| File | Subject | SAN | Issuer |
| --- | --- | --- | --- |
| `certs/gateway.crt` | `CN=gateway` | `DNS:gateway` | `CN=ZeroTrustLab-CA` |
| `certs/orders.crt` | `CN=orders` | `DNS:orders` | `CN=ZeroTrustLab-CA` |
| `certs/inventory.crt` | `CN=inventory` | `DNS:inventory` | `CN=ZeroTrustLab-CA` |

Resources are named individually in policy by method+path, not by host or subnet.
`policies/authz.rego` has separate rules for `/route-test` (line 24), `/orders/delete`
(line 33) and `/admin/mint-delete-credential` (line 43).

The control-plane components are treated as resources too: Vault is addressed through
an AppRole identity the gateway holds (`VAULT_ROLE_ID` / `VAULT_SECRET_ID`,
`docker-compose.yml:17-18`), and OPA's policy directory is mounted read-only
(`docker-compose.yml:108`) so the PDP cannot rewrite what it enforces.

**Not implemented.** OPA (`:8181`) and Vault (`:8200`) are published to the host and
spoken to over plain HTTP inside the network (`gateway/app.py:98-99`, `209-216`), so
those two resources are identified but not cryptographically protected in transit.

---

## Tenet 2: All communication is secured regardless of network location

**Mechanism: mutual TLS with `ssl.CERT_REQUIRED` on every application listener,
including the ones that only ever hear from a peer on the same private bridge.**

`gateway/app.py:61-70` (`mtls_context()`) builds the server context:

```python
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
context.load_verify_locations(cafile=TLS_CA)          # /certs/ca.crt
context.verify_mode = ssl.CERT_REQUIRED               # makes it mutual
```

The identical function appears in `orders/app.py:12-21` and `inventory/app.py:12-21`.
That is the "regardless of network location" part: `orders` sits on a private Docker
network with no published port and still refuses a handshake from a client the lab CA
did not sign.

Outbound calls are the other half: `gateway/app.py:76-78` pins a client cert and CA
bundle on the upstream session:

```python
upstream.cert = (TLS_CERT, TLS_KEY)
upstream.verify = TLS_CA
```

Hostname verification is left on, which is why `docker-compose.yml:9-10` sets
`ORDERS_URL: https://orders:5000`, because the name has to match `DNS:orders` in the SAN.
The CA bundle is mounted read-only at `docker-compose.yml:22`, `116` and `124`, with
the reasoning stated in the file: a container that can rewrite the bundle it validates
against can trust anything it likes.

**Verified this session:**

```
$ curl -s http://localhost:8000/route-test
curl exit 52 (empty reply), no plaintext listener exists

$ curl -sS --cacert certs/ca.crt --resolve gateway:8000:127.0.0.1 https://gateway:8000/route-test
curl: (56) OpenSSL SSL_read: error:0A00045C:SSL routines::tlsv13 alert certificate required
```

The second refusal happens in the TLS handshake, so no Flask route runs and there is no
401 to report. That is the distinction the tenet is after.

**Not implemented.** Gateway↔OPA and gateway↔Vault are plain HTTP. Keycloak runs
`start-dev` on HTTP (`docker-compose.yml:169`), and the realm export sets
`"sslRequired":"external"`.

---

## Tenet 3: Access to individual enterprise resources is granted on a per-session basis

**Mechanism: a stateless gateway plus two independent expiry clocks: a 300-second
OIDC access token and a 20-second Vault credential.**

*Token clock.* `zerotrust-lab-realm-export.json` sets `"accessTokenLifespan":300`.
Confirmed on a live token issued this session: `exp - iat = 300`. The gateway refuses
to accept a token that does not carry an expiry at all:
`gateway/app.py:156` passes `options={"verify_aud": False, "require": ["exp", "iss"]}`
to `jwt.decode`, and maps a lapsed one to a 401 at `gateway/app.py:158-160`.

*No session state.* `require_token_and_policy` (`gateway/app.py:141-199`) re-runs
signature verification and the policy call on every request. The gateway holds no
cookie, no server-side session table and no authorization cache; the only thing kept
between requests is the JWK set (`gateway/app.py:93`, `lifespan=300`), which is key
material, not an access decision.

*Credential clock.* The destructive path narrows the session much further.
`vault/setup.sh:40-47` creates the AppRole with `token_ttl` and `token_max_ttl` both
set from `DELETE_CREDENTIAL_TTL` (`20s`, `docker-compose.yml:72`), plus
`token_no_default_policy=true`. Equal ttl and max_ttl is what caps the credential's
life: Vault still reports it as `renewable` and will accept a renew call, but the
renewal cannot push the expiry past the 20 second maximum, so there is no way to hold
one open.

**Verified this session:**

```
$ GET /admin/mint-delete-credential   (manageruser)
{"credential":"hvs.CAESIN35KgFI79er7Vwz59gAKPTOVScXrwJoes5P8g580EjM...",
 "ttl_seconds":20,"expires_at":1789251317,"minted_for":"manageruser",
 "usage":"send as X-Vault-Credential on POST /orders/delete"}

$ POST /orders/delete  (same manager token + that credential)
{"credential_ttl_remaining":6,"deleted_by":"manageruser",
 "orders":{"data":{"deleted":{"id":1,"item":"widget","qty":2},"remaining":0},"status":200}}
```

`credential_ttl_remaining: 6` is Vault's own count of seconds left at the moment the
credential was spent (`gateway/app.py:446`), read from the lookup response rather than
computed locally.

The expiry demo from `SETUP.md:339-348` was subsequently run end to end. A credential
was minted, left untouched for 25 seconds, then replayed against the same endpoint:

```
$ vault token lookup <credential>        (immediately after minting)
ttl: 18   policies: ["delete-order"]   num_uses: 0

$ POST /orders/delete   (manager token + a credential minted 25s earlier)
{"error":"vault_credential_invalid","detail":"vault rejected the credential in
 X-Vault-Credential (expired, revoked, malformed, or never issued): 2 errors
 occurred: * permission denied * invalid token"}
```

Renewal buys no extra time: `vault token renew -increment=1h` against a fresh
credential returned `token_duration 19s`, capped by `token_max_ttl`.

*Browser sessions.* On the SAML side each SP keeps a session of its own:
`mock-docs/app.py:43` sets a per-app `SESSION_COOKIE_NAME`, and
`docker-compose.yml:141` / `160` give the two apps different `FLASK_SECRET_KEY`s,
because `localhost:9001` and `localhost:9002` share one cookie jar and a shared key
would let either app read the other's session.

**Not implemented.** `token_num_uses=0` (`vault/setup.sh:46`) leaves a credential
replayable *within* its window, so the control is time-bounded, not single-use.

---

## Tenet 4: Access is determined by dynamic policy

**Mechanism: the decision is made outside the gateway, by OPA, against live token
claims, under a deny-by-default rule set that reloads without a restart.**

`gateway/app.py:105-130` (`opa_allows`) posts the decision input on every request:

```python
payload = {"input": {"authenticated": True, "method": request.method,
                     "path": request.path, "claims": claims}}
response = opa.post(OPA_URL, json=payload, timeout=TIMEOUT)   # /v1/data/authz/allow
```

There is no role comparison anywhere in `gateway/app.py`: the gateway is a PEP that
asks, and `policies/authz.rego` is the PDP that answers.

The policy is deny-by-default at `policies/authz.rego:20`:

```rego
default allow := false
```

Three rules grant anything, and each names an explicit method and path:
`GET /route-test` for any authenticated user (line 24), `POST /orders/delete` (line 33)
and `GET /admin/mint-delete-credential` (line 43) for holders of the `manager` realm
role. The role test at lines 52-55 reads `input.claims.realm_access.roles`, the live
claim, not a copy in config:

```rego
has_realm_role(role) if {
	some assigned in input.claims.realm_access.roles
	assigned == role
}
```

The attribute it reads is provisioned in `keycloak-setup.py` (`MANAGER_ROLE = "manager"`,
line 27; the two-user fixture at line 40, one with the role and one without) and
appears in a real token, confirmed this session on a `manageruser` access token:
`realm_access.roles = ['manager','offline_access','uma_authorization','default-roles-zerotrust-lab']`.

*Dynamic in the operational sense too.* `docker-compose.yml:99` passes `--watch` to
`opa run --server`, so an edit to `authz.rego` takes effect on the running PDP with no
gateway rebuild; `--ignore=*_test.rego` (line 101) keeps the tests out of the served
document tree.

**Verified this session** (full results under tenet 6): `testuser` and `manageruser`
sent byte-identical requests to `POST /orders/delete` and got 403 and "policy allowed"
respectively, with the only difference being one claim in the token.

**Not implemented.** The policy's input carries only `authenticated`, `method`, `path`
and `claims`: no time of day, no source address, no device signal, no request history.
"Dynamic" here means *evaluated per request against live claims*, not *risk-adaptive*.

**Test coverage.** `policies/authz_test.rego` contains 7 `test_` rules (lines 20, 29,
38, 47, 56, 68, 78), covering both sides of each of the three allow rules, plus a deny-by-default
case for an unnamed path. `SETUP.md` §4 previously described five and printed
`PASS: 5/5`, predating the two mint-endpoint tests; it now says seven. The suite was
executed: `opa test policies/ -v` reported `PASS: 7/7` (see the verification note at the
top of this file), matching the seven rule declarations in the file.

---

## Tenet 5: The enterprise monitors and measures the integrity and security posture of all assets

**Partially met.** Asset *posture*, meaning device health, patch level and attestation, is still
never measured, and nothing in this repo could measure it. What is built is narrower
but real: credential and identity state is re-checked against the authoritative source
on every use rather than cached, and every such check now leaves a record.

What is actually built:

- **Each check writes down what it found.** `audit()` (`gateway/app.py:33-53`) emits one
  JSON object per line to stdout for every gate the request passes or fails, so the
  outcome of a verification is durable in `docker compose logs gateway` rather than
  visible only in the response to the caller. The `token` events record the result of
  signature/issuer/expiry verification (`gateway/app.py:146`, `159`, `162`, `167-173`);
  the `credential` events record the result of the Vault lookup (`gateway/app.py:324-330`,
  `346-352`, `356`, `359-365`). Measurement without a record is not monitoring, and
  before this the lab had the former and not the latter.

- **Credential state is queried, never inferred.** `verify_delete_credential`
  (`gateway/app.py:260-309`) calls Vault's `auth/token/lookup-self` with the presented
  credential on every delete. The docstring at lines 263-266 states the design: the
  gateway does not trust the credential's shape, its own memory of having minted one,
  or an offline signature check. Expiry is therefore Vault's answer, which is why a
  revoked credential fails exactly as fast as a timed-out one.
- **Scope is checked, not just liveness.** `gateway/app.py:302-307` rejects a valid
  Vault token that lacks the `delete-order` policy. Verified this session by presenting
  the Vault root token:
  ```
  {"error":"vault_credential_out_of_scope",
   "detail":"credential is valid but not scoped to delete-order; it carries ['root']"}
  ```
- **Dependency state gates startup.** `docker-compose.yml:32-35` blocks the gateway on
  `vault-init: condition: service_completed_successfully`, so it cannot come up in a
  state where the AppRole it depends on does not exist.
- **Identity is verified cryptographically per connection**, via `CERT_REQUIRED` against
  `certs/ca.crt` (tenet 2), which is a check on *who* an asset is, not on its health.

Not implemented. No part of the following exists in the repo:

- No device or host posture signal of any kind: no agent, no attestation, no OS/patch
  state, and nothing in the OPA input that could carry one.
- No certificate revocation checking. `certs/ca.srl` exists as a serial file but no
  CRL or OCSP responder is configured or consulted.
- No certificate rotation. All four certs are static files valid
  `Sep 12 2026 → Sep 12 2027` with private keys sitting in `certs/`.
- **The gateway never inspects the client certificate it accepted.** `getpeercert`
  appears nowhere in the repo, so the mTLS peer's identity never reaches the policy
  input, so the cert is a gate, not an observed attribute.
- `/health` endpoints exist (`gateway/app.py:371-373`, `orders/app.py:33-35`,
  `inventory/app.py:33-35`) but nothing polls them: `docker-compose.yml` contains no
  `healthcheck:` block, and every `depends_on` except `vault-init` uses
  `condition: service_started`.
- The audit log added above records **decisions about** assets, not the **state of**
  assets. Nothing measures whether a host is patched, whether a container image drifted,
  or whether a private key is still confined to the container it belongs to.

---

## Tenet 6: All resource authentication and authorization are dynamic and strictly enforced before access is allowed

**Mechanism: three gates, stacked as decorators, all of which run before the view body
executes; every failure mode is fail-closed.**

The enforcement order is visible in the decorator stack at `gateway/app.py:428-431`:

```python
@app.post("/orders/delete")
@require_token_and_policy      # 1. token signature/issuer/expiry, then 2. OPA
@require_vault_credential      # 3. Vault credential liveness + scope
def orders_delete():
```

1. **Authentication.** `gateway/app.py:150-157` fetches the signing key for the token's
   `kid` from Keycloak's live JWKS (`PyJWKClient(..., cache_jwk_set=True, lifespan=300)`,
   line 93) and verifies with `algorithms=["RS256"]`, a pinned `issuer`, and
   `require=["exp","iss"]`. An unknown `kid` triggers a JWKS re-fetch, so a Keycloak
   key rotation is picked up without a restart.
2. **Authorization.** `opa_allows` (tenet 4), reached only after step 1 succeeds.
3. **Just-in-time credential.** `require_vault_credential` (`gateway/app.py:312-369`).

Ordering is deliberate and stated at `gateway/app.py:315-316`: OPA runs first, so a
caller without the `manager` role never learns that a Vault gate exists.

**Fail-closed at every branch:**

| Site | Behaviour |
| --- | --- |
| `gateway/app.py:130` | `body.get("result") is True`, so an undefined OPA result is a deny, not an allow |
| `gateway/app.py:192-195` | OPA unreachable → 503 `policy_unavailable` ("no decision is not the same as an allow") |
| `gateway/app.py:355-357` | Vault unreachable → 503 `vault_unavailable` |
| `gateway/app.py:302-307` | live-but-wrong-scope credential → 403 |
| `policies/authz.rego:20` | unmatched route → deny |

**Verified this session,** against the running stack, same client cert throughout:

| Request | Result |
| --- | --- |
| `GET /route-test`, no token | 401 `{"detail":"missing bearer token","error":"unauthorized"}` |
| `GET /route-test`, testuser | 200, orders + inventory returned |
| `POST /orders/delete`, testuser | 403 `{"detail":"policy denied POST /orders/delete","error":"forbidden","subject":"testuser"}` |
| `GET /admin/mint-delete-credential`, testuser | 403 `{"detail":"policy denied GET /admin/mint-delete-credential","error":"forbidden","subject":"testuser"}` |
| `POST /orders/delete`, manageruser, no header | 403 `vault_credential_required` |
| `POST /orders/delete`, manageruser, root token | 403 `vault_credential_out_of_scope` |
| `POST /orders/delete`, manageruser, fresh credential | 200 `{"credential_ttl_remaining":6,"deleted_by":"manageruser",...}` |

Three independent facts had to hold simultaneously for that last 200: a client
certificate signed by `certs/ca.crt`, an unexpired Keycloak token carrying `manager`,
and a Vault credential minted seconds earlier and scoped to `delete-order`. Removing
any one produced a distinct, non-overlapping refusal above.

The mint endpoint is itself behind the policy (`gateway/app.py:394-395`), so the
authorization to obtain the second factor is enforced by the same PDP as the action;
row 4 above is that check failing for a non-manager.

**Not implemented.** The two authentication layers are not bound to each other: the
gateway accepts *any* certificate the lab CA signed regardless of which user's token
accompanies it, and `SETUP.md:106-112` notes the smoke test reuses `gateway.crt` as an
operator cert for exactly that reason. There is no token binding, no mapping from cert
subject to token subject, and no per-operator certificate. `orders` and `inventory`
authenticate the gateway by cert but perform no authorization of their own
(`orders/app.py:43-50` deletes on request); they rely entirely on being unreachable
except through the PEP.

---

## Tenet 7: The enterprise collects as much information as possible on the current state of assets and uses it to improve its security posture

**Partially met: collection yes, "uses it to improve posture" still manual.** Every
authentication, authorization and credential decision is now recorded. Nothing
aggregates, retains, correlates or acts on those records; a human reading
`docker compose logs` is the entire analysis tier. Calling this a SIEM would be false.

What is actually built:

- **The gateway logs every decision point, one JSON object per line to stdout.**
  `audit()` at `gateway/app.py:33-53` is the whole emitter, a single `print(json.dumps(record,
  sort_keys=True), flush=True)`, no logging framework, no handler configuration. The
  record it builds has this shape. A captured deny line from the verification run at the
  top of this file matched it on `decision`, `event` and `reason`; the remaining fields
  are as the code constructs them:

  ```json
  {"decision": "deny", "event": "policy", "method": "POST", "path": "/orders/delete",
   "reason": "OPA returned allow=false", "roles": ["default-roles-zerotrust-lab",
   "offline_access", "uma_authorization"], "subject": "testuser",
   "ts": "2026-09-12T20:31:04.882+00:00"}
  ```

  `event` names the gate (`token`, `policy`, `credential`) and `decision` is its answer
  (`allow`, `deny`, `error`, plus `issue` when a credential is minted). Call sites:

  | Decision | Line | Emits |
  | --- | --- | --- |
  | no bearer token | `gateway/app.py:146` | `token` / `deny` |
  | token expired | `gateway/app.py:159` | `token` / `deny` |
  | bad signature or issuer | `gateway/app.py:162` | `token` / `deny` |
  | token verified | `gateway/app.py:167-173` | `token` / `allow` |
  | OPA said no | `gateway/app.py:177-183` | `policy` / `deny` |
  | OPA unreachable | `gateway/app.py:194` | `policy` / `error` |
  | OPA said yes | `gateway/app.py:197` | `policy` / `allow` |
  | no `X-Vault-Credential` | `gateway/app.py:324-330` | `credential` / `deny` |
  | credential invalid or out of scope | `gateway/app.py:346-352` | `credential` / `deny` |
  | Vault unreachable | `gateway/app.py:356`, `407` | `credential` / `error` |
  | credential accepted | `gateway/app.py:359-365` | `credential` / `allow` |
  | credential minted | `gateway/app.py:411-417` | `credential` / `issue` |

  A manager's successful delete therefore leaves three lines (`token allow`, `policy
  allow`, `credential allow`); a refusal leaves the prefix up to whichever gate closed,
  which is the "collect the current state" part the tenet asks for.

- **The log carries the attribute the decision turned on.** `realm_roles()`
  (`gateway/app.py:56-58`) pulls `realm_access.roles` into every `token` and `policy`
  record, so a deny is explicable from the log alone rather than requiring the original
  token to be re-inspected.

- **Secrets stay out of it.** The `audit()` docstring states the rule
  (`gateway/app.py:36-38`) and the call sites honour it: the mint event records the TTL
  and the policy name, never the credential (`gateway/app.py:409-417`), and the
  rejection path logs Vault's own error text rather than the token that failed
  (`gateway/app.py:345`).

- **OPA logs the decision itself, not just the request.** `docker-compose.yml:91-96`
  adds `--set=decision_logs.console=true`. Without it `--log-level=info` records only
  that `/v1/data/authz/allow` was served; with it OPA emits the full input it was given
  and the result it returned, so the PDP's answer is auditable independently of the PEP
  that asked. Console sink only, with no bundle service and no remote decision-log endpoint.

- **Every refusal is attributable to a specific layer.** The seven error codes tabled
  at `SETUP.md:363-371` each originate at one site: `unauthorized`
  (`gateway/app.py:147`, `160`, `163`), `forbidden` (`184-191`),
  `vault_credential_required` (`331-341`), `vault_credential_invalid` (`292-296`),
  `vault_credential_out_of_scope` (`302-307`), `policy_unavailable` (`195`),
  `vault_unavailable` (`357`, `408`). A 403 never leaves you guessing which gate closed, as
  verified in the tenet 6 table, where three different 403s came back from three
  different causes.
- **Responses carry subject and credential state too**, not just the log: denials name
  the caller (`subject=subject`, `gateway/app.py:188`) and successful deletes report the
  actor and the seconds left on the spent credential (`gateway/app.py:443-446`).
- **Live credential state is inspectable.** `vault token lookup "$CRED"` against the
  fixed root token shows a TTL counting down (`SETUP.md:403-407`).
- **Policy behaviour is testable offline** against recorded token shapes:
  `policies/authz_test.rego` covers both sides of every rule plus a deny-by-default
  case for an unnamed path (line 78).
- **Feedback loop, manual.** `--watch` on the mounted policy dir
  (`docker-compose.yml:99`) means the path from "observed a wrong decision" to
  "changed the rule" is an edit plus `opa test`, with no rebuild (`SETUP.md:220-222`).
  That is the only "use it to improve posture" mechanism present, and a human is the
  entire loop.

Not implemented:

- **This is `print()` to stdout, not a logging subsystem.** No `logging` module, so no
  levels, no handlers, no rotation, no way to turn it down in production. `orders`,
  `inventory` and the two mock SPs still log nothing of their own; only the gateway
  and OPA emit records.
- **No correlation.** A gateway line and the OPA decision line it caused share no
  request ID, so pairing them means matching on timestamp, subject and path by eye.
  Nothing ties the mTLS peer to either (`getpeercert` is still unused, per tenet 5).
- **No aggregation, retention or alerting.** No SIEM, no log driver configuration, no
  metrics endpoint (OPA's `/metrics` is still not enabled), and nothing that consumes
  any of this automatically. `docker compose logs` is the whole collection tier,
  bounded by container lifetime: restart a container and its history is gone.
- **Nothing acts on the data.** The tenet's second half, *uses it to improve its
  security posture*, has no automated component here at all. The loop is a human
  reading a deny, editing `authz.rego`, and letting `--watch` reload it.
- Vault runs in dev mode with in-memory storage (`docker-compose.yml:42-47`), so its
  audit-relevant state does not survive a restart, and no audit device is enabled.

---

## Lab-only weaknesses that affect the mapping above

These are deliberate conveniences documented in the repo, not oversights, but they
mean several controls above would not hold outside the lab:

- Vault runs in dev mode with the root token pinned in the compose file
  (`docker-compose.yml:46`, acknowledged at `SETUP.md:243-248`): in-memory storage,
  auto-unsealed, root token in version control.
- The AppRole `role_id` and `secret_id` are fixed strings in `docker-compose.yml:17-18`
  and `69-70` so the gateway can be configured statically; `vault/setup.sh:50-52` notes
  that a real deployment uses a short-lived `secret_id` from a trusted broker.
- `.env` holds the live `gateway-client` secret in the working tree.
- Keycloak runs `start-dev` with `admin`/`admin` (`docker-compose.yml:171-172`), and the
  realm export sets `"bruteForceProtected":false`.
- Both lab users share the permanent password `Test1234!` (`keycloak-setup.py:35`).
- CA and service private keys are unencrypted files in `certs/`, valid for a year, with
  no rotation or revocation path.
