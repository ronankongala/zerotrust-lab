#!/usr/bin/env bash
#
# verify.sh - re-runs the lab's core verification checks against the running
# stack in a single pass, printing one PASS/FAIL line per check and exiting
# non-zero if any of them fail.
#
# Covers, in the order the lab is built up in SETUP.md:
#
#   1. every service is up
#   2. the plaintext baseline is refused at the gateway
#   3. Keycloak issues an OIDC token, and the gateway is 401 without one and
#      200 with one
#   4. mutual TLS verifies between two services, and a caller with no client
#      certificate is refused
#   5. the Rego policy unit tests pass
#   6. OPA allows a manager and denies a non-manager on the same endpoint
#   7. Vault mints a credential and the gateway accepts it inside its TTL
#
# Prerequisites: ./certs/generate.sh has been run, the stack is up, and
# ./keycloak-setup.py has been run with its printed secret copied into .env.
#
# Usage:  ./verify.sh
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 2

if [ -t 1 ]; then
	GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
else
	GREEN=''; RED=''; DIM=''; BOLD=''; OFF=''
fi

PASSED=0
FAILED=0

pass()    { printf '  %sPASS%s  %s\n' "$GREEN" "$OFF" "$1"; PASSED=$((PASSED + 1)); }
fail()    { printf '  %sFAIL%s  %s\n' "$RED" "$OFF" "$1"; FAILED=$((FAILED + 1)); }
info()    { printf '        %s%s%s\n' "$DIM" "$1" "$OFF"; }
section() { printf '\n%s%s%s\n' "$BOLD" "$1" "$OFF"; }
die()     { printf '\n%sverify.sh cannot run:%s %s\n' "$RED" "$OFF" "$1" >&2; exit 2; }

# ---------------------------------------------------------------- preconditions
for tool in docker curl openssl python3; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH"
done
[ -f certs/ca.crt ] || die "certs/ is empty. Run ./certs/generate.sh first."
[ -f .env ] || die ".env is missing. Run ./keycloak-setup.py and copy the printed secret into it."

set -a; . ./.env; set +a
[ -n "${KEYCLOAK_CLIENT_SECRET:-}" ] || die "KEYCLOAK_CLIENT_SECRET is not set in .env"

LAB_PASSWORD="${LAB_PASSWORD:-Test1234!}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
GATEWAY_URL="https://gateway:8000"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# gateway.crt only carries DNS:gateway in its SAN, so --resolve keeps the name
# the certificate claims while still connecting to the published port.
CURL_CERT=(--cacert certs/ca.crt --cert certs/gateway.crt --key certs/gateway.key)
CURL_RESOLVE=(--resolve gateway:8000:127.0.0.1)

# call <path> <token> [extra curl args...]  ->  sets CODE and BODY
call() {
	local path="$1" token="$2"; shift 2
	local auth=()
	[ -n "$token" ] && auth=(-H "Authorization: Bearer $token")
	CODE="$(curl -s -m 30 "${CURL_CERT[@]}" "${CURL_RESOLVE[@]}" "${auth[@]}" \
		-o "$TMP/body" -w '%{http_code}' "$@" "$GATEWAY_URL$path" 2>/dev/null)"
	BODY="$(cat "$TMP/body" 2>/dev/null)"
}

jfield() { python3 -c 'import sys, json
try:
    d = json.load(sys.stdin)
    for k in sys.argv[1:]:
        d = d[k]
    print(d)
except Exception:
    pass' "$@" 2>/dev/null; }

get_token() {
	curl -s -m 30 -X POST \
		"$KEYCLOAK_URL/realms/zerotrust-lab/protocol/openid-connect/token" \
		-d grant_type=password \
		-d client_id=gateway-client \
		-d client_secret="$KEYCLOAK_CLIENT_SECRET" \
		-d username="$1" \
		-d password="$LAB_PASSWORD" 2>/dev/null | jfield access_token
}

printf '%szerotrust-lab verification%s\n' "$BOLD" "$OFF"
info "$(date -Is)"

# ------------------------------------------------------------------- 1. stack up
section "1. Stack is up"
RUNNING="$(docker compose ps --services --filter status=running 2>/dev/null)"
for svc in gateway orders inventory opa vault keycloak mock-docs mock-dashboard; do
	if grep -qx "$svc" <<<"$RUNNING"; then
		pass "$svc is running"
	else
		fail "$svc is NOT running (try: docker compose up -d)"
	fi
done

# -------------------------------------------------------- 2. plaintext baseline
section "2. Plain HTTP baseline is refused"
curl -s -m 10 -o /dev/null http://localhost:8000/route-test >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
	pass "plain HTTP to :8000 refused (curl exit $rc, the listener is TLS-only)"
else
	fail "plain HTTP to :8000 returned a response; expected the TLS listener to refuse it"
fi

# ------------------------------------------------------------------- 3. OIDC
section "3. OIDC token issuance and gateway enforcement"
TOKEN="$(get_token testuser)"
MANAGER_TOKEN="$(get_token manageruser)"

if [ -n "$TOKEN" ]; then
	pass "Keycloak issued an access token for testuser"
	info "$(python3 -c 'import sys, json, base64
t = sys.argv[1]; p = t.split(".")[1]; p += "=" * (-len(p) % 4)
c = json.loads(base64.urlsafe_b64decode(p))
print("lifespan %ss, issuer %s" % (c["exp"] - c["iat"], c["iss"]))' "$TOKEN" 2>/dev/null)"
else
	fail "Keycloak did not issue a token for testuser (is .env's secret current?)"
fi

if [ -n "$MANAGER_TOKEN" ]; then
	pass "Keycloak issued an access token for manageruser"
	info "$(python3 -c 'import sys, json, base64
t = sys.argv[1]; p = t.split(".")[1]; p += "=" * (-len(p) % 4)
c = json.loads(base64.urlsafe_b64decode(p))
print("realm roles: %s" % ", ".join(sorted(c.get("realm_access", {}).get("roles", []))))' "$MANAGER_TOKEN" 2>/dev/null)"
else
	fail "Keycloak did not issue a token for manageruser"
fi

call /route-test ""
if [ "$CODE" = "401" ]; then
	pass "GET /route-test without a token -> 401"
else
	fail "GET /route-test without a token -> $CODE (expected 401)"
fi

call /route-test "$TOKEN"
if [ "$CODE" = "200" ]; then
	pass "GET /route-test with a valid token -> 200"
else
	fail "GET /route-test with a valid token -> $CODE (expected 200)"
fi

# ------------------------------------------------------------------- 4. mTLS
section "4. Mutual TLS between gateway and orders"
HANDSHAKE="$(docker compose exec -T gateway sh -c \
	'openssl s_client -connect orders:5000 -CAfile /certs/ca.crt \
	 -cert /certs/gateway.crt -key /certs/gateway.key </dev/null 2>&1' 2>/dev/null)"

if grep -q 'Verification: OK' <<<"$HANDSHAKE" && grep -q 'subject=CN=orders' <<<"$HANDSHAKE"; then
	pass "handshake verifies, peer is CN=orders signed by the lab CA"
	info "$(grep -m1 'Protocol' <<<"$HANDSHAKE" | sed 's/^ *//')"
else
	fail "handshake to orders:5000 did not verify"
fi

WITH_CERT="$(docker compose exec -T gateway sh -c \
	'printf "GET /health HTTP/1.0\r\n\r\n" | openssl s_client -connect orders:5000 \
	 -CAfile /certs/ca.crt -cert /certs/gateway.crt -key /certs/gateway.key -quiet 2>&1' 2>/dev/null)"
if grep -q 'HTTP/1.1 200' <<<"$WITH_CERT"; then
	pass "application data flows over the mutually authenticated channel"
else
	fail "no HTTP response from orders over mTLS"
fi

NO_CERT="$(docker compose exec -T gateway sh -c \
	'printf "GET /health HTTP/1.0\r\n\r\n" | openssl s_client -connect orders:5000 \
	 -CAfile /certs/ca.crt -quiet 2>&1' 2>/dev/null)"
if grep -qi 'certificate required' <<<"$NO_CERT"; then
	pass "orders refuses a caller presenting no client certificate"
else
	fail "orders accepted a connection without a client certificate"
fi

# -------------------------------------------------------------- 5. policy tests
section "5. OPA policy unit tests"
if grep -qx opa <<<"$RUNNING"; then
	OPA_OUT="$(docker compose exec -T opa opa test /policies -v 2>&1)"
else
	OPA_OUT="$(docker run --rm -v "$PWD/policies:/policies:ro" \
		openpolicyagent/opa:latest test /policies -v 2>&1)"
fi
OPA_TALLY="$(grep -oE 'PASS: [0-9]+/[0-9]+' <<<"$OPA_OUT" | tail -1)"
if [ -n "$OPA_TALLY" ] && ! grep -qE '^(FAIL|ERROR)' <<<"$OPA_OUT"; then
	pass "opa test policies/ -v reported $OPA_TALLY"
else
	fail "opa test policies/ -v did not pass cleanly"
	printf '%s\n' "$OPA_OUT" | tail -15
fi

# --------------------------------------------------------- 6. live OPA decision
section "6. Live OPA decision, same endpoint, different roles"
call /admin/mint-delete-credential "$TOKEN"
if [ "$CODE" = "403" ] && [ "$(jfield error <<<"$BODY")" = "forbidden" ]; then
	pass "testuser (no manager role) denied -> 403 forbidden"
else
	fail "testuser -> $CODE $(jfield error <<<"$BODY") (expected 403 forbidden)"
fi

call /admin/mint-delete-credential "$MANAGER_TOKEN"
CREDENTIAL="$(jfield credential <<<"$BODY")"
if [ "$CODE" = "200" ] && [ -n "$CREDENTIAL" ]; then
	pass "manageruser allowed on the identical request -> 200"
	info "credential ttl_seconds=$(jfield ttl_seconds <<<"$BODY"), minted for $(jfield minted_for <<<"$BODY")"
else
	fail "manageruser -> $CODE (expected 200 with a credential)"
fi

call /orders/delete "$TOKEN" -X POST -H 'Content-Type: application/json' -d '{"id":1}'
if [ "$CODE" = "403" ] && [ "$(jfield error <<<"$BODY")" = "forbidden" ]; then
	pass "testuser denied on POST /orders/delete -> 403 forbidden"
else
	fail "testuser POST /orders/delete -> $CODE $(jfield error <<<"$BODY") (expected 403 forbidden)"
fi

# ------------------------------------------------------- 7. Vault JIT credential
section "7. Vault credential minted and used inside its TTL"
order_ids() {
	call /route-test "$MANAGER_TOKEN"
	python3 -c 'import sys, json
try:
    d = json.load(sys.stdin)
    print(" ".join(str(o["id"]) for o in d["orders"]["data"]["orders"]))
except Exception:
    pass' <<<"$BODY" 2>/dev/null
}

IDS="$(order_ids)"
if [ -z "$IDS" ]; then
	# ORDERS is an in-memory list in orders/app.py, so a restart reseeds it.
	# Earlier runs of this script consume one order each.
	info "no orders left from earlier runs, restarting orders to reseed"
	docker compose restart orders >/dev/null 2>&1
	for _ in $(seq 1 20); do
		IDS="$(order_ids)"
		[ -n "$IDS" ] && break
		sleep 1
	done
fi

ORDER_ID="${IDS%% *}"
if [ -z "$ORDER_ID" ]; then
	fail "no order available to delete (is the orders service healthy?)"
else
	CREDENTIAL="$(call /admin/mint-delete-credential "$MANAGER_TOKEN"; jfield credential <<<"$BODY")"
	if [ -z "$CREDENTIAL" ]; then
		fail "could not mint a Vault credential"
	else
		pass "Vault minted a delete-order credential"
		call /orders/delete "$MANAGER_TOKEN" \
			-X POST -H 'Content-Type: application/json' -d "{\"id\":$ORDER_ID}" \
			-H "X-Vault-Credential: $CREDENTIAL"
		if [ "$CODE" = "200" ]; then
			pass "POST /orders/delete with a fresh credential -> 200 (order $ORDER_ID deleted)"
			info "credential_ttl_remaining=$(jfield credential_ttl_remaining <<<"$BODY")s, deleted_by=$(jfield deleted_by <<<"$BODY")"
		else
			fail "POST /orders/delete with a fresh credential -> $CODE $(jfield error <<<"$BODY") (expected 200)"
		fi
	fi
fi

# ---------------------------------------------------------------------- summary
section "Summary"
if [ "$FAILED" -eq 0 ]; then
	printf '  %s%d passed, 0 failed%s\n\n' "$GREEN" "$PASSED" "$OFF"
	exit 0
fi
printf '  %s%d passed, %d failed%s\n\n' "$RED" "$PASSED" "$FAILED" "$OFF"
exit 1
