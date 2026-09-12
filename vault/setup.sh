#!/bin/sh
# Bootstrap the lab's just-in-time privileged access layer.
#
# Runs once, as the `vault-init` compose service, against the dev-mode Vault.
# Dev mode keeps everything in memory, so this has to re-run on every
# `docker compose up` -- hence a one-shot container rather than a script you are
# expected to remember to invoke.
set -eu

echo "vault-init: waiting for ${VAULT_ADDR}"
# `vault status` exits 2 while sealed and 0 once unsealed; dev mode auto-unseals,
# so a 0 means the API is genuinely ready to take writes.
until vault status >/dev/null 2>&1; do
	sleep 1
done

# The Vault policy attached to the minted credential. It is deliberately close to
# empty: the credential's only power is to prove that it exists and has not
# expired. That is the whole point of a JIT credential -- it is evidence of a
# fresh authorization, not a key to anything.
#
# lookup-self has to be granted explicitly because the role below turns off the
# built-in `default` policy, which is what normally carries it.
vault policy write delete-order - <<'POLICY'
# Allows the holder to introspect its own token (TTL, policies) and nothing else.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
POLICY

# AppRole rather than userpass: the client here is the gateway (a machine), not a
# human typing a password. role_id is the public "who", secret_id the private
# "proof" -- the same split as a client_id/client_secret pair.
vault auth enable approle 2>/dev/null || true

# token_ttl == token_max_ttl == 20s is what makes the credential just-in-time:
# it cannot be renewed past 20 seconds, so a leaked one is worthless almost
# immediately. token_num_uses=0 leaves it reusable *within* that window, which
# keeps the expiry demo in SETUP.md about time rather than about replay.
vault write auth/approle/role/delete-order \
	token_policies=delete-order \
	token_no_default_policy=true \
	token_ttl="${DELETE_CREDENTIAL_TTL:-20s}" \
	token_max_ttl="${DELETE_CREDENTIAL_TTL:-20s}" \
	token_num_uses=0 \
	secret_id_ttl=0 \
	secret_id_num_uses=0

# Vault would generate both of these for us, but then the gateway could not be
# configured from a static compose file. Pinning them is a lab affordance in the
# same spirit as the fixed root token; in a real deployment the secret_id is
# short-lived and delivered by a trusted broker.
vault write auth/approle/role/delete-order/role-id \
	role_id="${DELETE_ROLE_ID}"
# Re-registering a secret_id Vault already knows is a hard error, and this
# script has to survive a bare `docker compose up -d gateway` re-running it
# against a Vault that is still live. Destroying first makes it idempotent.
vault write -f auth/approle/role/delete-order/secret-id/destroy \
	secret_id="${DELETE_SECRET_ID}" >/dev/null 2>&1 || true
vault write auth/approle/role/delete-order/custom-secret-id \
	secret_id="${DELETE_SECRET_ID}" >/dev/null

echo "vault-init: approle role 'delete-order' ready (ttl ${DELETE_CREDENTIAL_TTL:-20s})"
