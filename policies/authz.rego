# Fine-grained authorization for the Zero Trust lab gateway.
#
# By the time the gateway asks OPA anything it has already verified the OIDC
# token's signature, issuer and expiry; a failure there is a 401 and never
# reaches this policy. What is left is the authorization question: given this
# identity, is this method+path allowed? Input the gateway sends:
#
#   {
#     "authenticated": true,
#     "method": "POST",
#     "path": "/orders/delete",
#     "claims": { ...the decoded access token... }
#   }
package authz

import rego.v1

# Deny by default. Every permission below has to be spelled out, so a new
# gateway route is unreachable until a rule names it.
default allow := false

# 1. Reading is open to any authenticated user. /route-test fans out to both
#    the orders and inventory services, so this one rule covers reading either.
allow if {
	input.authenticated
	input.method == "GET"
	input.path == "/route-test"
}

# 2. Destructive actions need a "manager" realm role in the token, not merely a
#    valid token. This is the difference between authentication and
#    authorization the lab is demonstrating.
allow if {
	input.authenticated
	input.method == "POST"
	input.path == "/orders/delete"
	has_realm_role("manager")
}

# 3. Minting a just-in-time Vault credential is itself a manager-only act. The
#    credential is the second gate on POST /orders/delete, so anyone who could
#    mint one freely would have turned that gate back into a formality.
allow if {
	input.authenticated
	input.method == "GET"
	input.path == "/admin/mint-delete-credential"
	has_realm_role("manager")
}

# Keycloak puts realm roles under realm_access.roles; a token without that claim
# simply makes this undefined, which fails the rule that referenced it.
has_realm_role(role) if {
	some assigned in input.claims.realm_access.roles
	assigned == role
}
