package authz_test

import rego.v1

import data.authz

# Shaped like a real Keycloak access token, trimmed to the claims the policy
# reads. testuser gets only the realm's default roles; manageruser also carries
# the "manager" role that keycloak-setup.py assigns.
plain_user := {
	"preferred_username": "testuser",
	"realm_access": {"roles": ["default-roles-zerotrust-lab", "offline_access"]},
}

manager_user := {
	"preferred_username": "manageruser",
	"realm_access": {"roles": ["default-roles-zerotrust-lab", "manager"]},
}

test_authenticated_get_route_test_allowed if {
	authz.allow with input as {
		"authenticated": true,
		"method": "GET",
		"path": "/route-test",
		"claims": plain_user,
	}
}

test_unauthenticated_get_route_test_denied if {
	not authz.allow with input as {
		"authenticated": false,
		"method": "GET",
		"path": "/route-test",
		"claims": {},
	}
}

test_manager_post_orders_delete_allowed if {
	authz.allow with input as {
		"authenticated": true,
		"method": "POST",
		"path": "/orders/delete",
		"claims": manager_user,
	}
}

test_non_manager_post_orders_delete_denied if {
	not authz.allow with input as {
		"authenticated": true,
		"method": "POST",
		"path": "/orders/delete",
		"claims": plain_user,
	}
}

test_manager_mint_delete_credential_allowed if {
	authz.allow with input as {
		"authenticated": true,
		"method": "GET",
		"path": "/admin/mint-delete-credential",
		"claims": manager_user,
	}
}

# The mint endpoint is the gate in front of the gate: leaving it open to any
# authenticated user would let a non-manager hand a credential to a manager, or
# to anyone else who found one.
test_non_manager_mint_delete_credential_denied if {
	not authz.allow with input as {
		"authenticated": true,
		"method": "GET",
		"path": "/admin/mint-delete-credential",
		"claims": plain_user,
	}
}

# Deny-by-default: a route no rule mentions is refused even for a manager.
test_unknown_path_denied if {
	not authz.allow with input as {
		"authenticated": true,
		"method": "GET",
		"path": "/orders/secret",
		"claims": manager_user,
	}
}
