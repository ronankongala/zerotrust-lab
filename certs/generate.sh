#!/usr/bin/env bash
#
# Regenerates the lab's TLS material: a self-signed CA plus a certificate for
# each of the three mutually-authenticating services.
#
# certs/ is gitignored — the private keys are not meant to leave the machine
# that made them — so a fresh clone has no certificates at all and has to run
# this once before `docker compose up`:
#
#     ./certs/generate.sh
#
# By default it is a no-op when the material already exists, so re-running is
# safe. Pass --force to discard everything and mint a new CA:
#
#     ./certs/generate.sh --force
#
# A forced run replaces the CA itself, which invalidates every certificate
# issued by the old one. The running containers hold their certificates open
# from the bind mount, so restart the stack afterwards or they will keep
# presenting the old identities and every handshake will fail verification:
#
#     docker compose restart gateway orders inventory
#
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CERT_DIR"

DAYS=365
BITS=4096
CA_CN="ZeroTrustLab-CA"
SERVICES=(gateway orders inventory)

FORCE=0
case "${1:-}" in
	--force) FORCE=1 ;;
	"") ;;
	*)
		echo "usage: $(basename "$0") [--force]" >&2
		exit 2
		;;
esac

# Every service certificate chains to this CA, so an existing CA is only thrown
# away on an explicit --force.
if [[ -f ca.crt && -f ca.key && $FORCE -eq 0 ]]; then
	echo "CA already present, keeping it (--force to regenerate)"
else
	echo "generating CA (CN=$CA_CN, $BITS bit, $DAYS days)"
	openssl genrsa -out ca.key "$BITS" 2>/dev/null
	chmod 600 ca.key
	openssl req -x509 -new -key ca.key -sha256 -days "$DAYS" \
		-subj "/CN=$CA_CN" -out ca.crt
	# A new CA means a new serial sequence; the old one no longer applies.
	rm -f ca.srl
fi

for svc in "${SERVICES[@]}"; do
	if [[ -f "$svc.crt" && -f "$svc.key" && $FORCE -eq 0 ]]; then
		echo "$svc: already present, skipping"
		continue
	fi

	echo "$svc: generating key, CSR and CA-signed certificate"
	openssl genrsa -out "$svc.key" "$BITS" 2>/dev/null
	chmod 600 "$svc.key"
	openssl req -new -key "$svc.key" -subj "/CN=$svc" -out "$svc.csr"

	# The services verify hostnames, so the name each one is reached by inside
	# the compose network has to appear in the SAN -- a CN alone is not enough
	# for any current TLS client.
	openssl x509 -req -in "$svc.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
		-days "$DAYS" -sha256 -out "$svc.crt" \
		-extfile <(printf 'subjectAltName=DNS:%s\n' "$svc") 2>/dev/null
done

echo
echo "done. issued:"
for svc in "${SERVICES[@]}"; do
	printf '  %-10s %s\n' "$svc" \
		"$(openssl x509 -in "$svc.crt" -noout -ext subjectAltName | tail -1 | tr -d ' ')"
done
