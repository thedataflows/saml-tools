#!/bin/env bash
#MISE description="Generate demo x509 keys for testing"
#MISE alias="gdk"

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)

output_dir=${1:-"$repo_root/testdata/demo-keys"}
private_key="$output_dir/private.pem"
public_key="$output_dir/public.pem"
certificate="$output_dir/cert.pem"

rsa_bits=${RSA_BITS:-2048}
days=${DAYS:-3650}
subject=${SUBJECT:-/CN=saml-tools-demo/O=saml-tools}

test -f "$private_key" && { echo "Error: $private_key already exists. Aborting." >&2; exit 1; }
test -f "$public_key" && { echo "Error: $public_key already exists. Aborting." >&2; exit 1; }
test -f "$certificate" && { echo "Error: $certificate already exists. Aborting." >&2; exit 1; }

mkdir -p "$output_dir"
umask 077

openssl genpkey \
	-algorithm RSA \
	-pkeyopt "rsa_keygen_bits:${rsa_bits}" \
	-out "$private_key"

openssl req \
	-new \
	-x509 \
	-key "$private_key" \
	-out "$certificate" \
	-days "$days" \
	-subj "$subject"

openssl x509 \
	-in "$certificate" \
	-pubkey \
	-noout \
	>"$public_key"

printf 'Generated PEM files in %s\n' "$output_dir"
printf 'Private key: %s\n' "$private_key"
printf 'Public key: %s\n' "$public_key"
printf 'Certificate: %s\n' "$certificate"
