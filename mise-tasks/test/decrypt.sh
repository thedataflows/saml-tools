#!/bin/env bash
#MISE description="Test SAML decrypt command with demo keys"
#MISE alias="td"

set -euo pipefail

go run . \
  --log-level debug \
  decrypt \
    --key testdata/demo-keys/private.pem\
    testdata/encrypted-assertion.xml
