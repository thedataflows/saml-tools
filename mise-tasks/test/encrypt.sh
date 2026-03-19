#!/bin/env bash
#MISE description="Test SAML encrypt command with demo keys"
#MISE alias="te"

set -euo pipefail

go run . \
  --log-level debug \
  encrypt \
    --key testdata/demo-keys/cert.pem \
    testdata/plain-assertion.xml
