# Vault policy for cert-keeper sidecar.
# Apply with: vault policy write cert-keeper k8s/vault-policy.hcl

# Allow issuing certificates from the PKI secrets engine.
path "pki/issue/cert-keeper" {
  capabilities = ["create", "update"]
}

# Allow reading PKI roles (optional, for validation).
path "pki/roles/cert-keeper" {
  capabilities = ["read"]
}
