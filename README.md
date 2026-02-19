# cert-keeper

A Rust sidecar container for Kubernetes that manages TLS certificates from HashiCorp Vault and provides TLS termination.

## What it does

- Authenticates to Vault using Kubernetes service account tokens
- Fetches TLS certificates from Vault's PKI secrets engine
- Terminates TLS and forwards plaintext TCP to your application on localhost
- Writes certificates to a shared volume so your app can access them directly
- Automatically renews certificates before expiry with hot-reload (no downtime)
- Protocol-agnostic L4 proxy: works with HTTP, gRPC, WebSockets, etc.

## Architecture

```
                    
                                       Pod                       
                                                                 
  TLS traffic  cert-keeper (:8443)  app (:8080)     
                                                                
                             /certs/tls.crt                  
                                 /certs/tls.key   (emptyDir)     
                                 /certs/ca.crt                   
                    
```

## Configuration

All configuration is via environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `VAULT_ADDR` | yes | - | Vault server URL |
| `VAULT_AUTH_ROLE` | yes | - | Vault Kubernetes auth role |
| `VAULT_PKI_ROLE` | yes | - | Vault PKI role for certificate issuance |
| `CERT_COMMON_NAME` | yes | - | Certificate Common Name (CN) |
| `VAULT_AUTH_MOUNT` | no | `kubernetes` | Vault auth method mount path |
| `VAULT_PKI_MOUNT` | no | `pki` | Vault PKI mount path |
| `VAULT_NAMESPACE` | no | - | Vault Enterprise namespace |
| `VAULT_CACERT` | no | - | Path to CA cert for verifying Vault's TLS |
| `CERT_ALT_NAMES` | no | - | Comma-separated Subject Alternative Names |
| `CERT_IP_SANS` | no | - | Comma-separated IP SANs |
| `CERT_TTL` | no | `24h` | Certificate TTL |
| `CERT_DIR` | no | `/certs` | Directory for certificate files |
| `LISTEN_ADDR` | no | `0.0.0.0:8443` | TLS listener address |
| `BACKEND_ADDR` | no | `127.0.0.1:8080` | Plaintext backend address |
| `RENEWAL_THRESHOLD` | no | `0.66` | Renew certificate at this fraction of TTL |
| `RUST_LOG` | no | `info` | Log level filter |
| `LOG_FORMAT` | no | `json` | Log format: `json` or `pretty` |

## Quick Start

### 1. Set up Vault

```bash
# Enable PKI secrets engine
vault secrets enable pki

# Configure PKI (adjust for your CA setup)
vault write pki/root/generate/internal \
    common_name="cluster.local" \
    ttl=87600h

# Create a role for cert-keeper
vault write pki/roles/cert-keeper \
    allowed_domains="svc.cluster.local" \
    allow_subdomains=true \
    max_ttl=72h

# Enable Kubernetes auth
vault auth enable kubernetes

vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc"

# Create policy and bind role
vault policy write cert-keeper k8s/vault-policy.hcl

vault write auth/kubernetes/role/cert-keeper \
    bound_service_account_names=cert-keeper \
    bound_service_account_namespaces=default \
    policies=cert-keeper \
    ttl=1h
```

### 2. Deploy

```bash
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/deployment.yaml
```

### 3. Verify

```bash
# Check cert-keeper logs
kubectl logs deployment/my-app -c cert-keeper

# Verify TLS
kubectl port-forward deployment/my-app 8443:8443
curl -k https://localhost:8443
```

## Certificate Files

cert-keeper writes three files to the shared volume (default `/certs`):

| File | Contents |
|---|---|
| `tls.crt` | Leaf certificate + issuing CA (full chain) |
| `tls.key` | Private key |
| `ca.crt` | Issuing CA certificate |

Files are written atomically (write to temp, then rename) so your application never reads partial content.

## Building

```bash
# Local build
cargo build --release

# Docker build
docker buildx build -t cert-keeper:test .
```

## Releasing

Releases are automated via GitHub Actions. Push a semver tag to trigger a build:

```bash
git tag v0.1.0
git push --tags
```

This builds multi-arch images (amd64 + arm64) and pushes to `aksdevs/cert-keeper` on DockerHub with tags:
- `aksdevs/cert-keeper:0.1.0`
- `aksdevs/cert-keeper:0.1`
- `aksdevs/cert-keeper:latest`

## License

MIT
