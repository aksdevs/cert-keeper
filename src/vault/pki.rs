use serde::Deserialize;
use tracing::{debug, info};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::vault::client::VaultClient;

#[derive(Debug, Deserialize)]
struct PkiResponse {
    data: PkiData,
    lease_duration: u64,
}

#[derive(Debug, Deserialize)]
struct PkiData {
    certificate: String,
    issuing_ca: String,
    private_key: String,
}

/// A certificate bundle returned from Vault PKI.
pub struct CertBundle {
    /// PEM-encoded certificate (leaf + issuing CA).
    pub certificate: String,
    /// PEM-encoded private key.
    pub private_key: String,
    /// PEM-encoded issuing CA certificate.
    pub ca_certificate: String,
    /// Lease duration in seconds (used for renewal scheduling).
    pub lease_duration_secs: u64,
}

/// Issue a new certificate from Vault's PKI secrets engine.
pub async fn issue_certificate(client: &VaultClient, config: &Config) -> Result<CertBundle> {
    let url = format!(
        "{}/v1/{}/issue/{}",
        client.addr, config.vault_pki_mount, config.vault_pki_role
    );

    debug!(
        url = %url,
        common_name = %config.cert_common_name,
        ttl = %config.cert_ttl,
        "requesting certificate from vault PKI"
    );

    let mut body = serde_json::json!({
        "common_name": config.cert_common_name,
        "ttl": config.cert_ttl,
    });

    if let Some(ref alt_names) = config.cert_alt_names {
        body["alt_names"] = serde_json::Value::String(alt_names.clone());
    }

    if let Some(ref ip_sans) = config.cert_ip_sans {
        body["ip_sans"] = serde_json::Value::String(ip_sans.clone());
    }

    let token = client.token().await;
    let mut request = client
        .http
        .post(&url)
        .header("X-Vault-Token", &token)
        .json(&body);

    if let Some(ref ns) = client.namespace {
        request = request.header("X-Vault-Namespace", ns);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(Error::VaultPki(format!(
            "PKI issue returned {status}: {body}"
        )));
    }

    let pki_resp: PkiResponse = response.json().await?;

    // Build full chain: leaf cert + issuing CA
    let full_chain = format!(
        "{}\n{}",
        pki_resp.data.certificate.trim(),
        pki_resp.data.issuing_ca.trim()
    );

    info!(
        lease_duration = pki_resp.lease_duration,
        "certificate issued successfully"
    );

    Ok(CertBundle {
        certificate: full_chain,
        private_key: pki_resp.data.private_key,
        ca_certificate: pki_resp.data.issuing_ca,
        lease_duration_secs: pki_resp.lease_duration,
    })
}
