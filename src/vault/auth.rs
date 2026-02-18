use serde::Deserialize;
use tracing::{debug, info};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::vault::client::VaultClient;

const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

#[derive(Debug, Deserialize)]
struct AuthResponse {
    auth: AuthData,
}

#[derive(Debug, Deserialize)]
struct AuthData {
    client_token: String,
    lease_duration: u64,
}

/// Authenticate to Vault using the Kubernetes auth method.
///
/// Reads the service account JWT from the projected volume and exchanges it
/// for a Vault token.
pub async fn kubernetes_login(client: &VaultClient, config: &Config) -> Result<()> {
    let jwt = tokio::fs::read_to_string(SA_TOKEN_PATH)
        .await
        .map_err(|e| {
            Error::VaultAuth(format!(
                "failed to read service account token from {SA_TOKEN_PATH}: {e}"
            ))
        })?;

    let url = format!(
        "{}/v1/auth/{}/login",
        client.addr, config.vault_auth_mount
    );

    debug!(url = %url, role = %config.vault_auth_role, "authenticating to vault");

    let mut request = client
        .http
        .post(&url)
        .json(&serde_json::json!({
            "role": config.vault_auth_role,
            "jwt": jwt.trim(),
        }));

    if let Some(ref ns) = client.namespace {
        request = request.header("X-Vault-Namespace", ns);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(Error::VaultAuth(format!(
            "login returned {status}: {body}"
        )));
    }

    let auth_resp: AuthResponse = response.json().await?;

    client.set_token(auth_resp.auth.client_token).await;
    info!(
        lease_duration = auth_resp.auth.lease_duration,
        "vault authentication successful"
    );

    Ok(())
}
