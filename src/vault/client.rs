use std::sync::Arc;

use reqwest::Client;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::{Error, Result};

/// Shared Vault HTTP client with managed token state.
pub struct VaultClient {
    pub http: Client,
    pub addr: String,
    pub namespace: Option<String>,
    token: Arc<RwLock<String>>,
}

impl VaultClient {
    pub fn new(config: &Config) -> Result<Self> {
        let mut builder = Client::builder();

        if let Some(ref ca_path) = config.vault_cacert {
            let ca_pem = std::fs::read(ca_path)
                .map_err(|e| Error::Config(format!("failed to read VAULT_CACERT '{ca_path}': {e}")))?;
            let cert = reqwest::Certificate::from_pem(&ca_pem)
                .map_err(|e| Error::Config(format!("invalid VAULT_CACERT: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }

        let http = builder
            .build()
            .map_err(|e| Error::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            http,
            addr: config.vault_addr.trim_end_matches('/').to_string(),
            namespace: config.vault_namespace.clone(),
            token: Arc::new(RwLock::new(String::new())),
        })
    }

    pub async fn set_token(&self, token: String) {
        let mut guard = self.token.write().await;
        *guard = token;
    }

    pub async fn token(&self) -> String {
        self.token.read().await.clone()
    }
}
