use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::cert::store::CertStore;
use crate::vault::auth;
use crate::vault::client::VaultClient;
use crate::vault::pki;

/// Manages the certificate lifecycle: initial fetch, hot-reload, and renewal.
pub struct CertManager {
    client: Arc<VaultClient>,
    config: Config,
    store: CertStore,
    tx: watch::Sender<Option<Arc<ServerConfig>>>,
}

impl CertManager {
    pub fn new(
        client: Arc<VaultClient>,
        config: Config,
        tx: watch::Sender<Option<Arc<ServerConfig>>>,
    ) -> Self {
        let store = CertStore::new(&config.cert_dir);
        Self {
            client,
            config,
            store,
            tx,
        }
    }

    /// Perform initial Vault login and certificate fetch, then return.
    pub async fn init(&self) -> Result<u64> {
        auth::kubernetes_login(&self.client, &self.config).await?;
        let bundle = pki::issue_certificate(&self.client, &self.config).await?;

        self.store.write(&bundle).await?;
        let server_config = build_server_config(&bundle.certificate, &bundle.private_key)?;
        let _ = self.tx.send(Some(Arc::new(server_config)));

        Ok(bundle.lease_duration_secs)
    }

    /// Run the renewal loop. This should be spawned as a background task.
    pub async fn run_renewal_loop(self, initial_lease_secs: u64, mut shutdown: watch::Receiver<bool>) {
        let mut lease_secs = initial_lease_secs;
        let mut backoff = Duration::from_secs(5);
        let max_backoff = Duration::from_secs(300);

        loop {
            let renew_after = Duration::from_secs(
                (lease_secs as f64 * self.config.renewal_threshold) as u64
            );

            info!(
                renew_in_secs = renew_after.as_secs(),
                lease_secs,
                "scheduling next certificate renewal"
            );

            tokio::select! {
                _ = tokio::time::sleep(renew_after) => {}
                _ = shutdown.changed() => {
                    info!("renewal loop shutting down");
                    return;
                }
            }

            // Re-authenticate in case the Vault token has expired.
            match auth::kubernetes_login(&self.client, &self.config).await {
                Ok(_) => {
                    backoff = Duration::from_secs(5);
                }
                Err(e) => {
                    warn!(error = %e, "vault re-authentication failed, will retry");
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = shutdown.changed() => return,
                    }
                    backoff = (backoff * 2).min(max_backoff);
                    continue;
                }
            }

            match pki::issue_certificate(&self.client, &self.config).await {
                Ok(bundle) => {
                    if let Err(e) = self.store.write(&bundle).await {
                        error!(error = %e, "failed to write renewed certs to disk");
                    }

                    match build_server_config(&bundle.certificate, &bundle.private_key) {
                        Ok(config) => {
                            let _ = self.tx.send(Some(Arc::new(config)));
                            info!("certificate renewed and hot-reloaded");
                        }
                        Err(e) => {
                            error!(error = %e, "failed to parse renewed certificate");
                        }
                    }

                    lease_secs = bundle.lease_duration_secs;
                    backoff = Duration::from_secs(5);
                }
                Err(e) => {
                    error!(error = %e, "certificate renewal failed, will retry");
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = shutdown.changed() => return,
                    }
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }
}

/// Parse PEM certificate chain and private key, then build a rustls ServerConfig.
fn build_server_config(cert_pem: &str, key_pem: &str) -> Result<ServerConfig> {
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::CertParse(format!("failed to parse certificate PEM: {e}")))?;

    if certs.is_empty() {
        return Err(Error::CertParse("no certificates found in PEM".into()));
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| Error::CertParse(format!("failed to parse private key PEM: {e}")))?
        .ok_or_else(|| Error::CertParse("no private key found in PEM".into()))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Tls(format!("failed to build TLS server config: {e}")))?;

    Ok(config)
}
