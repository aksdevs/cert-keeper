use std::env;
use std::net::SocketAddr;

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub vault_addr: String,
    pub vault_auth_role: String,
    pub vault_auth_mount: String,
    pub vault_pki_role: String,
    pub vault_pki_mount: String,
    pub vault_namespace: Option<String>,
    pub vault_cacert: Option<String>,
    pub cert_common_name: String,
    pub cert_alt_names: Option<String>,
    pub cert_ip_sans: Option<String>,
    pub cert_ttl: String,
    pub cert_dir: String,
    pub listen_addr: SocketAddr,
    pub backend_addr: SocketAddr,
    pub renewal_threshold: f64,
    pub log_format: LogFormat,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogFormat {
    Json,
    Pretty,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let vault_addr = required_env("VAULT_ADDR")?;
        let vault_auth_role = required_env("VAULT_AUTH_ROLE")?;
        let vault_pki_role = required_env("VAULT_PKI_ROLE")?;
        let cert_common_name = required_env("CERT_COMMON_NAME")?;

        let vault_auth_mount = env::var("VAULT_AUTH_MOUNT").unwrap_or_else(|_| "kubernetes".into());
        let vault_pki_mount = env::var("VAULT_PKI_MOUNT").unwrap_or_else(|_| "pki".into());
        let vault_namespace = env::var("VAULT_NAMESPACE").ok();
        let vault_cacert = env::var("VAULT_CACERT").ok();
        let cert_alt_names = env::var("CERT_ALT_NAMES").ok();
        let cert_ip_sans = env::var("CERT_IP_SANS").ok();
        let cert_ttl = env::var("CERT_TTL").unwrap_or_else(|_| "24h".into());
        let cert_dir = env::var("CERT_DIR").unwrap_or_else(|_| "/certs".into());

        let listen_addr: SocketAddr = env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8443".into())
            .parse()
            .map_err(|e| Error::Config(format!("invalid LISTEN_ADDR: {e}")))?;

        let backend_addr: SocketAddr = env::var("BACKEND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".into())
            .parse()
            .map_err(|e| Error::Config(format!("invalid BACKEND_ADDR: {e}")))?;

        let renewal_threshold: f64 = env::var("RENEWAL_THRESHOLD")
            .unwrap_or_else(|_| "0.66".into())
            .parse()
            .map_err(|e| Error::Config(format!("invalid RENEWAL_THRESHOLD: {e}")))?;

        if !(0.0..1.0).contains(&renewal_threshold) {
            return Err(Error::Config(
                "RENEWAL_THRESHOLD must be between 0.0 and 1.0".into(),
            ));
        }

        let log_format = match env::var("LOG_FORMAT")
            .unwrap_or_else(|_| "json".into())
            .to_lowercase()
            .as_str()
        {
            "json" => LogFormat::Json,
            "pretty" => LogFormat::Pretty,
            other => {
                return Err(Error::Config(format!(
                    "invalid LOG_FORMAT '{other}': must be 'json' or 'pretty'"
                )))
            }
        };

        Ok(Config {
            vault_addr,
            vault_auth_role,
            vault_auth_mount,
            vault_pki_role,
            vault_pki_mount,
            vault_namespace,
            vault_cacert,
            cert_alt_names,
            cert_ip_sans,
            cert_ttl,
            cert_dir,
            cert_common_name,
            listen_addr,
            backend_addr,
            renewal_threshold,
            log_format,
        })
    }
}

fn required_env(key: &str) -> Result<String> {
    env::var(key).map_err(|_| Error::Config(format!("required environment variable {key} is not set")))
}
