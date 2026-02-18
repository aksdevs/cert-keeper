use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::error::{Error, Result};
use crate::proxy::forwarder;

/// Run the TLS proxy listener.
///
/// Accepts TLS connections, terminates TLS, and forwards plaintext to the
/// backend address. Uses a watch channel to hot-reload certificates.
pub async fn run(
    listen_addr: SocketAddr,
    backend_addr: SocketAddr,
    mut config_rx: watch::Receiver<Option<Arc<ServerConfig>>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    // Wait for the first certificate to be available.
    while config_rx.borrow().is_none() {
        tokio::select! {
            result = config_rx.changed() => {
                if result.is_err() {
                    return Err(Error::Tls("config channel closed before receiving certificate".into()));
                }
            }
            _ = shutdown.changed() => {
                return Ok(());
            }
        }
    }

    let listener = TcpListener::bind(listen_addr).await?;
    info!(addr = %listen_addr, "TLS proxy listening");

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (tcp_stream, peer_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!(error = %e, "failed to accept TCP connection");
                        continue;
                    }
                };

                debug!(peer = %peer_addr, "accepted TCP connection");

                // Build a fresh TLS acceptor from the latest server config.
                let acceptor = match config_rx.borrow().clone() {
                    Some(config) => TlsAcceptor::from(config),
                    None => {
                        warn!("no TLS config available, dropping connection");
                        continue;
                    }
                };

                let backend = backend_addr;
                tokio::spawn(async move {
                    match acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => {
                            if let Err(e) = forwarder::forward(tls_stream, backend).await {
                                debug!(peer = %peer_addr, error = %e, "connection ended");
                            }
                        }
                        Err(e) => {
                            debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                        }
                    }
                });
            }
            _ = shutdown.changed() => {
                info!("TLS proxy shutting down");
                return Ok(());
            }
        }
    }
}
