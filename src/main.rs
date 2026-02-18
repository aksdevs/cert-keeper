mod cert;
mod config;
mod error;
mod proxy;
mod vault;

use std::sync::Arc;

use rustls::ServerConfig;
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::cert::manager::CertManager;
use crate::config::{Config, LogFormat};
use crate::vault::client::VaultClient;

#[tokio::main]
async fn main() {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        }
    };

    init_logging(&config.log_format);
    info!(
        listen = %config.listen_addr,
        backend = %config.backend_addr,
        cert_dir = %config.cert_dir,
        "cert-keeper starting"
    );

    if let Err(e) = run(config).await {
        error!(error = %e, "cert-keeper exited with error");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> error::Result<()> {
    let client = Arc::new(VaultClient::new(&config)?);

    // Watch channel for broadcasting TLS server config updates.
    let (identity_tx, identity_rx) = watch::channel::<Option<Arc<ServerConfig>>>(None);

    // Shutdown signal channel.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Initial authentication and certificate fetch.
    let manager = CertManager::new(client.clone(), config.clone(), identity_tx);
    let initial_lease = manager.init().await?;

    // Spawn certificate renewal loop.
    let renewal_shutdown = shutdown_rx.clone();
    let renewal_handle = tokio::spawn(async move {
        manager.run_renewal_loop(initial_lease, renewal_shutdown).await;
    });

    // Spawn TLS proxy.
    let proxy_shutdown = shutdown_rx.clone();
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy::tls_acceptor::run(
            config.listen_addr,
            config.backend_addr,
            identity_rx,
            proxy_shutdown,
        )
        .await
        {
            error!(error = %e, "TLS proxy failed");
        }
    });

    // Wait for shutdown signal.
    shutdown_signal().await;
    info!("shutdown signal received, stopping...");
    let _ = shutdown_tx.send(true);

    // Wait for tasks to finish.
    let _ = tokio::join!(renewal_handle, proxy_handle);
    info!("cert-keeper stopped");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for Ctrl+C");
    }
}

fn init_logging(format: &LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    match format {
        LogFormat::Json => subscriber.json().init(),
        LogFormat::Pretty => subscriber.init(),
    }
}
