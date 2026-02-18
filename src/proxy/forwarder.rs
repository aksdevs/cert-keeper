use std::net::SocketAddr;

use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::debug;

use crate::error::Result;

/// Forward a TLS-terminated connection to the plaintext backend.
///
/// Uses `copy_bidirectional` for zero-copy L4 proxying. This is
/// protocol-agnostic: HTTP/1.1, HTTP/2, gRPC, WebSockets all work.
pub async fn forward(mut tls_stream: TlsStream<TcpStream>, backend_addr: SocketAddr) -> Result<()> {
    let mut backend = TcpStream::connect(backend_addr).await?;

    let (client_bytes, server_bytes) = copy_bidirectional(&mut tls_stream, &mut backend).await?;

    debug!(
        client_to_server = client_bytes,
        server_to_client = server_bytes,
        "connection closed"
    );

    Ok(())
}
