use std::path::{Path, PathBuf};

use tokio::fs;
use tracing::info;

use crate::error::Result;
use crate::vault::pki::CertBundle;

/// Handles atomic writes of certificate files to the shared volume.
pub struct CertStore {
    dir: PathBuf,
}

impl CertStore {
    pub fn new(dir: &str) -> Self {
        Self {
            dir: PathBuf::from(dir),
        }
    }

    pub fn cert_path(&self) -> PathBuf {
        self.dir.join("tls.crt")
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.join("tls.key")
    }

    pub fn ca_path(&self) -> PathBuf {
        self.dir.join("ca.crt")
    }

    /// Write the certificate bundle to disk atomically.
    ///
    /// Files are written to a `.tmp` suffix first, then renamed so that
    /// readers never see partial content.
    pub async fn write(&self, bundle: &CertBundle) -> Result<()> {
        fs::create_dir_all(&self.dir).await?;

        atomic_write(&self.cert_path(), &bundle.certificate).await?;
        atomic_write(&self.key_path(), &bundle.private_key).await?;
        atomic_write(&self.ca_path(), &bundle.ca_certificate).await?;

        info!(dir = %self.dir.display(), "certificate files written");
        Ok(())
    }
}

/// Write `contents` to `path` atomically via a temporary file + rename.
async fn atomic_write(path: &Path, contents: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, contents).await?;
    fs::rename(&tmp, path).await?;
    Ok(())
}
