use std::{os::unix::fs::FileTypeExt, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use async_compression::tokio::bufread::GzipDecoder;
use base64::{Engine, engine::general_purpose::STANDARD};
use const_format::concatcp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use slog::{Logger, debug, error, info, o};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

/// Currently, initdata only supports version 0.1.0.
const INITDATA_VERSION: &str = "0.1.0";
/// supported algorithms list
const SUPPORTED_ALGORITHMS: [&str; 3] = ["sha256", "sha384", "sha512"];

/// This is the target directory to store the extracted initdata.
pub const INITDATA_PATH: &str = "/run/confidential-containers/initdata";

const AA_CONFIG_KEY: &str = "aa.toml";
const CDH_CONFIG_KEY: &str = "cdh.toml";

const POLICY_KEY: &str = "policy.rego";

/// The path of initdata toml
pub const INITDATA_TOML_PATH: &str = concatcp!(INITDATA_PATH, "/initdata.toml");

/// The path of AA's config file
pub const AA_CONFIG_PATH: &str = concatcp!(INITDATA_PATH, "/aa.toml");

/// The path of CDH's config file
pub const CDH_CONFIG_PATH: &str = concatcp!(INITDATA_PATH, "/cdh.toml");

/// Magic number of initdata device
pub const INITDATA_MAGIC_NUMBER: &[u8] = b"initdata";

async fn detect_initdata_device(logger: &Logger) -> Result<Option<String>> {
    let dev_dir = Path::new("/dev");
    let mut read_dir = tokio::fs::read_dir(dev_dir).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let filename = entry.file_name();
        let filename = filename.to_string_lossy();
        debug!(logger, "Initdata check device `{filename}`");
        if !filename.starts_with("vd") {
            continue;
        }
        let path = entry.path();
        debug!(logger, "Initdata find potential device: `{path:?}`");
        let metadata = std::fs::metadata(path.clone())?;
        if !metadata.file_type().is_block_device() {
            continue;
        }

        let mut file = tokio::fs::File::open(&path).await?;
        let mut magic = [0; 8];
        match file.read_exact(&mut magic).await {
            Ok(_) => {
                debug!(
                    logger,
                    "Initdata read device `{filename}` first 8 bytes: {magic:?}"
                );
                if magic == INITDATA_MAGIC_NUMBER {
                    let path = path.as_path().to_string_lossy().to_string();
                    debug!(logger, "Found initdata device {path}");
                    return Ok(Some(path));
                }
            }
            Err(e) => debug!(logger, "Initdata read device `{filename}` failed: {e:?}"),
        }
    }

    Ok(None)
}

pub async fn read_initdata(dev_path: &str) -> Result<Vec<u8>> {
    let initdata_devfile = tokio::fs::File::open(dev_path).await?;
    let mut buf_reader = tokio::io::BufReader::new(initdata_devfile);
    // skip the magic number "initdata"
    buf_reader.seek(std::io::SeekFrom::Start(8)).await?;

    let mut len_buf = [0u8; 8];
    buf_reader.read_exact(&mut len_buf).await?;
    let length = u64::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0; length];
    buf_reader.read_exact(&mut buf).await?;
    let mut gzip_decoder = GzipDecoder::new(&buf[..]);

    let mut initdata = Vec::new();
    let _ = gzip_decoder.read_to_end(&mut initdata).await?;
    Ok(initdata)
}

pub struct InitdataReturnValue {
    pub _digest: Vec<u8>,
    pub _policy: Option<String>,
}

pub async fn initialize_initdata(logger: &Logger) -> Result<Option<InitdataReturnValue>> {
    let logger = logger.new(o!("subsystem" => "initdata"));
    let Some(initdata_device) = detect_initdata_device(&logger).await? else {
        info!(
            logger,
            "Initdata device not found, skip initdata initialization"
        );
        return Ok(None);
    };

    tokio::fs::create_dir_all(INITDATA_PATH)
        .await
        .inspect_err(|e| error!(logger, "Failed to create initdata dir: {e:?}"))?;

    let initdata_content = read_initdata(&initdata_device)
        .await
        .inspect_err(|e| error!(logger, "Failed to read initdata: {e:?}"))?;

    let initdata: InitData =
        toml::from_slice(&initdata_content).context("parse initdata failed")?;
    info!(logger, "Initdata version: {}", initdata.version());
    initdata.validate()?;

    tokio::fs::write(INITDATA_TOML_PATH, &initdata_content)
        .await
        .context("write initdata toml failed")?;

    let _digest = match initdata.algorithm() {
        "sha256" => Sha256::digest(&initdata_content).to_vec(),
        "sha384" => Sha384::digest(&initdata_content).to_vec(),
        "sha512" => Sha512::digest(&initdata_content).to_vec(),
        others => bail!("Unpupported hash algorithm {others}"),
    };

    if let Some(config) = initdata.get_node_data(AA_CONFIG_KEY) {
        tokio::fs::write(AA_CONFIG_PATH, config)
            .await
            .context("write AA config from initdata")?;
        info!(logger, "write AA config from initdata");
    }

    if let Some(config) = initdata.get_node_data(CDH_CONFIG_KEY) {
        tokio::fs::write(CDH_CONFIG_PATH, config)
            .await
            .context("write CDH config failed")?;
        info!(logger, "write CDH config from initdata");
    }

    debug!(logger, "iInitdata digest: {}", STANDARD.encode(&_digest));

    let res = InitdataReturnValue {
        _digest,
        _policy: initdata.get_node_data(POLICY_KEY).cloned(),
    };

    Ok(Some(res))
}

#[allow(clippy::doc_lazy_continuation)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InitData {
    /// version of InitData Spec
    version: String,
    /// algorithm: sha256, sha512, sha384
    algorithm: String,
    /// data for specific "key:value"
    data: HashMap<String, String>,
}

impl InitData {
    /// get node data
    pub fn get_node_data(&self, key: &str) -> Option<&String> {
        self.data.get(key)
    }

    /// get algorithm
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// get version
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Validate InitData
    pub fn validate(&self) -> Result<()> {
        if self.version != INITDATA_VERSION {
            return Err(anyhow!(
                "unsupported version : {}, expected: {}",
                self.version,
                INITDATA_VERSION
            ));
        }

        if !SUPPORTED_ALGORITHMS
            .iter()
            .any(|&alg| alg == self.algorithm)
        {
            return Err(anyhow!(
                "unsupported algorithm: {}, supported algorithms: {}",
                self.algorithm,
                SUPPORTED_ALGORITHMS.join(", ")
            ));
        }

        Ok(())
    }
}
