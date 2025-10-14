use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::io::FromRawFd;

use oci_client::manifest::OciDescriptor;
use ocicrypt_rs::config::DecryptConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PAYLOAD_FD: i32 = 3;

#[derive(Debug)]
pub enum GetPayloadError {
    Io(io::Error),
    Json(serde_json::Error),
    JsonNotFound,
    ManipulationError(String),
}
impl From<io::Error> for GetPayloadError {
    fn from(err: io::Error) -> Self {
        GetPayloadError::Io(err)
    }
}
impl From<serde_json::Error> for GetPayloadError {
    fn from(err: serde_json::Error) -> Self {
        GetPayloadError::Json(err)
    }
}

impl fmt::Display for GetPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetPayloadError::Io(e) => write!(f, "I/O error: {}", e),
            GetPayloadError::Json(e) => write!(f, "JSON error: {}", e),
            GetPayloadError::JsonNotFound => write!(f, "JSON not found"),
            GetPayloadError::ManipulationError(s) => write!(f, "JSON {}", s),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
    #[serde(rename = "DecryptConfig")]
    pub decrypt_config: DecryptConfig,
    #[serde(rename = "Descriptor")]
    pub descriptor: OciDescriptor,
}

pub fn read_payload() -> io::Result<Vec<u8>> {
    let mut file = unsafe { File::from_raw_fd(PAYLOAD_FD) };
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| {
        eprintln!("file.read_to_end error {}", e);
        e
    })?;
    std::mem::forget(file);
    Ok(buffer)
}

pub fn get_payload() -> Result<Payload, GetPayloadError> {
    let data = read_payload()?;
    let json_start_pos = data
        .iter()
        .position(|&b| b == b'{')
        .ok_or(GetPayloadError::JsonNotFound)?;
    let json_data = &data[json_start_pos..];
    let mut v: Value = serde_json::from_slice(json_data)?;

    if let Some(decrypt_config) = v.get_mut("DecryptConfig").and_then(|dc| dc.as_object_mut()) {
        if let Some(parameters) = decrypt_config.get("Parameters") {
            if parameters.is_null() {
                decrypt_config.insert("Parameters".to_string(), serde_json::json!({}));
            }
        }
    } else {
        return Err(GetPayloadError::ManipulationError(
            "DecryptConfig field not found".to_string(),
        ));
    }

    let payload: Payload = serde_json::from_value(v)?;
    Ok(payload)
}
