use anyhow::{Context, Result};
use ocicrypt_rs::config::{CryptoConfig, DecryptConfig, EncryptConfig};
use ocicrypt_rs::helpers::create_decrypt_config;
use std::collections::HashMap;
use walkdir::WalkDir;

pub fn get_decryption_keys(keys_path: &String) -> Result<CryptoConfig> {
    let mut keys: Vec<String> = Vec::new();
    let dec_recipients = Vec::new();

    // WalkDir is a robust way to iterate through directory entries.
    for entry in WalkDir::new(keys_path) {
        let entry =
            entry.with_context(|| format!("Failed to walk directory entry in '{}'", keys_path))?;
        let path = entry.path();
        let metadata = entry
            .metadata()
            .with_context(|| format!("Failed to read metadata for '{}'", path.display()))?;

        if metadata.is_dir() {
            continue;
        }

        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "Symbolic links are not supported in decryption key paths: {}",
                path.display()
            );
        }
        keys.push(path.display().to_string());
    }

    create_decrypt_config(keys, dec_recipients)
}

pub fn combine_decryption_configs(dc1: &DecryptConfig, dc2: &DecryptConfig) -> DecryptConfig {
    let cc1 = CryptoConfig {
        encrypt_config: None,
        decrypt_config: Some(dc1.clone()),
    };
    let cc2 = CryptoConfig {
        encrypt_config: None,
        decrypt_config: Some(dc2.clone()),
    };

    let combined = combine_crypto_configs(&[cc1, cc2]);
    combined.decrypt_config.unwrap()
}

fn combine_crypto_configs(ccs: &[CryptoConfig]) -> CryptoConfig {
    let mut ecparam: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    let mut ecdcparam: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    let mut dcparam: HashMap<String, Vec<Vec<u8>>> = HashMap::new();

    for cc in ccs {
        if let Some(ec) = &cc.encrypt_config {
            add_to_map(&mut ecparam, &ec.param);
            if let Some(dcp) = ec.decrypt_config.clone() {
                add_to_map(&mut ecdcparam, &dcp.param);
            }
        }
        if let Some(dc) = &cc.decrypt_config {
            add_to_map(&mut dcparam, &dc.param);
        }
    }

    CryptoConfig {
        encrypt_config: Some(EncryptConfig {
            param: ecparam,
            decrypt_config: Some(DecryptConfig { param: ecdcparam }),
        }),
        decrypt_config: Some(DecryptConfig { param: dcparam }),
    }
}

fn add_to_map(dst: &mut HashMap<String, Vec<Vec<u8>>>, src: &HashMap<String, Vec<Vec<u8>>>) {
    for (k, vlist) in src {
        dst.entry(k.clone()).or_default().extend(vlist.clone());
    }
}
