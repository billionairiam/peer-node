mod encryption;
mod payload;

use encryption::{combine_decryption_configs, get_decryption_keys};
use payload::{Payload, get_payload};

use clap::{Arg, Command};
use std::io::{self, Read, Write};
use std::process;

use ocicrypt_rs::encryption::decrypt_layer;

static USAGE: &str = "ctd-decoder is used as a call-out from containerd content stream plugins";

fn main() {
    let payload = match get_payload() {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("failed to get payload {:?}", e);
            std::process::exit(1);
        }
    };

    let matches = Command::new("ctd-decoder")
        .about(USAGE)
        .arg(
            Arg::new("decryption-keys-path")
                .long("decryption-keys-path")
                .help("Path to load decryption keys from. (optional)"),
        )
        .get_matches();

    if let Err(err) = run(&matches, &payload) {
        eprintln!("{}", err);
        process::exit(1);
    }
}

fn run(matches: &clap::ArgMatches, payload: &Payload) -> Result<(), String> {
    if let Err(err) = decrypt(matches, payload) {
        eprintln!("failed to decrypt {}", err);
    }

    Ok(())
}

fn decrypt(
    matches: &clap::ArgMatches,
    payload: &Payload,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut dec_cc = payload.decrypt_config.clone();

    if let Some(path) = matches.get_one::<String>("decryption-keys-path") {
        let key_path_cc = get_decryption_keys(path)?;
        dec_cc =
            combine_decryption_configs(&dec_cc, &key_path_cc.decrypt_config.unwrap_or_default());
    }

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut buf = [0u8; 10 * 1024];
    let (rio, _) = decrypt_layer(
        &dec_cc,
        stdin,
        payload.descriptor.annotations.as_ref(),
        false,
    )
    .map_err(|e| {
        eprintln!("decrypt_layer error {}", e);
        e
    })?;
    let mut r = rio.unwrap();
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        stdout.write_all(&buf[..n])?;
    }

    Ok(())
}
