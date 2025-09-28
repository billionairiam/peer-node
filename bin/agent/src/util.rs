use anyhow::{Result, anyhow};
use futures::StreamExt;
use std::io;
use std::io::ErrorKind;
use std::os::unix::io::{FromRawFd, RawFd};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch::Receiver;
use tokio_vsock::{Incoming, VsockListener, VsockStream};
use tracing::instrument;

// Size of I/O read buffer
const BUF_SIZE: usize = 8192;

// Interruptable I/O copy using readers and writers
// (an interruptable version of "io::copy()").
pub async fn interruptable_io_copier<R, W>(
    mut reader: R,
    mut writer: W,
    mut shutdown: Receiver<bool>,
) -> io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin + Sized,
    W: tokio::io::AsyncWrite + Unpin + Sized,
{
    let mut total_bytes: u64 = 0;

    let mut buf: [u8; BUF_SIZE] = [0; BUF_SIZE];

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                eprintln!("INFO: interruptable_io_copier: got shutdown request");
                break;
            }

            result = reader.read(&mut buf) => {
                let bytes = match result {
                    Ok(0) => return Ok(total_bytes),
                    Ok(len) => len,
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };

                total_bytes += bytes as u64;

                writer.write_all(&buf[..bytes]).await?;
            }
        }
    }
    Ok(total_bytes)
}

#[instrument]
pub fn get_vsock_incoming(fd: RawFd) -> Incoming {
    unsafe { VsockListener::from_raw_fd(fd).incoming() }
}

#[instrument]
pub async fn get_vsock_stream(fd: RawFd) -> Result<VsockStream> {
    let stream = get_vsock_incoming(fd)
        .next()
        .await
        .ok_or_else(|| anyhow!("can't handle incoming vsock connection"))?;

    Ok(stream?)
}
