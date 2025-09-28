use slog::{Logger, info};
use std::io::{Result, Write};

#[derive(Debug)]
pub struct LogWriter(Logger);

impl LogWriter {
    pub fn new(logger: Logger) -> Self {
        LogWriter(logger)
    }
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        buf.split(|b| *b == b'\n').for_each(|it| {
            if !it.is_empty() {
                info!(self.0, "{}", String::from_utf8_lossy(it));
            }
        });

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
