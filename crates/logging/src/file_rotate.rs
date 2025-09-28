use std::fs::{self, File, OpenOptions};
use std::io::{self, LineWriter, Result, Write};
use std::path::{Path, PathBuf};

/// Default rotate size for logger files.
const DEFAULT_LOG_FILE_SIZE_TO_ROTATE: u64 = 10485760;

/// Default number of log files to keep.
const DEFAULT_HISTORY_LOG_FILES: usize = 3;

#[derive(Debug)]
pub struct FileRotator {
    path: PathBuf,
    file: Option<LineWriter<File>>,
    ignore_errors: bool,
    rotate_size: u64,
    rotate_keep: usize,
    truncate: bool,
    written_size: u64,
}

impl FileRotator {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let p = Path::new(path.as_ref());
        match p.metadata() {
            Ok(md) => {
                if !md.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("path '{}' is not a file", p.to_string_lossy()),
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if let Some(parent) = p.parent() {
            if p.has_root() || !parent.as_os_str().is_empty() {
                let md = parent.metadata()?;
                if !md.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("'{}' is not a directory", parent.to_string_lossy()),
                    ));
                }
            }
        }

        Ok(FileRotator {
            path: p.to_path_buf(),
            file: None,
            ignore_errors: false,
            rotate_size: DEFAULT_LOG_FILE_SIZE_TO_ROTATE,
            rotate_keep: DEFAULT_HISTORY_LOG_FILES,
            truncate: false,
            written_size: 0,
        })
    }

    pub fn truncate_mode(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }

    pub fn rotate_threshold(&mut self, size: u64) -> &mut Self {
        self.rotate_size = size;
        self
    }

    pub fn rotate_count(&mut self, count: usize) -> &mut Self {
        self.rotate_keep = count;
        self
    }

    pub fn ignore_errors(&mut self, ignore_errors: bool) -> &mut Self {
        self.ignore_errors = ignore_errors;
        self
    }

    fn reopen_if_needed(&mut self) -> Result<()> {
        if self.file.is_none() || !self.path.exists() {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(self.truncate)
                .append(!self.truncate)
                .open(&self.path)?;
            match file.metadata() {
                Ok(md) => self.written_size = md.len(),
                Err(e) => {
                    if self.ignore_errors {
                        self.written_size = 0;
                    } else {
                        return Err(e);
                    }
                }
            }
            self.file = Some(LineWriter::new(file));
        }

        Ok(())
    }

    fn rotate(&mut self) -> Result<()> {
        for i in (1..=self.rotate_keep).rev() {
            let from = self.rotated_path(i);
            let to = self.rotated_path(i + 1);
            if from.exists() {
                let _ = fs::rename(from, to);
            }
        }

        if self.path.exists() {
            let rotated_path = self.rotated_path(1);
            let _ = fs::rename(&self.path, rotated_path);
        }

        let deleted_path = self.rotated_path(self.rotate_keep - 1);
        if deleted_path.exists() {
            let _ = fs::remove_file(deleted_path);
        }

        // Reset the `written_size` so only try to rotate again when another `rotate_size` bytes
        // of log messages have been written to the lo file.
        self.written_size = 0;
        self.reopen_if_needed()?;

        Ok(())
    }

    fn rotated_path(&self, i: usize) -> PathBuf {
        let mut path = self.path.clone().into_os_string();
        path.push(format!(".{}", i));
        PathBuf::from(path)
    }
}

impl Write for FileRotator {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.ignore_errors {
            let _ = self.reopen_if_needed();
            if let Some(file) = self.file.as_mut() {
                let _ = file.write_all(buf);
            }
        } else {
            self.reopen_if_needed()?;
            match self.file.as_mut() {
                Some(file) => file.write_all(buf)?,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("can't open file: {:?}", self.path),
                    ));
                }
            }
        }

        self.written_size += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(f) = self.file.as_mut() {
            if let Err(e) = f.flush() {
                if !self.ignore_errors {
                    return Err(e);
                }
            }
        }
        if self.written_size >= self.rotate_size {
            if let Err(e) = self.rotate() {
                if !self.ignore_errors {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}
