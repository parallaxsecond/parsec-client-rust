// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Handler for Unix domain sockets
use super::{Connect, ReadWrite};
use crate::error::{ClientErrorKind, Result};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(not(feature = "no-fs-permission-check"))]
use log::error;
#[cfg(not(feature = "no-fs-permission-check"))]
use std::ffi::OsStr;
#[cfg(not(feature = "no-fs-permission-check"))]
use std::fs;
#[cfg(not(feature = "no-fs-permission-check"))]
use std::io::{Error, ErrorKind};
#[cfg(not(feature = "no-fs-permission-check"))]
use std::os::unix::fs::MetadataExt;

const DEFAULT_SOCKET_PATH: &str = "/tmp/parsec/parsec.sock";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// IPC handler for Unix domain sockets
#[derive(Debug, Clone)]
pub struct Handler {
    /// Path at which the socket can be found
    path: PathBuf,
    /// Timeout for reads and writes on the streams
    timeout: Option<Duration>,
}

impl Connect for Handler {
    fn connect(&self) -> Result<Box<dyn ReadWrite>> {
        #[cfg(not(feature = "no-fs-permission-check"))]
        self.secure_parsec_socket_folder()?;

        let stream = UnixStream::connect(self.path.clone()).map_err(ClientErrorKind::Ipc)?;

        stream
            .set_read_timeout(self.timeout)
            .map_err(ClientErrorKind::Ipc)?;
        stream
            .set_write_timeout(self.timeout)
            .map_err(ClientErrorKind::Ipc)?;

        Ok(Box::from(stream))
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }
}

impl Handler {
    /// Create new client using given socket path and timeout duration
    pub fn new(path: PathBuf, timeout: Option<Duration>) -> Self {
        Handler { path, timeout }
    }

    /// Checks if the socket is inside a folder with correct owners and permissions to make sure it
    /// is from the Parsec service.
    #[cfg(not(feature = "no-fs-permission-check"))]
    fn secure_parsec_socket_folder(&self) -> Result<()> {
        let mut socket_dir = self.path.clone();
        if !socket_dir.pop() {
            return Err(ClientErrorKind::Ipc(Error::new(
                ErrorKind::Other,
                "Socket permission checks failed",
            ))
            .into());
        }
        let meta = fs::metadata(socket_dir).map_err(ClientErrorKind::Ipc)?;

        match users::get_user_by_uid(meta.uid()) {
            Some(user) => {
                if user.name() != OsStr::new("parsec") {
                    error!("The socket directory must be owned by the parsec user.");
                    return Err(ClientErrorKind::Ipc(Error::new(
                        ErrorKind::Other,
                        "Socket permission checks failed",
                    ))
                    .into());
                }
            }
            None => {
                error!("Can not find socket directory user owner.");
                return Err(ClientErrorKind::Ipc(Error::new(
                    ErrorKind::Other,
                    "Socket permission checks failed",
                ))
                .into());
            }
        }

        match users::get_group_by_gid(meta.gid()) {
            Some(group) => {
                if group.name() != OsStr::new("parsec-clients") {
                    error!("The socket directory must be owned by the parsec-clients group.");
                    return Err(ClientErrorKind::Ipc(Error::new(
                        ErrorKind::Other,
                        "Socket permission checks failed",
                    ))
                    .into());
                }
            }
            None => {
                error!("Can not find socket directory group owner.");
                return Err(ClientErrorKind::Ipc(Error::new(
                    ErrorKind::Other,
                    "Socket permission checks failed",
                ))
                .into());
            }
        }

        if (meta.mode() & 0o777) != 0o750 {
            error!("The permission bits of the folder containing the Parsec socket must be 750.");
            return Err(ClientErrorKind::Ipc(Error::new(
                ErrorKind::Other,
                "Socket permission checks failed",
            ))
            .into());
        }

        Ok(())
    }
}

impl Default for Handler {
    fn default() -> Self {
        Handler {
            path: DEFAULT_SOCKET_PATH.into(),
            timeout: Some(DEFAULT_TIMEOUT),
        }
    }
}
