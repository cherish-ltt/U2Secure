use std::fs::File;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::{Component, PathBuf};
use std::process::Command;

use rustix::fd::OwnedFd;
use rustix::fs::{self, FileType, Mode, OFlags};
use rustix::process::{Gid, Uid};

use crate::domain::errors::DomainError;

pub(super) fn add_authorized_key(username: &str, key: &str) -> Result<(), DomainError> {
    let account = Account::lookup(username)?;
    let dir = KeyDirectory::open(&account).map_err(key_error)?;
    dir.append(key).map_err(key_error)
}

fn key_error(error: impl std::fmt::Display) -> DomainError {
    DomainError::SystemCommandFailed(
        crate::i18n::tr("err_secure_key_file").replace("{error}", &error.to_string()),
    )
}

struct Account {
    home: PathBuf,
    uid: Uid,
    gid: Gid,
}

impl Account {
    fn lookup(username: &str) -> Result<Self, DomainError> {
        if username.is_empty() || username.starts_with('-') || username.contains(['/', '\0']) {
            return Err(key_error("invalid account name"));
        }
        let output = super::system::run_cmd("getent", &["passwd", username])?;
        Self::parse(username, &output).map_err(key_error)
    }

    fn parse(username: &str, output: &str) -> io::Result<Self> {
        let fields: Vec<_> = output.trim_end().split(':').collect();
        if fields.len() != 7 || fields[0] != username || output.trim_end().contains('\n') {
            return Err(unsafe_path());
        }
        let uid = fields[2].parse().map_err(|_| unsafe_path())?;
        let gid = fields[3].parse().map_err(|_| unsafe_path())?;
        if uid == u32::MAX || gid == u32::MAX {
            return Err(unsafe_path());
        }
        Ok(Self {
            home: fields[5].into(),
            uid: Uid::from_raw(uid),
            gid: Gid::from_raw(gid),
        })
    }
}

struct KeyDirectory {
    fd: OwnedFd,
    uid: Uid,
    gid: Gid,
}

impl KeyDirectory {
    fn open(account: &Account) -> io::Result<Self> {
        if !account.home.is_absolute() {
            return Err(unsafe_path());
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut home = fs::open("/", flags, Mode::empty())?;
        for component in account.home.components() {
            match component {
                Component::RootDir => {},
                Component::Normal(name) => home = fs::openat(&home, name, flags, Mode::empty())?,
                _ => return Err(unsafe_path()),
            }
            let metadata = fs::fstat(&home)?;
            let trusted_sticky = metadata.st_uid == 0 && metadata.st_mode & 0o1000 != 0;
            if ![0, account.uid.as_raw()].contains(&metadata.st_uid)
                || (metadata.st_mode & 0o022 != 0 && !trusted_sticky)
            {
                return Err(unsafe_path());
            }
        }
        let metadata = fs::fstat(&home)?;
        if metadata.st_uid != account.uid.as_raw() || metadata.st_mode & 0o022 != 0 {
            return Err(unsafe_path());
        }
        let fd = match fs::openat(&home, ".ssh", flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => {
                // uid() also clears inherited supplementary groups before dropping privileges.
                let output = Command::new("/bin/mkdir")
                    .arg("-m")
                    .arg("700")
                    .arg(account.home.join(".ssh"))
                    .uid(account.uid.as_raw())
                    .gid(account.gid.as_raw())
                    .output()?;
                if !output.status.success() {
                    return Err(io::Error::other(format!(
                        "mkdir: {}: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
                fs::openat(&home, ".ssh", flags, Mode::empty())?
            },
            Err(error) => return Err(error.into()),
        };
        let metadata = fs::fstat(&fd)?;
        if metadata.st_uid != account.uid.as_raw() || metadata.st_mode & 0o022 != 0 {
            return Err(unsafe_path());
        }
        Ok(Self {
            fd,
            uid: account.uid,
            gid: account.gid,
        })
    }

    fn authorized_file(&self) -> io::Result<File> {
        let flags =
            OFlags::WRONLY | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let (fd, created) = match fs::openat(
            &self.fd,
            "authorized_keys",
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => (fd, true),
            Err(rustix::io::Errno::EXIST) => (
                fs::openat(&self.fd, "authorized_keys", flags, Mode::empty())?,
                false,
            ),
            Err(error) => return Err(error.into()),
        };
        let metadata = fs::fstat(&fd)?;
        let expected_uid = if created {
            rustix::process::geteuid()
        } else {
            self.uid
        };
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != expected_uid.as_raw()
            || metadata.st_nlink != 1
        {
            return Err(unsafe_path());
        }
        if created {
            fs::fchown(&fd, Some(self.uid), Some(self.gid))?;
        }
        fs::fchmod(&fd, Mode::from_raw_mode(0o600))?;
        Ok(File::from(fd))
    }

    fn append(&self, key: &str) -> io::Result<()> {
        let mut file = self.authorized_file()?;
        writeln!(file, "{key}")?;
        file.sync_all()
    }
}

fn unsafe_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unsafe SSH directory or file",
    )
}

#[cfg(test)]
#[path = "ssh_keys_tests.rs"]
mod tests;
