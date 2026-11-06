use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};

use super::{Account, KeyDirectory, key_error, unsafe_path};
use crate::domain::errors::DomainError;
use crate::domain::undo::UndoAction;
use crate::infrastructure::rollback;

const NAMES: [&str; 2] = ["id_ed25519", "id_ed25519.pub"];

pub(crate) fn generate_ssh_keypair(username: &str, replace: bool) -> Result<String, DomainError> {
    let account = Account::lookup(username)?;
    let dir = Arc::new(KeyDirectory::open(&account).map_err(key_error)?);
    let generated = tempfile::Builder::new()
        .prefix("u2secure-keygen-")
        .tempdir()
        .map_err(key_error)?;
    let output = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(generated.path().join(NAMES[0]))
        .stdin(Stdio::null())
        .output()
        .map_err(key_error)?;
    if !output.status.success() {
        return Err(key_error(format!(
            "ssh-keygen: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    install_pair(dir, generated.path(), replace).map_err(key_error)?;
    Ok(account
        .home
        .join(".ssh")
        .join(NAMES[1])
        .to_string_lossy()
        .into_owned())
}

fn install_pair(dir: Arc<KeyDirectory>, generated: &Path, replace: bool) -> io::Result<()> {
    let contents = NAMES
        .map(|name| std::fs::read(generated.join(name)))
        .into_iter()
        .collect::<io::Result<Vec<_>>>()?;
    let backup = tempfile::Builder::new()
        .prefix("u2secure-key-backup-")
        .tempdir()?;
    let mut entries = Vec::new();
    for name in NAMES {
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        match fs::openat(&dir.fd, name, flags, Mode::empty()) {
            Ok(fd) => {
                let metadata = fs::fstat(&fd)?;
                if !replace {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "SSH key already exists; replacement requires confirmation",
                    ));
                }
                if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
                    || metadata.st_uid != dir.uid.as_raw()
                    || metadata.st_nlink != 1
                {
                    return Err(unsafe_path());
                }
                let mut file = File::from(fd);
                let mut old = Vec::new();
                file.read_to_end(&mut old)?;
                let path = backup.path().join(name);
                let mut saved = File::create(&path)?;
                saved.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                saved.write_all(&old)?;
                saved.sync_all()?;
                entries.push(KeyEntry {
                    name,
                    file: Some(file),
                    old_mode: Some(Mode::from_raw_mode(metadata.st_mode & 0o777)),
                });
            },
            Err(rustix::io::Errno::NOENT) => entries.push(KeyEntry {
                name,
                file: None,
                old_mode: None,
            }),
            Err(error) => return Err(error.into()),
        }
    }
    let mut update = KeyUpdate {
        dir,
        entries,
        backup,
    };
    let result = update.write(&contents);
    rollback::register_tracked(
        UndoAction::try_new(
            crate::i18n::tr("undo_key_restore").into(),
            Box::new(move || update.restore().map_err(key_error)),
        ),
        "key_restore_temporary",
        &[],
    );
    result
}

struct KeyEntry {
    name: &'static str,
    file: Option<File>,
    old_mode: Option<Mode>,
}

struct KeyUpdate {
    dir: Arc<KeyDirectory>,
    entries: Vec<KeyEntry>,
    backup: tempfile::TempDir,
}

impl KeyUpdate {
    fn write(&mut self, contents: &[Vec<u8>]) -> io::Result<()> {
        for (entry, bytes) in self.entries.iter_mut().zip(contents) {
            if entry.file.is_none() {
                let flags = OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC;
                let fd = fs::openat(&self.dir.fd, entry.name, flags, Mode::from_raw_mode(0o600))?;
                entry.file = Some(File::from(fd));
                fs::fchown(
                    entry.file.as_ref().ok_or_else(unsafe_path)?,
                    Some(self.dir.uid),
                    Some(self.dir.gid),
                )?;
            }
            let file = entry.file.as_mut().ok_or_else(unsafe_path)?;
            file.rewind()?;
            file.set_len(0)?;
            file.write_all(bytes)?;
            fs::fchmod(&*file, Mode::from_raw_mode(0o600))?;
            file.sync_all()?;
        }
        Ok(())
    }

    fn restore(mut self) -> io::Result<()> {
        let mut errors = Vec::new();
        for entry in &mut self.entries {
            let Some(file) = &mut entry.file else {
                continue;
            };
            let result = (|| -> io::Result<()> {
                if let Some(mode) = entry.old_mode {
                    let old = std::fs::read(self.backup.path().join(entry.name))?;
                    file.rewind()?;
                    file.set_len(0)?;
                    file.write_all(&old)?;
                    fs::fchmod(&*file, mode)?;
                    file.sync_all()?;
                }
                let current = match fs::statat(&self.dir.fd, entry.name, AtFlags::SYMLINK_NOFOLLOW)
                {
                    Ok(current) => current,
                    Err(rustix::io::Errno::NOENT) if entry.old_mode.is_none() => return Ok(()),
                    Err(error) => return Err(error.into()),
                };
                let opened = fs::fstat(&*file)?;
                if current.st_dev != opened.st_dev || current.st_ino != opened.st_ino {
                    return Err(io::Error::other("SSH key path changed during rollback"));
                }
                if entry.old_mode.is_none() {
                    fs::unlinkat(&self.dir.fd, entry.name, AtFlags::empty())?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                errors.push(format!("{}: {error}", entry.name));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            let path = self.backup.keep();
            Err(io::Error::other(format!(
                "{}; backup: {}",
                errors.join("; "),
                path.display()
            )))
        }
    }
}

#[cfg(test)]
#[path = "ssh_keypair_tests.rs"]
mod tests;
