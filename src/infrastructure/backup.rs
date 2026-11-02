use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use crate::domain::errors::DomainError;

pub fn backup_file(path: &Path) -> Result<Option<PathBuf>, DomainError> {
    let backup = || -> io::Result<Option<PathBuf>> {
        let mut source = match File::open(path) {
            Ok(source) => source,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let prefix = format!(
            "{}.bak.",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        let mut target = tempfile::Builder::new()
            .prefix(&prefix)
            .tempfile_in(path.parent().unwrap_or_else(|| Path::new(".")))?;
        io::copy(&mut source, &mut target)?;
        target
            .as_file()
            .set_permissions(source.metadata()?.permissions())?;
        let (_, path) = target.keep().map_err(|e| e.error)?;
        Ok(Some(path))
    };
    backup().map_err(|e| {
        DomainError::SystemCommandFailed(format!(
            "{} {}: {e}",
            crate::i18n::tr("err_backup"),
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backups_are_unique_and_never_overwrite_existing_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        assert!(backup_file(&path).unwrap().is_none());
        std::fs::write(&path, "original").unwrap();
        let first = backup_file(&path).unwrap().unwrap();
        std::fs::write(&path, "changed").unwrap();
        let second = backup_file(&path).unwrap().unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(first).unwrap(), "original");
        assert_eq!(std::fs::read_to_string(second).unwrap(), "changed");
        assert!(backup_file(dir.path()).is_err());
    }
}
