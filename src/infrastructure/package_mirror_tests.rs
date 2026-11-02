use super::*;
use std::fs;

fn session(pm: PackageManager) -> MirrorSession {
    let mut session = MirrorSession::apply(PackageMirror::Original, pm).unwrap();
    session.mirror = PackageMirror::Tsinghua;
    session
}

#[test]
fn apt_sources_are_copied_without_changing_originals() {
    let input = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let list = input.path().join("sources.list");
    let parts = input.path().join("parts");
    fs::create_dir(&parts).unwrap();
    let original = "deb https://deb.debian.org/debian stable main\n";
    fs::write(&list, original).unwrap();
    fs::write(
        parts.join("extra.list"),
        "deb https://security.debian.org/debian-security stable-security main\n",
    )
    .unwrap();
    fs::write(
        parts.join("debian.sources"),
        "Types: deb\nURIs: https://deb.debian.org/debian\nSuites: stable\n",
    )
    .unwrap();
    fs::write(parts.join("ignored.txt"), original).unwrap();
    fs::create_dir(parts.join("unreadable.list")).unwrap();
    fs::create_dir(parts.join("unreadable.sources")).unwrap();
    let mut session = session(PackageManager::Apt);
    session.build_apt(&output, &list, &parts).unwrap();
    assert!(session.is_active());
    assert_eq!(session.rewritten_files, 3);
    assert_eq!(session.rewritten_entries, 3);
    let over = session.override_value();
    let copied = fs::read_to_string(over.apt_sourcelist.unwrap()).unwrap();
    assert!(copied.contains("mirrors.tuna.tsinghua.edu.cn/debian"));
    assert!(copied.contains("stable-security"));
    let copied_parts = std::path::PathBuf::from(over.apt_sourceparts.unwrap());
    assert!(
        fs::read_to_string(copied_parts.join("debian.sources"))
            .unwrap()
            .contains("mirrors.tuna.tsinghua.edu.cn")
    );
    assert!(!copied_parts.join("ignored.txt").exists());
    assert_eq!(fs::read_to_string(&list).unwrap(), original);
    assert_eq!(session.mirror(), &PackageMirror::Tsinghua);
    assert!(session.summary().contains('3'));
    let generated = output.path().to_path_buf();
    session.dir = Some(output);
    drop(session);
    assert!(!generated.exists());
    assert_eq!(fs::read_to_string(list).unwrap(), original);
}

#[test]
fn mirror_builders_handle_missing_sources_and_temp_write_failures() {
    let input = tempfile::tempdir().unwrap();
    let missing = input.path().join("missing");
    let output = tempfile::tempdir().unwrap();
    let mut apt = session(PackageManager::Apt);
    apt.build_apt(&output, &missing, &missing).unwrap();
    assert!(!apt.is_active());
    assert!(!apt.summary().is_empty());
    let blocked = tempfile::tempdir().unwrap();
    fs::write(blocked.path().join("parts"), "not a directory").unwrap();
    assert!(apt.build_apt(&blocked, &missing, &missing).is_err());
    let source = input.path().join("sources.list");
    fs::write(&source, "deb https://deb.debian.org/debian stable main\n").unwrap();
    fs::create_dir(output.path().join("sources.list")).unwrap();
    assert!(apt.build_apt(&output, &source, &missing).is_err());

    let mut yum = session(PackageManager::Yum);
    yum.build_yum(&output, &missing).unwrap();
    assert!(!yum.is_active());
    fs::write(blocked.path().join("yum.repos.d"), "blocked").unwrap();
    assert!(yum.build_yum(&blocked, &missing).is_err());
    assert!(
        !MirrorSession::apply(PackageMirror::Tsinghua, PackageManager::Unknown)
            .unwrap()
            .is_active()
    );
}

#[test]
fn yum_only_rewrites_baseurls_and_reports_skipped_mirrorlists() {
    let input = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let repo = "[base]\nbaseurl=https://mirror.centos.org/centos/9/os/\n";
    let list = "[dynamic]\nmirrorlist=https://mirrorlist.centos.org/?release=9\n";
    fs::write(input.path().join("base.repo"), repo).unwrap();
    fs::write(input.path().join("dynamic.repo"), list).unwrap();
    fs::write(input.path().join("ignored.txt"), repo).unwrap();
    fs::create_dir(input.path().join("unreadable.repo")).unwrap();
    let mut session = session(PackageManager::Dnf);
    session.build_yum(&output, input.path()).unwrap();
    assert_eq!(session.rewritten_files, 1);
    assert_eq!(session.skipped_repos, 1);
    assert!(session.summary().contains('1'));
    let target = session.override_value().yum_reposdir.unwrap();
    let target = std::path::Path::new(&target);
    assert!(
        fs::read_to_string(target.join("base.repo"))
            .unwrap()
            .contains("mirrors.tuna.tsinghua.edu.cn")
    );
    assert_eq!(
        fs::read_to_string(target.join("dynamic.repo")).unwrap(),
        list
    );
    assert_eq!(
        fs::read_to_string(input.path().join("base.repo")).unwrap(),
        repo
    );
    assert!(!target.join("ignored.txt").exists());
    assert!(
        session
            .pm_argv(PackageManager::Yum, &["install", "-y", "aide"])
            .iter()
            .any(|arg| arg.starts_with("--setopt=reposdir="))
    );
}

#[test]
fn warmup_skips_other_managers_and_propagates_execution_errors() {
    let mut other = session(PackageManager::Dnf);
    other.override_.yum_reposdir = Some("temporary-repos".into());
    warm_up_with(&other, &mut |_, _| panic!("no callback"), |_| {
        panic!("no command")
    })
    .unwrap();
    let mut apt = session(PackageManager::Apt);
    apt.override_.apt_sourcelist = Some("temporary-list".into());
    let error = warm_up_with(&apt, &mut |_, _| panic!("no status callback"), |_| {
        Err(DomainError::SystemCommandFailed("cannot spawn".into()))
    })
    .unwrap_err();
    assert!(error.contains("cannot spawn"));
    let mut calls = 0;
    let mut failures = Vec::new();
    warm_up_with(
        &apt,
        &mut |attempt, reason| failures.push((attempt, reason)),
        |_| {
            calls += 1;
            Ok(if calls < 3 {
                system::StreamStatus::NoResponse
            } else {
                system::StreamStatus::Success
            })
        },
    )
    .unwrap();
    assert_eq!(calls, 3);
    assert_eq!(failures.len(), 2);
    assert_eq!(failures[1].0, 2);
    assert!(probe_latency(&PackageMirror::Original).is_none());
    assert_eq!(
        build_pm_argv(
            PackageManager::Unknown,
            &MirrorOverride::default(),
            &["update"]
        ),
        ["unknown", "update"]
    );
}
