use super::*;
use std::fs;

fn plan(dir: &Path) -> AidePlan {
    AidePlan {
        source: "generated",
        config: Some(dir.join("aide.conf")),
        database_out: dir.join("database.new"),
        database_in: dir.join("database"),
    }
}

#[test]
fn wrapper_config_and_command_selection_use_fixture_paths() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("aide.conf");
    fs::write(&config, "database_in=file:/fixture/db\n").unwrap();
    let wrapper = dir.path().join("aideinit");
    for declaration in [
        format!("CONFIG={}", config.display()),
        format!("export CONFIG=\"${{CONFIG:-{}}}\"", config.display()),
        format!("CONFIG='{}'", config.display()),
    ] {
        fs::write(&wrapper, format!("# wrapper\n{declaration}\n")).unwrap();
        assert_eq!(wrapper_config_path(&wrapper), Some(config.clone()));
    }
    fs::write(
        &wrapper,
        "CONFIG=relative\nCONFIG=/nonexistent/u2secure.conf\n",
    )
    .unwrap();
    assert_eq!(wrapper_config_path(&wrapper), None);
    assert_eq!(wrapper_config_path(&dir.path().join("missing")), None);
    let mut plan = plan(dir.path());
    let command = plan.init_command_with_wrappers(&[&wrapper]);
    assert_eq!(
        command.argv,
        [
            wrapper.display().to_string(),
            "-y".into(),
            "-f".into(),
            "-c".into(),
            config.display().to_string()
        ]
    );
    assert_eq!(
        plan.init_command_with_wrappers(&[]).argv,
        [
            "aide".into(),
            format!("--config={}", config.display()),
            "--init".into()
        ]
    );
    plan.config = None;
    assert_eq!(plan.init_command_with_wrappers(&[&wrapper]).argv.len(), 3);
    assert_eq!(
        plan.init_command_with_wrappers(&[]).argv,
        ["aide", "--init"]
    );
    assert_eq!(plan.check_command().argv, ["aide", "--check"]);
    assert_eq!(plan.config_check_command().argv, ["aide", "--config-check"]);
    assert_eq!(standard_config_paths(PackageManager::Apt).len(), 2);
    assert_eq!(
        standard_config_paths(PackageManager::Dnf),
        [PathBuf::from("/etc/aide.conf")]
    );
    assert!(render_daily_script(None, "/fixture/log").contains("aide --check"));
}

#[test]
fn fallback_paths_and_files_remain_inside_supplied_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    fs::create_dir(&db).unwrap();
    let candidate = db.to_str().unwrap();
    let selected = fallback_plan_with(dir.path(), &[candidate]);
    assert_eq!(selected.database_in.parent(), Some(db.as_path()));
    assert_eq!(fs::read_dir(&db).unwrap().count(), 0);
    assert_eq!(
        fallback_plan_with(dir.path(), &[]).database_in.parent(),
        Some(dir.path())
    );
    assert!(!is_writable_dir(&dir.path().join("missing")));
    let mut plan = plan(dir.path());
    ensure_fallback_config(&mut plan).unwrap();
    assert!(
        fs::read_to_string(plan.config.as_ref().unwrap())
            .unwrap()
            .contains("database_in=file:")
    );
    plan.reload_database_paths();
    assert_eq!(plan.database_in, dir.path().join("database"));
    plan.config = Some(dir.path().join("missing.conf"));
    plan.reload_database_paths();
    assert_eq!(plan.database_in, dir.path().join("database"));
    plan.config = None;
    assert!(ensure_fallback_config(&mut plan).is_err());
    let file = dir.path().join("blocked");
    fs::write(&file, "not a directory").unwrap();
    assert!(write_config(&file.join("config"), &plan).is_err());
    assert!(write_config(dir.path(), &plan).is_err());
    assert_eq!(
        parse_database_path("database_in=   # empty", "database_in"),
        None
    );
}

#[test]
fn database_promotion_preserves_existing_baselines_and_reports_errors() {
    let dir = tempfile::tempdir().unwrap();
    let mut plan = plan(dir.path());
    assert!(!plan.database_ready());
    assert!(plan.database_metadata().is_empty());
    assert!(
        promote_database(&plan)
            .unwrap_err()
            .to_string()
            .contains("database.new")
    );
    fs::write(&plan.database_out, "NEW_DATABASE").unwrap();
    promote_database(&plan).unwrap();
    assert!(plan.database_ready());
    assert_eq!(
        fs::read_to_string(&plan.database_in).unwrap(),
        "NEW_DATABASE"
    );
    assert!(plan.database_metadata().contains("database"));
    #[cfg(unix)]
    assert_eq!(read_mode(&plan.database_in), Some(0o600));
    fs::write(&plan.database_out, "REPLACEMENT").unwrap();
    promote_database(&plan).unwrap();
    assert_eq!(
        fs::read_to_string(&plan.database_in).unwrap(),
        "NEW_DATABASE"
    );
    plan.database_in = dir.path().join("missing/db");
    assert!(
        promote_database(&plan)
            .unwrap_err()
            .to_string()
            .contains("missing/db")
    );
    assert!(read_mode(&plan.database_in).is_none());
    fs::remove_file(&plan.database_out).unwrap();
    let gzip = PathBuf::from(format!("{}.gz", plan.database_out.display()));
    fs::write(&gzip, "COMPRESSED_MARKER").unwrap();
    assert_eq!(plan.existing_database(&plan.database_out), Some(gzip));
}

#[test]
fn initialization_requires_database_output_and_a_successful_or_difference_check() {
    for code in [0, 1, 7, 14, 17] {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan(dir.path());
        let log = dir.path().join("init.log");
        let check = dir.path().join("check.log");
        let mut calls = 0;
        let result = initialize_database_with(&plan, &log, &check, |command, path| {
            calls += 1;
            if calls == 1 {
                assert_eq!(path, log);
                fs::write(&plan.database_out, "DATABASE_MARKER").unwrap();
                Ok(StreamStatus::Success)
            } else {
                assert_eq!(path, check);
                assert_eq!(command, &plan.check_command());
                assert_eq!(
                    fs::read_to_string(&plan.database_in).unwrap(),
                    "DATABASE_MARKER"
                );
                Ok(if code == 0 {
                    StreamStatus::Success
                } else {
                    StreamStatus::Failed(Some(code))
                })
            }
        });
        assert_eq!(calls, 2);
        assert_eq!(result.is_ok(), code < 14);
        if let Err(error) = result {
            assert!(error.to_string().contains(&code.to_string()));
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut plan = plan(dir.path());
    for status in [
        StreamStatus::Failed(Some(17)),
        StreamStatus::TimedOut,
        StreamStatus::Cancelled,
    ] {
        let result = initialize_database_with(
            &plan,
            &dir.path().join("log"),
            &dir.path().join("check"),
            |_, _| Ok(status),
        );
        assert!(result.is_err());
        assert!(!plan.database_ready());
    }
    let error = initialize_database_with(
        &plan,
        &dir.path().join("log"),
        &dir.path().join("check"),
        |_, _| Err(DomainError::SystemCommandFailed("SPAWN_FAILURE".into())),
    )
    .unwrap_err();
    assert!(error.to_string().contains("SPAWN_FAILURE"));
    plan.config = None;
    assert!(init_failure_hint(&StreamStatus::Failed(Some(17)), &plan).contains("17"));
}

#[cfg(unix)]
#[test]
fn aide_config_checks_use_a_fake_binary_and_preserve_exit_status() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let aide = dir.path().join("aide");
    fs::write(
        &aide,
        "#!/bin/sh\nprintf CONFIG_CHECK_MARKER\nexit \"$U2C_AIDE_EXIT\"\n",
    )
    .unwrap();
    fs::set_permissions(aide, fs::Permissions::from_mode(0o700)).unwrap();
    for code in ["0", "17"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "infrastructure::aide::coverage_tests::isolated_aide_config_check",
                "--nocapture",
            ])
            .env("PATH", dir.path())
            .env("U2C_AIDE_EXIT", code)
            .env("U2C_AIDE_DIR", dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn isolated_aide_config_check() {
    let Ok(code) = std::env::var("U2C_AIDE_EXIT") else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os("U2C_AIDE_DIR").unwrap());
    let log = dir.join("check.log");
    let problem = config_problem(&plan(&dir), &log).unwrap();
    assert_eq!(problem.is_none(), code == "0");
    if let Some(problem) = problem {
        assert!(problem.contains("17"));
    }
    assert!(
        fs::read_to_string(log)
            .unwrap()
            .contains("CONFIG_CHECK_MARKER")
    );
}
