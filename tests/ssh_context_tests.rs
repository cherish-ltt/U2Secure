#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::process::Command;
use u2secure::domain::ssh_context::SshContext;
use u2secure::infrastructure::ssh::SshConfig;

#[test]
fn explicit_context_is_required_before_querying() {
    assert!(SshContext::parse("admin", "192.0.2.10", "", "192.0.2.20", "22").is_err());
    let context =
        SshContext::parse("admin", "192.0.2.10", "client.example", "192.0.2.20", "22").unwrap();
    assert!(
        SshConfig::new("missing-config", "missing-command")
            .effective_for(&context)
            .is_err()
    );
}

#[test]
fn separators_and_invalid_fields_are_rejected() {
    let valid = ["admin", "192.0.2.10", "client.example", "192.0.2.20", "22"];
    for index in 0..5 {
        for value in ["", "a,b", "a=b", "a b", "a\n", "a\0"] {
            let mut fields = valid;
            fields[index] = value;
            assert!(
                SshContext::parse(fields[0], fields[1], fields[2], fields[3], fields[4]).is_err(),
                "index={index} input={value:?}"
            );
        }
    }
    for (index, value) in [
        (1, "192.0.2.999"),
        (3, "example.com"),
        (4, "0"),
        (4, "65536"),
        (2, "-client"),
        (2, "client..example"),
        (2, "client.."),
    ] {
        let mut fields = valid;
        fields[index] = value;
        assert!(SshContext::parse(fields[0], fields[1], fields[2], fields[3], fields[4]).is_err());
    }
    let ipv6 = SshContext::parse(
        "root",
        "2001:db8::10",
        "2001:db8::10",
        "2001:db8::20",
        "2222",
    )
    .unwrap();
    assert_eq!(
        ipv6.connection_spec(),
        "user=root,addr=2001:db8::10,host=2001:db8::10,laddr=2001:db8::20,lport=2222"
    );
}

fn fixture(script: &str) -> (tempfile::TempDir, SshConfig) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sshd config");
    let program = dir.path().join("sshd fixture");
    std::fs::write(&path, "Include conditions.conf\n").unwrap();
    std::fs::write(&program, format!("#!/bin/sh\n{script}")).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    let ssh = SshConfig::new(&path, &program);
    (dir, ssh)
}

#[test]
fn exact_argv_selects_context_values_without_global_upgrade_or_writes() {
    let (dir, ssh) = fixture(
        r#"
[ "$1" = -T ] && [ "$2" = -f ] && [ -f "$3" ] || exit 41
if [ "$#" = 3 ]; then
  printf 'port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin no\n'
  exit 0
fi
[ "$#" = 5 ] && [ "$4" = -C ] || exit 42
case "$5" in
  user=admin,addr=192.0.2.10,host=client.example,laddr=192.0.2.20,lport=22)
    printf 'port 22\npasswordauthentication yes\nkbdinteractiveauthentication no\npermitrootlogin forced-commands-only\n';;
  user=root,addr=192.0.2.10,host=client.example,laddr=192.0.2.20,lport=22)
    printf 'port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin without-password\n';;
  *) echo 'wrong connection spec' >&2; exit 43;;
esac
"#,
    );
    let before = ssh.effective().unwrap();
    assert!(!before.verified);
    let context =
        SshContext::parse("admin", "192.0.2.10", "client.example", "192.0.2.20", "22").unwrap();
    let result = ssh.effective_for(&context).unwrap();
    assert_eq!(result.password_authentication, "yes");
    assert_eq!(result.kbd_interactive_authentication, "no");
    assert_eq!(result.permit_root_login, "forced-commands-only");
    assert!(!result.matches_baseline());
    let context =
        SshContext::parse("root", "192.0.2.10", "client.example", "192.0.2.20", "22").unwrap();
    assert!(ssh.effective_for(&context).unwrap().matches_baseline());
    assert!(!ssh.effective().unwrap().verified);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("sshd config")).unwrap(),
        "Include conditions.conf\n"
    );
}

#[test]
fn missing_invalid_and_failed_output_never_falls_back_to_globals() {
    let context =
        SshContext::parse("admin", "192.0.2.10", "client.example", "192.0.2.20", "22").unwrap();
    for script in [
        "printf 'passwordauthentication no\npermitrootlogin no\n'",
        "printf 'passwordauthentication unknown\nkbdinteractiveauthentication no\npermitrootlogin no\n'",
        "printf 'passwordauthentication no\npasswordauthentication yes\nkbdinteractiveauthentication no\npermitrootlogin no\n'",
        "printf '\\377'",
        "kill -KILL $$",
    ] {
        let (_dir, ssh) = fixture(script);
        assert!(ssh.effective_for(&context).is_err());
    }
    for reason in [
        "unsupported option -- C",
        "bad Match at line 9",
        "Include missing config",
    ] {
        let (_dir, ssh) = fixture(&format!("printf '%s' '{reason}' >&2\nexit 42"));
        let error = ssh.effective_for(&context).unwrap_err().to_string();
        assert!(error.contains(reason) && error.contains("42"), "{error}");
    }
}

#[test]
fn oversized_output_and_timeout_are_explicit() {
    let context =
        SshContext::parse("admin", "192.0.2.10", "client.example", "192.0.2.20", "22").unwrap();
    let (_dir, ssh) = fixture("/usr/bin/yes fixture");
    let error = ssh.effective_for(&context).unwrap_err().to_string();
    assert!(error.contains("1048576"), "{error}");
    let (_dir, ssh) = fixture("/bin/sleep 10");
    let started = std::time::Instant::now();
    let error = ssh.effective_for(&context).unwrap_err().to_string();
    assert!(
        error.contains(
            &u2secure::i18n::tr("capture_timeout")
                .replace("{program}", "")
                .trim()
                .to_string()
        ),
        "{error}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(8));
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires explicit OpenSSH paths in an isolated Linux environment"]
fn linux_openssh_matches_included_connection_rules() {
    let program =
        std::env::var("U2SECURE_TEST_SSHD").expect("explicit isolated sshd path required");
    let keygen = std::env::var("U2SECURE_TEST_SSH_KEYGEN")
        .expect("explicit isolated ssh-keygen path required");
    assert!(std::path::Path::new(&program).is_absolute());
    assert!(std::path::Path::new(&keygen).is_absolute());
    let dir = tempfile::tempdir().unwrap();
    let host_key = dir.path().join("host-key");
    let generated = Command::new(keygen)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let config_path = dir.path().join("sshd_config");
    let included = dir.path().join("conditions.conf");
    for (global, conditional) in [("no", "yes"), ("yes", "no")] {
        std::fs::write(&included, format!("Match User root Address 192.0.2.10 LocalAddress 192.0.2.20 LocalPort 2222\nPasswordAuthentication {conditional}\nKbdInteractiveAuthentication {conditional}\nPermitRootLogin {conditional}\n")).unwrap();
        std::fs::write(&config_path, format!("HostKey {}\nPort 2222\nUsePAM no\nPasswordAuthentication {global}\nKbdInteractiveAuthentication {global}\nPermitRootLogin {global}\nInclude {}\n", host_key.display(), included.display())).unwrap();
        let ssh = SshConfig::new(&config_path, &program);
        assert!(!ssh.effective().is_ok_and(|config| config.verified));
        for (user, addr, laddr, lport, expected) in [
            ("root", "192.0.2.10", "192.0.2.20", "2222", conditional),
            ("nobody", "192.0.2.10", "192.0.2.20", "2222", global),
            ("root", "192.0.2.11", "192.0.2.20", "2222", global),
            ("root", "192.0.2.10", "192.0.2.21", "2222", global),
            ("root", "192.0.2.10", "192.0.2.20", "2223", global),
        ] {
            let context = SshContext::parse(user, addr, "client.example", laddr, lport).unwrap();
            let result = ssh.effective_for(&context).unwrap();
            let raw = Command::new(&program)
                .arg("-T")
                .arg("-f")
                .arg(&config_path)
                .arg("-C")
                .arg(context.connection_spec())
                .output()
                .unwrap();
            assert!(
                raw.status.success(),
                "{}",
                String::from_utf8_lossy(&raw.stderr)
            );
            let raw = String::from_utf8(raw.stdout).unwrap();
            for (key, value) in [
                ("passwordauthentication", result.password_authentication),
                (
                    "kbdinteractiveauthentication",
                    result.kbd_interactive_authentication,
                ),
                ("permitrootlogin", result.permit_root_login),
            ] {
                assert_eq!(value, expected, "{key}: {}", context.connection_spec());
                assert!(raw.lines().any(|line| line == format!("{key} {value}")));
            }
        }
    }
}
