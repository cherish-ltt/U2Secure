#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use u2secure::application::steps::change_ssh_port;
use u2secure::infrastructure::{rollback, ssh::SshConfig, ufw::Ufw};

fn script(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

const FAKE: &str = r#"#!/bin/sh
cd "$(dirname "$0")" || exit 70
echo "$*" >> calls
case "$1" in
 status) printf 'Status: '; cat active;;
 allow)
   [ -f fail-allow ] && { echo 'allow failure' >&2; exit 19; }
   for file in user.rules user6.rules; do
     grep -qx "$2" "$file" 2>/dev/null || echo "$2" >> "$file"
   done
   [ ! -f fail-after ] || { echo 'partial allow failure' >&2; exit 20; };;
 --force)
   if [ "$2" = enable ]; then echo active > active; echo enabled > ufw.conf
   else echo inactive > active; echo disabled > ufw.conf; fi;;
 reload) [ ! -f fail-reload ] || { echo 'reload failure' >&2; exit 23; }; echo active > active;;
 *) exit 71;;
esac
"#;

#[test]
fn firewall_snapshots_preserve_existing_rules_and_stop_ssh_on_failure() {
    for active in [false, true] {
        for ipv4 in [false, true] {
            for ipv6 in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let root = dir.path();
                let program = root.join("ufw-fake");
                script(&program, FAKE);
                std::fs::write(
                    root.join("active"),
                    if active { "active\n" } else { "inactive\n" },
                )
                .unwrap();
                std::fs::write(root.join("ufw.conf"), "original config\n").unwrap();
                for (name, exists) in [("user.rules", ipv4), ("user6.rules", ipv6)] {
                    if exists {
                        std::fs::write(root.join(name), "2222\n").unwrap();
                    }
                }
                let ufw = Ufw::new(root, program);
                assert_eq!(
                    ufw.allow_port(2222, true).unwrap(),
                    !active || !ipv4 || !ipv6
                );
                assert!(rollback::undo_all().is_empty());
                assert_eq!(ufw.enabled().unwrap(), active);
                assert_eq!(
                    std::fs::read_to_string(root.join("ufw.conf")).unwrap(),
                    "original config\n"
                );
                for (name, existed) in [("user.rules", ipv4), ("user6.rules", ipv6)] {
                    assert_eq!(root.join(name).exists(), existed);
                    if existed {
                        assert_eq!(std::fs::read_to_string(root.join(name)).unwrap(), "2222\n");
                    }
                }
                assert!(
                    !std::fs::read_to_string(root.join("calls"))
                        .unwrap()
                        .contains("delete")
                );
            }
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let config_path = root.join("sshd_config");
    std::fs::write(&config_path, "Port 22\n").unwrap();
    let config = SshConfig::new(&config_path, root.join("must-not-run-sshd"));
    let program = root.join("ufw-fake");
    script(&program, FAKE);
    std::fs::write(root.join("active"), "active\n").unwrap();
    std::fs::write(root.join("fail-allow"), "").unwrap();
    let firewall = Ufw::new(root, &program);
    let error = change_ssh_port(&config, Some(&firewall), 2222)
        .unwrap_err()
        .to_string();
    assert!(error.contains("allow failure") && error.contains("19"));
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), "Port 22\n");
    assert!(rollback::undo_all().is_empty());

    let missing = Ufw::new(root, root.join("missing-ufw"));
    assert!(change_ssh_port(&config, Some(&missing), 2222).is_err());
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), "Port 22\n");
    std::fs::remove_file(root.join("fail-allow")).unwrap();
    std::fs::write(root.join("fail-after"), "").unwrap();
    assert!(
        change_ssh_port(&config, Some(&firewall), 2222)
            .unwrap_err()
            .to_string()
            .contains("partial allow failure")
    );
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), "Port 22\n");
    assert!(rollback::undo_all().is_empty());
    assert!(!root.join("user.rules").exists());
    assert!(!root.join("user6.rules").exists());
    std::fs::remove_file(root.join("fail-after")).unwrap();
    assert!(firewall.allow_port(2222, false).unwrap());
    std::fs::write(root.join("fail-reload"), "").unwrap();
    let failures = rollback::undo_all();
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("reload failure") && failures[0].contains("23"));
}
