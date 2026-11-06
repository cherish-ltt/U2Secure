use super::*;

fn values() -> impl Iterator<Item = String> {
    ["admin", "192.0.2.10", "client.example", "192.0.2.20", "22"]
        .into_iter()
        .map(String::from)
}

fn auth() -> SshAuthentication {
    SshAuthentication {
        password_authentication: "no".into(),
        kbd_interactive_authentication: "no".into(),
        permit_root_login: "prohibit-password".into(),
    }
}

#[test]
fn cancelled_or_invalid_input_never_queries_or_confirms() {
    for index in 0..5 {
        let mut input = values().enumerate();
        let text = run_with(
            |_| {
                let (position, value) = input.next().unwrap();
                Ok(if index == position {
                    String::new()
                } else {
                    value
                })
            },
            |_| panic!("cancelled input must not confirm"),
            |_| panic!("cancelled input must not query"),
        );
        assert_eq!(text, tr("ssh_context_cancelled"));
    }
    for bad_input in [
        Ok("admin,host=attacker".into()),
        Err(DomainError::SystemCommandFailed("input-closed".into())),
    ] {
        let mut first = Some(bad_input);
        let mut input = values().skip(1);
        let text = run_with(
            |_| first.take().unwrap_or_else(|| Ok(input.next().unwrap())),
            |_| panic!("invalid input must not confirm"),
            |_| panic!("invalid input must not query"),
        );
        assert!(text.contains(tr("ssh_context_failed").split('{').next().unwrap()));
    }
}

#[test]
fn confirmation_is_required_and_uses_exact_input() {
    for response in [Ok(false), Err(DomainError::UserAborted)] {
        let mut input = values();
        let text = run_with(
            |_| Ok(input.next().unwrap()),
            |_| response,
            |_| panic!("unconfirmed input must not query"),
        );
        assert!(!text.contains(tr("ssh_context_read")));
    }
    let mut input = values();
    let text = run_with(
        |_| Ok(input.next().unwrap()),
        |context| {
            assert_eq!(
                context.connection_spec(),
                "user=admin,addr=192.0.2.10,host=client.example,laddr=192.0.2.20,lport=22"
            );
            Ok(true)
        },
        |context| {
            assert!(context.connection_spec().contains("host=client.example"));
            Ok(auth())
        },
    );
    assert!(text.contains(tr("ssh_context_read")));
    assert!(text.contains(tr("ssh_context_baseline_matches")));
    assert!(text.contains("PasswordAuthentication: no"));
    assert!(text.contains("KbdInteractiveAuthentication: no"));
    assert!(text.contains("PermitRootLogin: prohibit-password"));
    assert!(text.contains(tr("ssh_context_scope")));
}

#[test]
fn findings_and_raw_failures_remain_scoped() {
    let mut input = values();
    let context = collect_with(|_| Ok(input.next().unwrap()))
        .unwrap()
        .unwrap();
    let mut allowed = auth();
    allowed.password_authentication = "yes".into();
    let text = render(&context, Ok(allowed));
    assert!(text.contains(tr("ssh_context_baseline_differs")));
    assert!(text.contains("PasswordAuthentication: yes"));
    let text = render(
        &context,
        Err(DomainError::SystemCommandFailed(
            "bad Match at line 9\nexit 42\u{1b}[2J".into(),
        )),
    );
    assert!(text.contains("bad Match at line 9\nexit 42"));
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains(tr("ssh_context_read")));
    assert!(text.contains(&context.connection_spec()));
    assert!(text.contains(tr("ssh_context_scope")));
}
