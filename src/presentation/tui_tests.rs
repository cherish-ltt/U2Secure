use super::*;
use crate::domain::audit::{AuditItem, PackageManager};
use ratatui::{backend::TestBackend, buffer::Buffer};

fn report() -> AuditReport {
    AuditReport {
        items: vec![
            AuditItem::safe("SAFE", "verified".into()),
            AuditItem::partial("PARTIAL", "conditional".into()),
            AuditItem::missing("MISSING", "absent".into()),
            AuditItem::needs_update("UPDATE", "stale".into()),
        ],
        is_root: true,
        package_manager: PackageManager::Apt,
        ssh_port: 22,
        ssh_config_verified: true,
        password_auth_disabled: false,
        root_login_disabled: false,
        sudo_users: vec![],
        fail2ban_installed: false,
        ufw_enabled: false,
        auto_updates_enabled: false,
        system_up_to_date: false,
        reboot_hint: crate::domain::audit::RebootHint::Unsupported,
        lynis_installed: false,
        logwatch_installed: false,
        aide_installed: false,
        ssh_restart_needed: true,
    }
}

fn app() -> TuiApp {
    let report = report();
    TuiApp {
        steps: init_steps(&report),
        report,
        cursor: 0,
        mode: AppMode::Select,
        logs: vec![],
        results: vec![],
        progress: (0, 0),
        popup: None,
        job: None,
        current: None,
        live_tail: vec![],
        mirror: PackageMirror::Original,
        pending: None,
        mirror_failure: None,
        status: String::new(),
        summary_scroll: 0,
    }
}

fn key(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn release(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new_with_kind(
        code,
        KeyModifiers::NONE,
        KeyEventKind::Release,
    ))
}

fn press(app: &mut TuiApp, code: KeyCode) -> PopupAction {
    popup_action(app, key(code), |_| panic!("unexpected key lookup")).unwrap()
}

fn queued(action: PopupAction, kind: StepKind) -> ExecuteParams {
    let queued = match action {
        PopupAction::Queue(kind, params) => Some((kind, params)),
        _ => None,
    };
    assert!(queued.is_some(), "expected a queued operation");
    let (actual_kind, params) = queued.unwrap();
    assert_eq!(actual_kind, kind);
    assert!(!params.apply_ssh_changes);
    *params
}

fn collected(action: SelectAction) -> Vec<StepKind> {
    let selected = match action {
        SelectAction::Collect(selected) => Some(selected),
        _ => None,
    };
    assert!(
        selected.is_some(),
        "expected parameter collection without execution"
    );
    selected.unwrap()
}

#[test]
fn selected_mirror_requires_plan_review_before_start() {
    let mut app = app();
    app.pending = Some(PendingRun {
        selected: vec![StepKind::SystemUpdate],
        params: ExecuteParams::default(),
    });
    app.popup = Some(Popup::MirrorSelect {
        items: vec!["original".into(), "selected-mirror".into()],
        selected: 1,
    });
    assert!(!matches!(
        press(&mut app, KeyCode::Enter),
        PopupAction::StartPending
    ));
    assert!(matches!(
        app.popup,
        Some(Popup::PlanReview { selected: 2, .. })
    ));
    assert!(app.job.is_none());
}

#[test]
fn plan_cancel_and_edit_do_not_start_a_batch() {
    let mut app = app();
    for choice in [1, 2] {
        app.pending = Some(PendingRun {
            selected: vec![StepKind::SshPortChange],
            params: ExecuteParams {
                new_ssh_port: Some(2201),
                ..Default::default()
            },
        });
        app.popup = Some(Popup::PlanReview {
            selected: choice,
            scroll: 0,
        });
        assert!(matches!(
            press(&mut app, KeyCode::Enter),
            PopupAction::Redraw
        ));
        assert!(app.pending.is_none());
        assert!(app.popup.is_none());
        assert!(app.job.is_none());
        start_pending_with(&mut app, |_, _, _| {
            panic!("cancel/edit must not spawn or warm up")
        });
        if choice == 1 {
            assert_eq!(
                app.steps
                    .iter()
                    .filter(|step| step.checked)
                    .map(|step| step.kind)
                    .collect::<Vec<_>>(),
                [StepKind::SshPortChange]
            );
            assert_eq!(app.status, crate::i18n::tr("plan_edit_hint"));
        }
    }
    app.pending = Some(PendingRun {
        selected: vec![StepKind::Ufw],
        params: ExecuteParams::default(),
    });
    show_plan(&mut app);
    press(&mut app, KeyCode::Esc);
    assert!(app.pending.is_none());
    assert_eq!(app.status, crate::i18n::tr("plan_cancelled"));
}

#[test]
fn edited_single_and_batch_plans_execute_the_reviewed_inputs() {
    let mut app = app();
    let dir = tempfile::tempdir().unwrap();
    for selected in [
        vec![StepKind::SshPortChange],
        vec![
            StepKind::SshPortChange,
            StepKind::SystemUpdate,
            StepKind::SshPortChange,
        ],
    ] {
        let params = ExecuteParams {
            new_ssh_port: Some(2202),
            apply_ssh_changes: true,
            ..Default::default()
        };
        app.pending = Some(PendingRun {
            selected: selected.clone(),
            params,
        });
        app.mirror = PackageMirror::Ustc;
        show_plan(&mut app);
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        assert!(matches!(
            press(&mut app, KeyCode::Enter),
            PopupAction::StartPending
        ));
        start_pending_with(&mut app, |actual, params, mirror| {
            assert_eq!(actual, crate::application::job::execution_plan(&selected));
            assert_eq!(params.new_ssh_port, Some(2202));
            assert!(params.apply_ssh_changes);
            assert_eq!(mirror, PackageMirror::Ustc);
            let logger = std::sync::Arc::new(crate::infrastructure::logger::FileLogger::with_path(
                dir.path().join("fixture.log"),
            ));
            StepRunner::new(logger)
                .with_report_dir(dir.path().to_string_lossy())
                .spawn_steps(vec![], params)
        });
        assert!(matches!(app.mode, AppMode::Executing));
        assert_eq!(
            app.progress.1,
            crate::application::job::execution_plan(&selected).len()
        );
        app.job.take().unwrap().join();
    }
}

#[test]
fn changed_mirror_requires_new_review_and_cancel_keeps_prior_effects_explicit() {
    let mut app = app();
    app.pending = Some(PendingRun {
        selected: vec![StepKind::SystemUpdate],
        params: ExecuteParams::default(),
    });
    app.mirror = PackageMirror::Tsinghua;
    app.popup = Some(Popup::MirrorFailedDialog {
        reason: "fixture-offline".into(),
        selected: 1,
    });
    assert!(matches!(
        press(&mut app, KeyCode::Enter),
        PopupAction::AskMirror
    ));
    app.popup = Some(Popup::MirrorSelect {
        items: PackageMirror::all()
            .iter()
            .map(PackageMirror::label)
            .collect(),
        selected: 2,
    });
    assert!(matches!(
        press(&mut app, KeyCode::Enter),
        PopupAction::Redraw
    ));
    assert!(matches!(
        app.popup,
        Some(Popup::PlanReview { selected: 2, .. })
    ));
    let screen = text(&draw(&app, 180, 32));
    assert!(screen.contains("mirrors.ustc.edu.cn"));
    assert!(!screen.contains("mirrors.tuna.tsinghua.edu.cn"));
    assert!(screen.contains(crate::i18n::tr("plan_cancel_scope")));
    press(&mut app, KeyCode::Enter);
    start_pending_with(&mut app, |_, _, _| {
        panic!("cancel must not warm up the replacement mirror")
    });
}

#[test]
fn preview_renders_shared_lines_and_scrolls_in_small_terminals() {
    let mut app = app();
    let params = ExecuteParams {
        new_username: Some("operator-fixture".into()),
        ssh_key_username: Some("deploy-fixture".into()),
        ssh_key_action: Some(SshKeyAction::PasteKey("key-body-fixture".into())),
        new_ssh_port: Some(2208),
        ..Default::default()
    };
    let plan = RunPlan::new(StepKind::all(), params.clone(), PackageMirror::Original);
    app.pending = Some(PendingRun {
        selected: StepKind::all().to_vec(),
        params,
    });
    show_plan(&mut app);
    let screen = text(&draw(&app, 240, 60));
    for line in plan.lines() {
        assert!(screen.contains(&line), "missing {line}");
    }
    assert!(!screen.contains("key-body-fixture"));
    for (width, height) in [(1, 1), (20, 6), (80, 24)] {
        assert_eq!(draw(&app, width, height).area.width, width);
    }
    let before = text(&draw(&app, 80, 12));
    for _ in 0..30 {
        press(&mut app, KeyCode::PageDown);
    }
    let after = text(&draw(&app, 80, 12));
    assert_ne!(before, after);
    assert!(after.contains(crate::i18n::tr("plan_execute")));
    assert!(after.contains(crate::i18n::tr("plan_cancel")));
    for _ in 0..30 {
        press(&mut app, KeyCode::PageUp);
    }
    assert_eq!(text(&draw(&app, 80, 12)), before);
    press(&mut app, KeyCode::Down);
    assert!(matches!(
        app.popup,
        Some(Popup::PlanReview { selected: 2, .. })
    ));
    app.pending = None;
    let _ = draw(&app, 80, 12);
}

fn draw(app: &TuiApp, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| render_with_data(frame, app, "fixture-reports", 2222, 45678))
        .unwrap();
    terminal.backend().buffer().clone()
}

fn text(buffer: &Buffer) -> String {
    buffer
        .content
        .chunks(buffer.area.width.max(1) as usize)
        .map(|row| {
            let mut rendered = String::new();
            let mut cells = row.iter();
            while let Some(cell) = cells.next() {
                rendered.push_str(cell.symbol());
                for _ in 1..Span::raw(cell.symbol()).width() {
                    cells.next();
                }
            }
            rendered
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn lines_text(lines: &[Line<'_>]) -> String {
    lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn selected_update_shows_reboot_hint_source_and_limits_without_probing() {
    use crate::domain::audit::RebootHint;
    let mut app = app();
    app.cursor = app
        .steps
        .iter()
        .position(|step| step.kind == StepKind::SystemUpdate)
        .unwrap();
    for hint in [
        RebootHint::Found("/run/reboot-required"),
        RebootHint::NotFound("/var/run/reboot-required"),
        RebootHint::Unsupported,
    ] {
        app.report.reboot_hint = hint;
        let screen = draw(&app, 80, 24);
        let help: String = screen
            .content
            .chunks(80)
            .skip(7)
            .take(15)
            .flat_map(|row| &row[37..79])
            .map(|cell| cell.symbol())
            .collect();
        let help: String = help.chars().filter(|ch| !ch.is_whitespace()).collect();
        let expected: String = crate::i18n::reboot_hint(hint)
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        assert!(help.contains(&expected), "missing hint: {}", text(&screen));
    }
}

#[test]
fn selection_defaults_and_navigation_preserve_opt_in_choices() {
    let mut app = app();
    assert_eq!(app.steps.len(), StepKind::all().len());
    assert!(app.steps.iter().all(|s| s.state == StepExecState::Idle));
    assert!(
        app.steps
            .iter()
            .filter(|s| s.kind.is_opt_in())
            .all(|s| !s.checked)
    );
    for event in [Event::Resize(80, 24), release(KeyCode::Down)] {
        assert!(matches!(select_action(&mut app, event), SelectAction::None));
        assert_eq!(app.cursor, 0);
    }
    select_action(&mut app, key(KeyCode::Up));
    assert_eq!(app.cursor, 0);
    select_action(&mut app, key(KeyCode::Char('j')));
    assert_eq!(app.cursor, 1);
    select_action(&mut app, key(KeyCode::Char('k')));
    assert_eq!(app.cursor, 0);
    for _ in 0..20 {
        select_action(&mut app, key(KeyCode::Down));
    }
    assert_eq!(app.cursor, app.steps.len() - 1);
    let previous = app.steps[app.cursor].checked;
    select_action(&mut app, key(KeyCode::Char(' ')));
    assert_eq!(app.steps[app.cursor].checked, !previous);
    for step in &mut app.steps {
        step.checked = step.kind.is_opt_in();
    }
    select_action(&mut app, key(KeyCode::Char('a')));
    assert!(app.steps.iter().all(|s| s.checked));
    select_action(&mut app, key(KeyCode::Char('a')));
    assert!(app.steps.iter().all(|s| s.checked == s.kind.is_opt_in()));
    let selected = collected(select_action(&mut app, key(KeyCode::Enter)));
    assert!(selected.iter().all(StepKind::is_opt_in));
    for step in &mut app.steps {
        step.checked = false;
    }
    assert!(matches!(
        select_action(&mut app, key(KeyCode::Enter)),
        SelectAction::None
    ));
    assert_eq!(app.status, crate::i18n::tr("tui_no_selection"));
    assert!(matches!(
        select_action(&mut app, key(KeyCode::Char('r'))),
        SelectAction::Audit
    ));
    assert!(matches!(
        select_action(&mut app, key(KeyCode::Char('q'))),
        SelectAction::Quit
    ));
    app.steps.clear();
    for code in [
        KeyCode::Down,
        KeyCode::Char(' '),
        KeyCode::Char('e'),
        KeyCode::Esc,
    ] {
        assert!(matches!(
            select_action(&mut app, key(code)),
            SelectAction::None
        ));
    }
}

#[test]
fn single_step_selection_opens_inputs_without_running_steps() {
    let mut app = app();
    for (index, kind) in StepKind::all().iter().enumerate() {
        app.cursor = index;
        app.popup = None;
        let action = select_action(&mut app, key(KeyCode::Char('e')));
        match kind {
            StepKind::UserCreation => {
                assert!(matches!(app.popup, Some(Popup::CreateUserUsername { .. })))
            },
            StepKind::SshPortChange => {
                assert!(matches!(app.popup, Some(Popup::SshPortInput { .. })))
            },
            StepKind::SshKeySetup => assert!(matches!(action, SelectAction::SelectKeyUser)),
            _ => {
                let selected = collected(action);
                assert_eq!(selected, [*kind]);
            },
        }
        assert!(app.job.is_none());
    }
    open_key_user_popup(&mut app, vec![]);
    assert!(matches!(app.popup, Some(Popup::SshKeyUsername { ref value }) if value.is_empty()));
    open_key_user_popup(
        &mut app,
        vec!["deploy".into(), "root".into(), "operator".into()],
    );
    assert!(
        matches!(app.popup, Some(Popup::SshKeyUserSelect { ref users, selected: 0 }) if users == &["root", "deploy", "operator"])
    );
}

#[test]
fn executing_and_summary_keys_respect_press_and_scroll_boundaries() {
    let mut app = app();
    app.mode = AppMode::Executing;
    for event in [
        Event::Resize(1, 1),
        release(KeyCode::Esc),
        key(KeyCode::Enter),
    ] {
        handle_executing_mode(&mut app, event);
        assert!(app.status.is_empty());
    }
    for code in [KeyCode::Esc, KeyCode::Char('q')] {
        handle_executing_mode(&mut app, key(code));
        assert_eq!(app.status, crate::i18n::tr("tui_running_hint"));
    }
    app.mode = AppMode::Summary;
    for (event, expected) in [
        (Event::Resize(1, 1), 0),
        (release(KeyCode::Enter), 0),
        (key(KeyCode::Up), 0),
        (key(KeyCode::Down), 1),
        (key(KeyCode::Char('j')), 2),
        (key(KeyCode::Char('k')), 1),
        (key(KeyCode::PageDown), 11),
        (key(KeyCode::PageUp), 1),
        (key(KeyCode::PageUp), 0),
    ] {
        handle_summary_mode(&mut app, event, || panic!("scrolling must not audit"));
        assert_eq!(app.summary_scroll, expected);
    }
    app.summary_scroll = u16::MAX;
    handle_summary_mode(&mut app, key(KeyCode::Down), || panic!("must not audit"));
    handle_summary_mode(&mut app, key(KeyCode::PageDown), || {
        panic!("must not audit")
    });
    assert_eq!(app.summary_scroll, u16::MAX);
    handle_summary_mode(&mut app, key(KeyCode::Enter), || {
        let mut report = report();
        report.ssh_port = 2222;
        report.ufw_enabled = true;
        Ok(report)
    });
    assert!(matches!(app.mode, AppMode::Select));
    assert_eq!(app.summary_scroll, 0);
    assert_eq!(app.report.ssh_port, 2222);
    assert!(
        !app.steps
            .iter()
            .find(|s| s.kind == StepKind::Ufw)
            .unwrap()
            .checked
    );
    app.mode = AppMode::Summary;
    app.summary_scroll = 7;
    let error = DomainError::AuditFailed("fixture-audit-failure".into());
    let message = error.to_string();
    handle_summary_mode(&mut app, key(KeyCode::Enter), || Err(error));
    assert!(matches!(app.mode, AppMode::Summary));
    assert_eq!(app.summary_scroll, 7);
    assert_eq!(app.report.ssh_port, 2222);
    assert_eq!(app.status, message);
    assert!(text(&draw(&app, 160, 40)).contains("fixture-audit-failure"));
    assert!(apply_audit_result(&mut app, Ok(report())));
    assert_eq!(app.report.ssh_port, 22);
    assert!(app.status.is_empty());
    assert!(is_ctrl_c(&KeyEvent::new(
        KeyCode::Char('c'),
        KeyModifiers::CONTROL
    )));
    assert!(!is_ctrl_c(&KeyEvent::new(
        KeyCode::Char('c'),
        KeyModifiers::NONE
    )));
    assert!(!is_ctrl_c(&KeyEvent::new(
        KeyCode::Char('q'),
        KeyModifiers::CONTROL
    )));
}

#[test]
fn popup_ignores_non_press_events_and_username_edits_round_trip() {
    let mut app = app();
    assert!(popup_action(&mut app, key(KeyCode::Enter), |_| panic!("lookup")).is_none());
    app.popup = Some(Popup::SshKeyUsername {
        value: String::new(),
    });
    for event in [Event::Resize(1, 1), release(KeyCode::Char('x'))] {
        assert!(popup_action(&mut app, event, |_| panic!("lookup")).is_none());
    }
    press(&mut app, KeyCode::Enter);
    assert!(matches!(app.popup, Some(Popup::SshKeyUsername { .. })));
    for c in "deployx".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Enter);
    assert!(
        matches!(app.popup, Some(Popup::SshKeyAction { ref username, selected: 0 }) if username == "deploy")
    );
    press(&mut app, KeyCode::Esc);
    assert!(app.popup.is_none());
    app.popup = Some(Popup::SshKeyUsername {
        value: "keep".into(),
    });
    press(&mut app, KeyCode::Esc);
    assert!(app.popup.is_none());
}

#[test]
fn key_user_selection_and_key_actions_preserve_explicit_overwrite() {
    let mut app = app();
    open_key_user_popup(&mut app, vec!["deploy".into()]);
    press(&mut app, KeyCode::Up);
    for _ in 0..3 {
        press(&mut app, KeyCode::Down);
    }
    assert!(matches!(
        app.popup,
        Some(Popup::SshKeyUserSelect { selected: 1, .. })
    ));
    press(&mut app, KeyCode::Enter);
    let action = popup_action(&mut app, key(KeyCode::Enter), |user| {
        assert_eq!(user, "deploy");
        true
    })
    .unwrap();
    assert!(matches!(action, PopupAction::Redraw));
    assert!(matches!(
        app.popup,
        Some(Popup::SshKeyOverwrite { selected: 0, .. })
    ));
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    assert!(matches!(
        app.popup,
        Some(Popup::SshKeyAction { selected: 0, .. })
    ));
    popup_action(&mut app, key(KeyCode::Enter), |_| true);
    press(&mut app, KeyCode::Up);
    let params = queued(press(&mut app, KeyCode::Enter), StepKind::SshKeySetup);
    assert_eq!(params.ssh_key_username.as_deref(), Some("deploy"));
    assert!(matches!(
        params.ssh_key_action,
        Some(SshKeyAction::ReplaceExisting)
    ));
    assert!(app.popup.is_none());
    app.popup = Some(Popup::SshKeyAction {
        username: "newuser".into(),
        selected: 0,
    });
    let params = queued(
        popup_action(&mut app, key(KeyCode::Enter), |_| false).unwrap(),
        StepKind::SshKeySetup,
    );
    assert!(matches!(
        params.ssh_key_action,
        Some(SshKeyAction::GenerateNew)
    ));
    assert_eq!(params.ssh_key_username.as_deref(), Some("newuser"));
    app.popup = Some(Popup::SshKeyOverwrite {
        username: "deploy".into(),
        selected: 0,
    });
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Up);
    for _ in 0..3 {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    assert!(app.popup.is_none());
    open_key_user_popup(&mut app, vec!["deploy".into()]);
    press(&mut app, KeyCode::Esc);
    assert!(app.popup.is_none());
}

#[test]
fn pasted_key_and_user_creation_queue_values_without_side_effects() {
    let mut app = app();
    app.popup = Some(Popup::SshKeyAction {
        username: "deploy".into(),
        selected: 1,
    });
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert!(matches!(app.popup, Some(Popup::SshKeyPaste { ref value, .. }) if value.is_empty()));
    for c in "public-fixturex".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    press(&mut app, KeyCode::Backspace);
    let params = queued(press(&mut app, KeyCode::Enter), StepKind::SshKeySetup);
    assert!(
        matches!(params.ssh_key_action, Some(SshKeyAction::PasteKey(ref value)) if value == "public-fixture")
    );
    assert_eq!(params.ssh_key_username.as_deref(), Some("deploy"));
    app.popup = Some(Popup::SshKeyPaste {
        username: "deploy".into(),
        value: "discard".into(),
    });
    press(&mut app, KeyCode::Esc);
    assert!(matches!(
        app.popup,
        Some(Popup::SshKeyAction { selected: 0, .. })
    ));
    app.popup = Some(Popup::CreateUserUsername {
        value: String::new(),
    });
    press(&mut app, KeyCode::Enter);
    for c in "deploy_-!x".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Enter);
    assert!(
        matches!(app.popup, Some(Popup::CreateUserLockPw { ref username, lock: true }) if username == "deploy_-")
    );
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Down);
    let params = queued(press(&mut app, KeyCode::Enter), StepKind::UserCreation);
    assert_eq!(params.new_username.as_deref(), Some("deploy_-"));
    assert_eq!(params.new_username, params.ssh_key_username);
    assert!(!params.lock_password);
    assert!(matches!(
        params.ssh_key_action,
        Some(SshKeyAction::GenerateNew)
    ));
    app.popup = Some(Popup::CreateUserUsername {
        value: "a".repeat(32),
    });
    press(&mut app, KeyCode::Char('b'));
    assert!(
        matches!(app.popup, Some(Popup::CreateUserUsername { ref value }) if value.len() == 32)
    );
    press(&mut app, KeyCode::Esc);
    assert!(app.popup.is_none());
}

#[test]
fn port_popup_rejects_invalid_values_and_queues_only_valid_ports() {
    let mut app = app();
    for value in ["", "0", "65536", "99999"] {
        app.popup = Some(Popup::SshPortInput {
            value: value.into(),
        });
        assert!(matches!(
            press(&mut app, KeyCode::Enter),
            PopupAction::Redraw
        ));
        assert!(app.popup.is_some());
    }
    app.popup = Some(Popup::SshPortInput {
        value: String::new(),
    });
    for c in "22a2229".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    assert!(matches!(app.popup, Some(Popup::SshPortInput { ref value }) if value == "22222"));
    press(&mut app, KeyCode::Backspace);
    let params = queued(press(&mut app, KeyCode::Enter), StepKind::SshPortChange);
    assert_eq!(params.new_ssh_port, Some(2222));
    for port in ["1", "65535"] {
        app.popup = Some(Popup::SshPortInput { value: port.into() });
        let params = queued(press(&mut app, KeyCode::Enter), StepKind::SshPortChange);
        assert_eq!(params.new_ssh_port, port.parse().ok());
    }
    app.popup = Some(Popup::SshPortInput { value: "22".into() });
    press(&mut app, KeyCode::Esc);
    assert!(app.popup.is_none());
}

#[test]
fn mirror_selection_custom_validation_and_failure_decisions_are_explicit() {
    let mut app = app();
    let items: Vec<_> = PackageMirror::all()
        .iter()
        .map(PackageMirror::label)
        .chain(["custom".into()])
        .collect();
    app.popup = Some(Popup::MirrorSelect {
        items: items.clone(),
        selected: 0,
    });
    press(&mut app, KeyCode::Up);
    for _ in 0..20 {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    assert!(matches!(app.popup, Some(Popup::MirrorCustomInput { .. })));
    press(&mut app, KeyCode::Enter);
    for c in "https://mirror.example.test".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    assert!(matches!(
        press(&mut app, KeyCode::Enter),
        PopupAction::Redraw
    ));
    assert!(matches!(app.mirror, PackageMirror::Custom(_)));
    app.popup = Some(Popup::MirrorCustomInput {
        value: "bad host/path".into(),
        error: None,
    });
    press(&mut app, KeyCode::Enter);
    assert!(matches!(
        app.popup,
        Some(Popup::MirrorCustomInput { error: Some(_), .. })
    ));
    press(&mut app, KeyCode::Backspace);
    assert!(matches!(
        app.popup,
        Some(Popup::MirrorCustomInput { error: None, .. })
    ));
    app.popup = Some(Popup::MirrorCustomInput {
        value: "a".repeat(120),
        error: Some("old".into()),
    });
    press(&mut app, KeyCode::Char('b'));
    assert!(
        matches!(app.popup, Some(Popup::MirrorCustomInput { ref value, error: None }) if value.len() == 120)
    );
    assert!(matches!(
        press(&mut app, KeyCode::Esc),
        PopupAction::OpenMirror
    ));
    app.popup = Some(Popup::MirrorSelect {
        items: items.clone(),
        selected: 1,
    });
    assert!(matches!(
        press(&mut app, KeyCode::Enter),
        PopupAction::Redraw
    ));
    assert_eq!(app.mirror, PackageMirror::all()[1]);
    app.popup = Some(Popup::MirrorSelect { items, selected: 1 });
    assert!(matches!(press(&mut app, KeyCode::Esc), PopupAction::Redraw));
    assert_eq!(app.mirror, PackageMirror::Original);
    assert_eq!(app.status, crate::i18n::tr("tui_mirror_use_original"));
    for selected in 0..3 {
        app.pending = Some(PendingRun {
            selected: vec![StepKind::SystemUpdate],
            params: ExecuteParams::default(),
        });
        app.popup = Some(Popup::MirrorFailedDialog {
            reason: "offline".into(),
            selected,
        });
        match (selected, press(&mut app, KeyCode::Enter)) {
            (0, PopupAction::Redraw) | (1, PopupAction::AskMirror) => {
                assert!(app.pending.is_some())
            },
            (2, PopupAction::Redraw) => assert!(app.pending.is_none()),
            _ => panic!("wrong mirror failure decision"),
        }
    }
    app.popup = Some(Popup::MirrorFailedDialog {
        reason: "offline".into(),
        selected: 0,
    });
    press(&mut app, KeyCode::Up);
    for _ in 0..4 {
        press(&mut app, KeyCode::Down);
    }
    assert!(matches!(
        app.popup,
        Some(Popup::MirrorFailedDialog { selected: 2, .. })
    ));
    press(&mut app, KeyCode::Esc);
    assert!(app.popup.is_none());
    assert!(app.pending.is_none());
    assert_eq!(app.status, crate::i18n::tr("mirror_abort_hint"));
}

#[test]
fn job_events_update_progress_tail_outcomes_and_completion() {
    let mut app = app();
    pump_job(&mut app);
    assert!(app.results.is_empty());
    let temp = tempfile::tempdir().unwrap();
    let live_log = temp.path().join("live.log");
    std::fs::write(
        &live_log,
        (0..12).map(|i| format!("line-{i}\n")).collect::<String>(),
    )
    .unwrap();
    app.mode = AppMode::Executing;
    app.live_tail.push("old".into());
    apply_job_events(
        &mut app,
        vec![JobEvent::StepStarted {
            kind: StepKind::Ufw,
            index: 1,
            total: 3,
            live_log: live_log.to_string_lossy().into(),
        }],
        false,
    );
    assert_eq!(app.progress, (1, 3));
    assert_eq!(
        app.live_tail,
        (4..12).map(|i| format!("line-{i}")).collect::<Vec<_>>()
    );
    assert_eq!(
        app.steps
            .iter()
            .find(|s| s.kind == StepKind::Ufw)
            .unwrap()
            .state,
        StepExecState::Running
    );
    for (result, expected) in [
        (
            StepResult::changed(StepKind::Ufw, "first\nsecond"),
            StepExecState::Success,
        ),
        (StepResult::skipped(StepKind::Ufw, ""), StepExecState::Idle),
        (
            StepResult::failed(StepKind::Ufw, "failure"),
            StepExecState::Failure,
        ),
    ] {
        apply_job_events(&mut app, vec![JobEvent::StepFinished(result)], false);
        assert_eq!(
            app.steps
                .iter()
                .find(|s| s.kind == StepKind::Ufw)
                .unwrap()
                .state,
            expected
        );
    }
    assert!(!app.logs[1].message.contains("second"));
    assert!(app.results[0].message.contains("second"));
    apply_job_events(
        &mut app,
        vec![
            JobEvent::Log("fixture log".into()),
            JobEvent::Interrupted,
            JobEvent::AllFinished,
        ],
        true,
    );
    assert_eq!(app.results.len(), 3);
    assert!(matches!(app.mode, AppMode::Summary));
    assert_eq!(app.progress, (3, 3));
    assert!(app.current.is_none());
    assert!(app.logs.iter().any(|l| l.message == "fixture log"));
    assert!(
        app.logs
            .iter()
            .any(|l| l.message == crate::i18n::tr("tui_exec_interrupted"))
    );
    app.steps.clear();
    mark_step_state(&mut app, StepKind::Ufw, StepExecState::Running);
    assert!(app.steps.is_empty());
}

#[test]
fn disconnected_job_is_failed_and_mirror_failure_preserves_retry_parameters() {
    let mut app = app();
    for current in [
        None,
        Some(CurrentStep {
            kind: StepKind::Ufw,
            live_log: String::new(),
        }),
    ] {
        app.current = current;
        let expected = app
            .current
            .as_ref()
            .map(|c| c.kind)
            .unwrap_or(StepKind::SystemUpdate);
        app.mode = AppMode::Executing;
        app.status = "running".into();
        apply_job_events(&mut app, vec![], true);
        let result = app.results.last().unwrap();
        assert_eq!(result.kind, expected);
        assert_eq!(result.outcome, StepOutcome::Failed);
        assert_eq!(result.message, crate::i18n::tr("tui_job_crashed"));
        assert!(matches!(app.mode, AppMode::Summary));
        assert!(app.status.is_empty());
        assert!(app.live_tail.is_empty());
    }
    app.pending = Some(PendingRun {
        selected: vec![StepKind::SystemUpdate],
        params: ExecuteParams::default(),
    });
    apply_job_events(
        &mut app,
        vec![
            JobEvent::MirrorFailed {
                reason: "no network".into(),
            },
            JobEvent::AllFinished,
        ],
        true,
    );
    assert!(matches!(app.mode, AppMode::Select));
    assert!(
        matches!(app.popup, Some(Popup::MirrorFailedDialog { ref reason, selected: 0 }) if reason == "no network")
    );
    assert!(app.pending.is_some());
    assert!(app.mirror_failure.is_none());
}

#[test]
fn headless_selection_renders_statuses_and_selection_styles() {
    let mut app = app();
    app.status = "fixture-status".into();
    for (step, state) in app.steps.iter_mut().zip([
        StepExecState::Running,
        StepExecState::Success,
        StepExecState::Failure,
        StepExecState::Idle,
    ]) {
        step.state = state;
    }
    let buffer = draw(&app, 160, 40);
    let screen = text(&buffer);
    for expected in [
        "U2Secure",
        env!("CARGO_PKG_VERSION"),
        "SAFE",
        "PARTIAL",
        "MISSING",
        "UPDATE",
        "fixture-status",
        "Enter",
        "Space",
    ] {
        assert!(screen.contains(expected), "missing {expected}");
    }
    for color in [Color::Green, Color::Yellow, Color::Red, Color::Cyan] {
        assert!(buffer.content.iter().any(|cell| cell.fg == color));
    }
    assert!(
        buffer
            .content
            .iter()
            .any(|cell| cell.bg == Color::Rgb(40, 40, 80))
    );
    app.status.clear();
    app.steps.clear();
    for (width, height) in [(1, 1), (20, 6), (80, 24)] {
        assert_eq!(draw(&app, width, height).area.width, width);
    }
}

#[test]
fn headless_execution_renders_tail_progress_and_only_recent_logs() {
    let mut app = app();
    app.mode = AppMode::Executing;
    assert!(text(&draw(&app, 160, 40)).contains(crate::i18n::tr("tui_exec_preparing")));
    app.current = Some(CurrentStep {
        kind: StepKind::Ufw,
        live_log: String::new(),
    });
    app.progress = (2, 3);
    app.status = "cancel-fixture".into();
    app.live_tail = vec!["output-fixture".into()];
    let icons = ["▶", "✅", "❌", "⚠️", "⏭", "other"];
    app.logs = (0..15)
        .map(|i| LogEntry {
            icon: icons[i % icons.len()],
            message: format!("log-{i:02}-fixture"),
        })
        .collect();
    let screen = text(&draw(&app, 160, 40));
    for expected in [
        "cancel-fixture",
        "output-fixture",
        "log-03-fixture",
        "log-14-fixture",
        "2/3",
    ] {
        assert!(screen.contains(expected), "missing {expected}");
    }
    assert!(!screen.contains("log-02-fixture"));
    app.progress = (8, 3);
    assert!(text(&draw(&app, 160, 40)).contains("8/3"));
    assert_eq!(format_duration(Duration::from_secs(0)), "00:00");
    assert_eq!(format_duration(Duration::from_secs(61)), "01:01");
    assert_eq!(format_duration(Duration::from_secs(6001)), "100:01");
}

#[test]
fn headless_summary_renders_all_outcomes_artifacts_and_scroll() {
    let mut app = app();
    app.mode = AppMode::Summary;
    let mut changed = StepResult::changed(StepKind::Ufw, "changed-fixture\nsecond-line");
    changed.artifacts = vec!["fixture-report.txt".into()];
    app.results = vec![
        changed,
        StepResult::skipped(StepKind::RestartSsh, "pending-fixture"),
        StepResult::failed(StepKind::SshPortChange, "failed-fixture"),
    ];
    let before = text(&draw(&app, 180, 44));
    for expected in [
        "changed-fixture",
        "second-line",
        "fixture-report.txt",
        "pending-fixture",
        "failed-fixture",
        "fixture-reports",
    ] {
        assert!(before.contains(expected), "missing {expected}");
    }
    let stats = crate::i18n::tr("tui_result_summary")
        .replace("{ok}", "1")
        .replace("{skip}", "1")
        .replace("{fail}", "1");
    assert!(before.contains(&stats));
    app.summary_scroll = 7;
    let after = text(&draw(&app, 180, 44));
    assert!(!after.contains("changed-fixture"));
    assert!(after.contains("failed-fixture"));
    app.results.clear();
    app.summary_scroll = 0;
    let empty_stats = crate::i18n::tr("tui_result_summary")
        .replace("{ok}", "0")
        .replace("{skip}", "0")
        .replace("{fail}", "0");
    assert!(text(&draw(&app, 180, 44)).contains(&empty_stats));
}

#[test]
fn headless_popups_render_titles_inputs_errors_and_selected_choices() {
    let mut app = app();
    let cases = [
        (
            Popup::MirrorSelect {
                items: vec!["mirror-fixture".into()],
                selected: 0,
            },
            "tui_mirror_title",
        ),
        (
            Popup::MirrorCustomInput {
                value: String::new(),
                error: None,
            },
            "tui_mirror_custom_title",
        ),
        (
            Popup::MirrorCustomInput {
                value: "host-fixture".into(),
                error: Some("invalid-fixture".into()),
            },
            "tui_mirror_custom_title",
        ),
        (
            Popup::MirrorFailedDialog {
                reason: "offline-fixture".into(),
                selected: 1,
            },
            "tui_mirror_failed_title",
        ),
        (
            Popup::SshKeyUsername {
                value: String::new(),
            },
            "tui_popup_username",
        ),
        (
            Popup::SshKeyUserSelect {
                users: vec!["root".into(), "deploy".into()],
                selected: 1,
            },
            "tui_popup_select_user",
        ),
        (
            Popup::SshKeyAction {
                username: "deploy".into(),
                selected: 1,
            },
            "tui_popup_select_action",
        ),
        (
            Popup::SshKeyPaste {
                username: "deploy".into(),
                value: "public-fixture".into(),
            },
            "tui_popup_paste_title",
        ),
        (
            Popup::SshKeyOverwrite {
                username: "deploy".into(),
                selected: 0,
            },
            "tui_popup_overwrite_title",
        ),
        (
            Popup::CreateUserUsername {
                value: "deploy".into(),
            },
            "tui_popup_new_user",
        ),
        (
            Popup::CreateUserLockPw {
                username: "deploy".into(),
                lock: true,
            },
            "tui_popup_lock_title",
        ),
        (
            Popup::CreateUserLockPw {
                username: "deploy".into(),
                lock: false,
            },
            "tui_popup_lock_title",
        ),
        (
            Popup::SshPortInput {
                value: String::new(),
            },
            "tui_popup_port_title",
        ),
        (
            Popup::SshPortInput {
                value: "2222".into(),
            },
            "tui_popup_port_title",
        ),
    ];
    for (popup, title) in cases {
        app.popup = Some(popup);
        let buffer = draw(&app, 160, 40);
        assert!(
            text(&buffer).contains(crate::i18n::tr(title)),
            "missing {title}"
        );
        assert!(
            buffer
                .content
                .iter()
                .any(|cell| cell.bg == Color::Rgb(25, 25, 45))
        );
        let small = draw(&app, 20, 8);
        assert_eq!(small.area.width, 20);
    }
}

#[test]
fn popup_text_helpers_handle_empty_unicode_and_input_limits() {
    assert!(
        lines_text(&render_username_input("")).contains(crate::i18n::tr("tui_popup_enter_user"))
    );
    assert!(lines_text(&render_username_input("deploy")).contains("deploy"));
    assert!(lines_text(&render_pubkey_input("")).contains(crate::i18n::tr("tui_popup_paste_hint")));
    let unicode = "界".repeat(51);
    let rendered = lines_text(&render_pubkey_input(&unicode));
    assert!(rendered.contains(&format!("{}...", "界".repeat(50))));
    assert!(!rendered.contains(&unicode));
    assert!(!lines_text(&render_pubkey_input(&"a".repeat(50))).contains("..."));
    assert!(lines_text(&render_port_input("", 2222, 45678)).contains("45678"));
    assert!(lines_text(&render_port_input("", 2222, 45678)).contains("2222"));
    assert!(lines_text(&render_port_input("3456", 2222, 45678)).contains("3456"));
    let custom = render_mirror_custom_input("host", Some("invalid-fixture"));
    assert_eq!(custom.last().unwrap().spans[0].style.fg, Some(Color::Red));
    assert!(
        lines_text(&render_mirror_custom_input("", None))
            .contains(crate::i18n::tr("tui_mirror_custom_placeholder"))
    );
    for selected in 0..2 {
        let options = render_select_options(&["first", "second"], selected);
        assert_eq!(options[selected + 1].spans[0].style.fg, Some(Color::Cyan));
        let strings = render_string_list(&["first".into(), "second".into()], selected);
        assert_eq!(strings[selected + 1].spans[0].style.fg, Some(Color::Cyan));
        let mirrors = render_mirror_options(&["first".into(), "second".into()], selected);
        assert_eq!(mirrors[selected + 1].spans[0].style.fg, Some(Color::Cyan));
    }
    assert_eq!(render_string_list(&[], 0).len(), 1);
    assert_eq!(render_select_options(&[], 0).len(), 1);
}
