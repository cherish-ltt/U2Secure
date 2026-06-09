//! TUI (ratatui) 表示层 —— 终端图形界面
//!
//! 布局：
//! ┌─ Title ──────────────────────────────────────────────┐
//! ├─ 审计摘要 ───────────────────────────────────────────┤
//! ├───────────┬──────────────────────────────────────────┤
//! │ 步骤列表   │ 执行状态 / 操作提示 / 结果摘要          │
//! │ (左面板)  │ (右面板)                                 │
//! ├───────────┴──────────────────────────────────────────┤
//! └─ Keybindings ────────────────────────────────────────┘

use std::collections::HashSet;
use std::io::{self, Stdout};
use std::sync::atomic::Ordering;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap},
};

use crate::application::orchestrator::HardeningOrchestrator;
use crate::application::steps::AllSteps;
use crate::domain::audit::{AuditReport, AuditStatus};
use crate::domain::steps::{ExecuteParams, HardeningStep, SshKeyAction, StepKind, StepResult};
use crate::infrastructure::rollback;
use crate::infrastructure::system;
use crate::presentation::cli;

// ---------------------------------------------------------------------------
// 类型别名
// ---------------------------------------------------------------------------

type TuiTerminal = Terminal<CrosstermBackend<Stdout>>;

// ---------------------------------------------------------------------------
// 状态定义
// ---------------------------------------------------------------------------

/// 步骤列表项
#[derive(Debug, Clone)]
struct StepItem {
    kind: StepKind,
    /// 是否被用户勾选
    checked: bool,
    /// 执行状态（用于执行阶段渲染）
    state: StepExecState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepExecState {
    /// 未执行 / 选择模式
    Idle,
    /// 正在执行
    Running,
    /// 执行成功
    Success,
    /// 执行失败
    Failure,
}

/// 日志条目（右侧面板渲染用）
#[derive(Debug, Clone)]
struct LogEntry {
    icon: &'static str,
    message: String,
}

/// TUI 弹窗状态（支持多步流程）
enum Popup {
    /// SSH 密钥：输入用户名
    SshKeyUsername { value: String },
    /// SSH 密钥：选择操作用户
    SshKeyUserSelect { users: Vec<String>, selected: usize },
    /// SSH 密钥：选择操作
    SshKeyAction { username: String, selected: usize },
    /// SSH 密钥：粘贴公钥
    SshKeyPaste { username: String, value: String },
    /// SSH 密钥：确认覆盖已有密钥
    SshKeyOverwrite { username: String, selected: usize },

    /// 创建用户：输入用户名
    CreateUserUsername { value: String },
    /// 创建用户：是否锁定密码
    CreateUserLockPw { username: String, lock: bool },

    /// 修改 SSH 端口：输入端口号
    SshPortInput { value: String },
}

/// TUI 模式
enum AppMode {
    /// 步骤选择
    Select,
    /// 执行中
    Executing,
    /// 执行完毕摘要
    Summary,
}

/// TUI 应用程序状态
struct TuiApp {
    report: AuditReport,
    steps: Vec<StepItem>,
    cursor: usize,
    mode: AppMode,
    /// 执行日志（跨模式保留）
    logs: Vec<LogEntry>,
    /// 执行结果
    results: Vec<StepResult>,
    /// 当前执行进度
    progress: (usize, usize), // (current, total)
    /// TUI 弹窗（激活时覆盖主界面）
    popup: Option<Popup>,
}

// ---------------------------------------------------------------------------
// 公共入口
// ---------------------------------------------------------------------------

/// 运行 TUI 界面
pub fn run_tui(orchestrator: &HardeningOrchestrator) -> anyhow::Result<()> {
    // 初始化终端
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 执行初始审计
    let report = orchestrator.audit();
    let steps = init_steps(&report);

    let mut app = TuiApp {
        report,
        steps,
        cursor: 0,
        mode: AppMode::Select,
        logs: vec![],
        results: vec![],
        progress: (0, 0),
        popup: None,
    };

    // 运行主循环
    let result = run_app(&mut terminal, &mut app, orchestrator);

    // 清理终端
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

// ---------------------------------------------------------------------------
// 主事件循环
// ---------------------------------------------------------------------------

fn run_app(
    terminal: &mut TuiTerminal,
    app: &mut TuiApp,
    orchestrator: &HardeningOrchestrator,
) -> anyhow::Result<()> {
    loop {
        // 渲染
        terminal.draw(|f| render(f, app))?;

        // 处理事件
        let event = event::read()?;

        // ── 弹窗激活时，优先处理 ──
        if let Some(ref mut p) = app.popup {
            if let Event::Key(key) = event
                && key.kind == KeyEventKind::Press
            {
                match *p {
                    Popup::SshKeyUsername { ref mut value } => match key.code {
                        KeyCode::Char(c) => value.push(c),
                        KeyCode::Backspace => {
                            value.pop();
                        }
                        KeyCode::Enter if !value.is_empty() => {
                            let username = value.clone();
                            app.popup = Some(Popup::SshKeyAction {
                                username,
                                selected: 0,
                            });
                        }
                        KeyCode::Esc => app.popup = None,
                        _ => {}
                    },
                    Popup::SshKeyUserSelect {
                        ref users,
                        ref mut selected,
                    } => match key.code {
                        KeyCode::Up | KeyCode::Char('k') => {
                            *selected = selected.saturating_sub(1);
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            *selected = selected.saturating_add(1).min(users.len().saturating_sub(1));
                        }
                        KeyCode::Enter => {
                            let username = users[*selected].clone();
                            app.popup = Some(Popup::SshKeyAction {
                                username,
                                selected: 0,
                            });
                        }
                        KeyCode::Esc => app.popup = None,
                        _ => {}
                    },
                    Popup::SshKeyAction {
                        ref username,
                        ref mut selected,
                    } => match key.code {
                        KeyCode::Up | KeyCode::Char('k') => {
                            *selected = selected.saturating_sub(1);
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            *selected = selected.saturating_add(1).min(2);
                        }
                        KeyCode::Enter => match *selected {
                            0 => {
                                let u = username.clone();
                                // 检查密钥是否已存在
                                let home = system::home_dir(&u);
                                let key_path = format!("{}/.ssh/id_ed25519", home);
                                if std::path::Path::new(&key_path).exists() {
                                    app.popup = Some(Popup::SshKeyOverwrite {
                                        username: u,
                                        selected: 0,
                                    });
                                } else {
                                    app.popup = None;
                                    run_ssh_key_setup(
                                        app, terminal, orchestrator, u,
                                        Some(SshKeyAction::GenerateNew),
                                    )?;
                                }
                            }
                            1 => {
                                let u = username.clone();
                                app.popup = Some(Popup::SshKeyPaste {
                                    username: u,
                                    value: String::new(),
                                });
                            }
                            _ => { app.popup = None; }
                        },
                        KeyCode::Esc => app.popup = None,
                        _ => {}
                    },
                    Popup::SshKeyPaste {
                        ref username,
                        ref mut value,
                    } => match key.code {
                        KeyCode::Char(c) => value.push(c),
                        KeyCode::Backspace => { value.pop(); }
                        KeyCode::Enter if !value.is_empty() => {
                            let u = username.clone();
                            let pk = value.clone();
                            app.popup = None;
                            run_ssh_key_setup(
                                app, terminal, orchestrator, u,
                                Some(SshKeyAction::PasteKey(pk)),
                            )?;
                        }
                        KeyCode::Esc => {
                            let u = username.clone();
                            app.popup = Some(Popup::SshKeyAction {
                                username: u,
                                selected: 0,
                            });
                        }
                        _ => {}
                    },
                    Popup::SshKeyOverwrite {
                        ref username,
                        ref mut selected,
                    } => match key.code {
                        KeyCode::Up | KeyCode::Char('k') => {
                            *selected = 0;
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            *selected = 1;
                        }
                        KeyCode::Enter => match *selected {
                            0 => {
                                let u = username.clone();
                                app.popup = None;
                                // 先删旧密钥再重建
                                let home = system::home_dir(&u);
                                for f in ["id_ed25519", "id_ed25519.pub"] {
                                    let p = format!("{}/.ssh/{}", home, f);
                                    let _ = std::fs::remove_file(&p);
                                }
                                run_ssh_key_setup(
                                    app, terminal, orchestrator, u,
                                    Some(SshKeyAction::GenerateNew),
                                )?;
                            }
                            _ => {
                                let u = username.clone();
                                app.popup = Some(Popup::SshKeyAction {
                                    username: u,
                                    selected: 0,
                                });
                            }
                        },
                        KeyCode::Esc => {
                            let u = username.clone();
                            app.popup = Some(Popup::SshKeyAction {
                                username: u,
                                selected: 0,
                            });
                        }
                        _ => {}
                    },
                    // ── 创建用户 ──
                    Popup::CreateUserUsername { ref mut value } => match key.code {
                        KeyCode::Char(c) if c.is_alphanumeric() || c == '-' || c == '_' => {
                            if value.len() < 32 {
                                value.push(c);
                            }
                        }
                        KeyCode::Backspace => { value.pop(); }
                        KeyCode::Enter if !value.is_empty() => {
                            let username = value.clone();
                            app.popup = Some(Popup::CreateUserLockPw {
                                username,
                                lock: true,
                            });
                        }
                        KeyCode::Esc => app.popup = None,
                        _ => {}
                    },
                    Popup::CreateUserLockPw {
                        ref username,
                        ref mut lock,
                    } => match key.code {
                        KeyCode::Up | KeyCode::Char('k') => *lock = true,
                        KeyCode::Down | KeyCode::Char('j') => *lock = false,
                        KeyCode::Enter => {
                            let u = username.clone();
                            let l = *lock;
                            app.popup = None;
                            run_user_creation(app, terminal, orchestrator, u, l)?;
                        }
                        KeyCode::Esc => {
                            let u = username.clone();
                            app.popup = Some(Popup::CreateUserUsername { value: u });
                        }
                        _ => {}
                    },
                    // ── SSH 端口 ──
                    Popup::SshPortInput { ref mut value } => match key.code {
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            if value.len() < 5 {
                                value.push(c);
                            }
                        }
                        KeyCode::Backspace => { value.pop(); }
                        KeyCode::Enter if !value.is_empty() => {
                            if let Ok(port) = value.parse::<u16>()
                                && port > 0
                            {
                                app.popup = None;
                                run_ssh_port_change(app, terminal, orchestrator, port)?;
                            }
                        }
                        KeyCode::Esc => app.popup = None,
                        _ => {}
                    },
                }
            }
            terminal.draw(|f| render(f, app))?;
            continue;
        }

        match app.mode {
            AppMode::Select => {
                if let Event::Key(key) = event {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Up | KeyCode::Char('k') => {
                            app.cursor = app.cursor.saturating_sub(1);
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.cursor = app
                                .cursor
                                .saturating_add(1)
                                .min(app.steps.len().saturating_sub(1));
                        }
                        KeyCode::Char(' ') => {
                            if app.cursor < app.steps.len() {
                                app.steps[app.cursor].checked ^= true;
                            }
                        }
                        KeyCode::Enter => {
                            let selected: Vec<StepKind> = app
                                .steps
                                .iter()
                                .filter(|s| s.checked)
                                .map(|s| s.kind)
                                .collect();
                            if !selected.is_empty() {
                                let params = suspend_for_params(terminal, &selected, &app.report);
                                let total = selected.len();
                                app.logs.clear();
                                app.results.clear();
                                app.progress = (0, total);
                                // 重置步骤状态
                                for s in &mut app.steps {
                                    s.state = StepExecState::Idle;
                                }
                                app.mode = AppMode::Executing;
                                execute_batch(app, terminal, orchestrator, &selected, &params)?;
                                app.mode = AppMode::Summary;
                            }
                        }
                        KeyCode::Char('e') => {
                            if app.cursor < app.steps.len() {
                                let kind = app.steps[app.cursor].kind;

                                // 单项执行：有交互需求的步骤用 TUI 弹窗
                                match kind {
                                    StepKind::UserCreation => {
                                        app.popup = Some(Popup::CreateUserUsername {
                                            value: String::new(),
                                        });
                                        continue;
                                    }
                                    StepKind::SshKeySetup => {
                                        let users = system::detect_sudo_users();
                                        if users.is_empty() {
                                            app.popup = Some(Popup::SshKeyUsername {
                                                value: String::new(),
                                            });
                                        } else {
                                            // 包含 root 在内供用户选择
                                            let mut choices = vec!["root".to_string()];
                                            for u in users {
                                                if u != "root" {
                                                    choices.push(u);
                                                }
                                            }
                                            app.popup = Some(Popup::SshKeyUserSelect {
                                                users: choices,
                                                selected: 0,
                                            });
                                        }
                                        continue;
                                    }
                                    StepKind::SshPortChange => {
                                        app.popup = Some(Popup::SshPortInput {
                                            value: String::new(),
                                        });
                                        continue;
                                    }
                                    _ => {}
                                }

                                let params = suspend_for_params(terminal, &[kind], &app.report);
                                app.logs.clear();
                                app.results.clear();
                                app.progress = (0, 1);
                                for s in &mut app.steps {
                                    s.state = StepExecState::Idle;
                                }
                                app.mode = AppMode::Executing;
                                execute_single(app, terminal, orchestrator, kind, &params)?;
                                app.mode = AppMode::Summary;
                            }
                        }
                        KeyCode::Char('r') => {
                            app.report = orchestrator.audit();
                            app.steps = init_steps(&app.report);
                            app.logs.clear();
                            app.results.clear();
                        }
                        KeyCode::Char('q') => return Ok(()),
                        _ => {}
                    }
                }
            }
            AppMode::Executing => {
                // 执行中不响应按键，仅允许 Ctrl+C（已在信号处理器中处理）
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                    && let KeyCode::Esc = key.code
                {
                    // 紧急返回（极少使用）
                    app.mode = AppMode::Select;
                }
            }
            AppMode::Summary => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    // 重新审计并返回选择
                    app.report = orchestrator.audit();
                    app.steps = init_steps(&app.report);
                    app.mode = AppMode::Select;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 执行逻辑
// ---------------------------------------------------------------------------

/// 批量执行选中的步骤
fn execute_batch(
    app: &mut TuiApp,
    terminal: &mut TuiTerminal,
    orchestrator: &HardeningOrchestrator,
    selected: &[StepKind],
    params: &ExecuteParams,
) -> anyhow::Result<()> {
    let all_steps = AllSteps::new();
    let selected_set: HashSet<StepKind> = selected.iter().copied().collect();

    // 按定义顺序过滤出要执行的步骤
    let steps_to_run: Vec<&Box<dyn HardeningStep>> = all_steps
        .steps()
        .iter()
        .filter(|s| selected_set.contains(&s.kind()))
        .collect();

    let total = steps_to_run.len();

    for (i, step) in steps_to_run.iter().enumerate() {
        // 检查 Ctrl+C 中断
        if rollback::INTERRUPTED.load(Ordering::SeqCst) {
            rollback::INTERRUPTED.store(false, Ordering::SeqCst);
            app.logs.push(LogEntry {
                icon: "⚠️",
                message: "用户中断".into(),
            });
            app.progress = (i, total);
            terminal.draw(|f| render(f, app))?;
            break;
        }

        let kind = step.kind();

        // 标记步骤为执行中
        mark_step_state(app, kind, StepExecState::Running);
        app.logs.push(LogEntry {
            icon: "▶",
            message: format!("正在执行: {}", kind.label()),
        });
        app.progress = (i, total);
        terminal.draw(|f| render(f, app))?;

        // 执行步骤
        match step.execute(params) {
            Ok(result) => {
                if result.changes_made {
                    mark_step_state(app, kind, StepExecState::Success);
                    app.logs.push(LogEntry {
                        icon: "✅",
                        message: format!("已完成: {}", kind.label()),
                    });
                } else {
                    // changes_made = false 认为是跳过而非失败
                    mark_step_state(app, kind, StepExecState::Idle);
                    app.logs.push(LogEntry {
                        icon: "⏭",
                        message: format!("跳过: {}", result.message),
                    });
                }
                app.results.push(result);
                orchestrator.logger.log_operation("完成", kind.label());
            }
            Err(e) => {
                mark_step_state(app, kind, StepExecState::Failure);
                app.logs.push(LogEntry {
                    icon: "❌",
                    message: format!("失败: {}", e),
                });
                let err_result = StepResult {
                    kind,
                    changes_made: false,
                    message: format!("失败: {e}"),
                };
                app.results.push(err_result);
                orchestrator
                    .logger
                    .log_operation("失败", &format!("{}: {e}", kind.label()));

                // 自动回退
                orchestrator
                    .logger
                    .log("[回退] 步骤失败，自动回退所有已注册的修改");
                rollback::undo_all();

                app.progress = (i + 1, total);
                terminal.draw(|f| render(f, app))?;
                break;
            }
        }

        app.progress = (i + 1, total);
        terminal.draw(|f| render(f, app))?;
    }

    Ok(())
}

/// 单个步骤执行
fn execute_single(
    app: &mut TuiApp,
    terminal: &mut TuiTerminal,
    _orchestrator: &HardeningOrchestrator,
    kind: StepKind,
    params: &ExecuteParams,
) -> anyhow::Result<()> {
    let all_steps = AllSteps::new();

    // 找到对应的步骤
    let step = all_steps.steps().iter().find(|s| s.kind() == kind);
    let step = match step {
        Some(s) => s,
        None => {
            app.logs.push(LogEntry {
                icon: "❌",
                message: format!("未找到步骤: {}", kind.label()),
            });
            return Ok(());
        }
    };

    // 标记为执行中
    mark_step_state(app, kind, StepExecState::Running);
    app.logs.push(LogEntry {
        icon: "▶",
        message: format!("正在执行: {}", kind.label()),
    });
    app.progress = (0, 1);
    terminal.draw(|f| render(f, app))?;

    // 执行
    match step.execute(params) {
        Ok(result) => {
            if result.changes_made {
                mark_step_state(app, kind, StepExecState::Success);
                app.logs.push(LogEntry {
                    icon: "✅",
                    message: format!("已完成: {}", kind.label()),
                });
            } else {
                mark_step_state(app, kind, StepExecState::Idle);
                app.logs.push(LogEntry {
                    icon: "⏭",
                    message: format!("跳过: {}", result.message),
                });
            }
            app.results.push(result);
        }
        Err(e) => {
            mark_step_state(app, kind, StepExecState::Failure);
            app.logs.push(LogEntry {
                icon: "❌",
                message: format!("失败: {}", e),
            });
            app.results.push(StepResult {
                kind,
                changes_made: false,
                message: format!("失败: {e}"),
            });
        }
    }

    app.progress = (1, 1);
    terminal.draw(|f| render(f, app))?;

    Ok(())
}

/// 执行 SSH 密钥设置（从弹窗流程调用）
fn run_ssh_key_setup(
    app: &mut TuiApp,
    terminal: &mut TuiTerminal,
    _orchestrator: &HardeningOrchestrator,
    username: String,
    action: Option<SshKeyAction>,
) -> anyhow::Result<()> {
    let params = ExecuteParams {
        ssh_key_username: Some(username),
        ssh_key_action: action,
        ..Default::default()
    };
    app.logs.clear();
    app.results.clear();
    app.progress = (0, 1);
    for s in &mut app.steps {
        s.state = StepExecState::Idle;
    }
    app.mode = AppMode::Executing;
    execute_single(app, terminal, _orchestrator, StepKind::SshKeySetup, &params)?;
    app.mode = AppMode::Summary;
    Ok(())
}

/// 执行非 root 用户创建（从弹窗流程调用）
fn run_user_creation(
    app: &mut TuiApp,
    terminal: &mut TuiTerminal,
    _orchestrator: &HardeningOrchestrator,
    username: String,
    lock_password: bool,
) -> anyhow::Result<()> {
    let params = ExecuteParams {
        new_username: Some(username.clone()),
        lock_password,
        ssh_key_username: Some(username),
        ssh_key_action: Some(SshKeyAction::GenerateNew),
        ..Default::default()
    };
    app.logs.clear();
    app.results.clear();
    app.progress = (0, 1);
    for s in &mut app.steps {
        s.state = StepExecState::Idle;
    }
    app.mode = AppMode::Executing;
    execute_single(app, terminal, _orchestrator, StepKind::UserCreation, &params)?;
    app.mode = AppMode::Summary;
    Ok(())
}

/// 执行 SSH 端口修改（从弹窗流程调用）
fn run_ssh_port_change(
    app: &mut TuiApp,
    terminal: &mut TuiTerminal,
    _orchestrator: &HardeningOrchestrator,
    port: u16,
) -> anyhow::Result<()> {
    let params = ExecuteParams {
        new_ssh_port: Some(port),
        ..Default::default()
    };
    app.logs.clear();
    app.results.clear();
    app.progress = (0, 1);
    for s in &mut app.steps {
        s.state = StepExecState::Idle;
    }
    app.mode = AppMode::Executing;
    execute_single(app, terminal, _orchestrator, StepKind::SshPortChange, &params)?;
    app.mode = AppMode::Summary;
    Ok(())
}

/// 标记某个步骤的执行状态
fn mark_step_state(app: &mut TuiApp, kind: StepKind, state: StepExecState) {
    if let Some(item) = app.steps.iter_mut().find(|s| s.kind == kind) {
        item.state = state;
    }
}

// ---------------------------------------------------------------------------
// 参数收集（挂起 TUI，复用 CLI 的 dialoguer 交互）
// ---------------------------------------------------------------------------

fn suspend_for_params(
    terminal: &mut TuiTerminal,
    selected: &[StepKind],
    report: &AuditReport,
) -> ExecuteParams {
    // 挂起 TUI
    disable_raw_mode().ok();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    // 使用 CLI 现有的 dialoguer 参数收集
    let params = cli::collect_step_params(selected, report);

    // 恢复 TUI
    let _ = enable_raw_mode();
    let _ = execute!(terminal.backend_mut(), EnterAlternateScreen);
    let _ = terminal.clear();

    params
}

// ---------------------------------------------------------------------------
// 初始化步骤列表
// ---------------------------------------------------------------------------

fn init_steps(report: &AuditReport) -> Vec<StepItem> {
    let all_kinds = StepKind::all();
    all_kinds
        .iter()
        .map(|kind| StepItem {
            kind: *kind,
            // 默认勾选未安全配置的项
            checked: !matches!(kind.check_default_status(report), AuditStatus::Safe),
            state: StepExecState::Idle,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 渲染
// ---------------------------------------------------------------------------

fn render(frame: &mut Frame, app: &TuiApp) {
    let area = frame.area();

    // 垂直分割：标题 / 审计摘要 / 主内容 / 底部快捷键
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Title
            Constraint::Length(5), // Audit summary (with wrapping)
            Constraint::Min(1),    // Main content
            Constraint::Length(1), // Footer
        ])
        .split(area);

    render_title(frame, vert[0]);
    render_audit_summary(frame, vert[1], &app.report);
    render_main_content(frame, vert[2], app);
    render_footer(frame, vert[3], app);

    // 弹窗（叠加在最上层）
    if app.popup.is_some() {
        render_popup(frame, area, app);
    }
}

// ---------------------------------------------------------------------------
// 标题栏
// ---------------------------------------------------------------------------

fn render_title(frame: &mut Frame, area: ratatui::layout::Rect) {
    let version = env!("CARGO_PKG_VERSION");
    let title = Line::from(vec![
        Span::styled(
            format!(" U2Secure v{} ", version),
            Style::default().fg(Color::White).bg(Color::Blue),
        ),
        Span::styled(
            " — Linux 服务器安全加固工具 ",
            Style::default().fg(Color::Cyan).bg(Color::Blue),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(title).style(Style::default().bg(Color::Blue)),
        area,
    );
}

// ---------------------------------------------------------------------------
// 审计摘要
// ---------------------------------------------------------------------------

fn render_audit_summary(frame: &mut Frame, area: ratatui::layout::Rect, report: &AuditReport) {
    let block = Block::default()
        .title(" 审计报告 ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default());

    // 将审计项压缩为一行
    let mut spans: Vec<Span> = vec![];
    for item in &report.items {
        let icon = item.status.icon();
        let fg = match item.status {
            AuditStatus::Safe => Color::Green,
            AuditStatus::Partial => Color::Yellow,
            AuditStatus::Missing => Color::Red,
            AuditStatus::NeedsUpdate => Color::Yellow,
        };
        spans.push(Span::styled(
            format!(" {icon} {}", item.name),
            Style::default().fg(fg),
        ));
    }

    let text = Paragraph::new(Line::from(spans))
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(text, area);
}

// ---------------------------------------------------------------------------
// 主内容区（左右分栏）
// ---------------------------------------------------------------------------

fn render_main_content(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    let horiz = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    render_step_list(frame, horiz[0], app);
    render_right_panel(frame, horiz[1], app);
}

// ---------------------------------------------------------------------------
// 左面板：步骤列表
// ---------------------------------------------------------------------------

fn render_step_list(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    let block = Block::default()
        .title(format!(" 加固步骤 ({}) ", app.steps.len()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let items: Vec<ListItem> = app
        .steps
        .iter()
        .map(|step| {
            let status_icon = step.kind.check_default_status(&app.report).icon();
            let checkbox = if step.checked { "[✓]" } else { "[ ]" };
            let label = step.kind.label();

            // 根据执行状态调整样式
            let (prefix, style) = match step.state {
                StepExecState::Running => ("▶ ", Style::default().fg(Color::Cyan).bold()),
                StepExecState::Success => ("✓ ", Style::default().fg(Color::Green)),
                StepExecState::Failure => ("✗ ", Style::default().fg(Color::Red)),
                StepExecState::Idle => ("  ", Style::default()),
            };

            let content = format!(" {} {} {} {}", prefix, checkbox, label, status_icon);
            ListItem::new(Line::from(Span::styled(content, style)))
        })
        .collect();

    let selected_style = Style::default()
        .bg(Color::Rgb(40, 40, 80))
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);

    let list = List::new(items)
        .block(block)
        .highlight_style(selected_style)
        .highlight_symbol("▸");

    let mut state = ratatui::widgets::ListState::default().with_selected(Some(app.cursor));
    frame.render_stateful_widget(list, area, &mut state);
}

// ---------------------------------------------------------------------------
// 右面板：操作提示 / 执行日志 / 结果摘要
// ---------------------------------------------------------------------------

fn render_right_panel(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    match app.mode {
        AppMode::Select => render_right_help(frame, area, app),
        AppMode::Executing => render_right_executing(frame, area, app),
        AppMode::Summary => render_right_summary(frame, area, app),
    }
}

/// 选择模式：操作提示
fn render_right_help(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    let block = Block::default()
        .title(" 操作提示 ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let selected_count = app.steps.iter().filter(|s| s.checked).count();

    let help = Text::from(vec![
        Line::from(vec![Span::raw("")]),
        Line::from(vec![
            Span::styled("  ↑↓", Style::default().bold()),
            Span::raw("  移动光标"),
        ]),
        Line::from(vec![
            Span::styled(" Space", Style::default().bold()),
            Span::raw("  切换选择 / 取消"),
        ]),
        Line::from(vec![
            Span::styled(" Enter", Style::default().bold()),
            Span::raw("  批量执行选中的步骤"),
        ]),
        Line::from(vec![
            Span::styled(" e", Style::default().bold()),
            Span::raw("  立即执行当前步骤"),
        ]),
        Line::from(vec![
            Span::styled(" r", Style::default().bold()),
            Span::raw("  重新审计"),
        ]),
        Line::from(vec![
            Span::styled(" q", Style::default().bold()),
            Span::raw("  退出"),
        ]),
        Line::from(vec![Span::raw("")]),
        Line::from(vec![Span::styled(
            format!(" 已勾选 {} 项", selected_count),
            Style::default().fg(Color::Cyan),
        )]),
        Line::from(vec![Span::styled(
            " 按 e 可强制执行任意单项",
            Style::default().dim(),
        )]),
    ]);

    frame.render_widget(
        Paragraph::new(help).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

/// 执行中：日志 + 进度条
fn render_right_executing(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    let block = Block::default()
        .title(" 执行状态 ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // 上下分割：日志区 + 进度条
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    // 日志区：显示最近 10 条
    let log_lines: Vec<Line> = app
        .logs
        .iter()
        .rev()
        .take(10)
        .rev()
        .map(|entry| {
            let icon_style = if entry.icon == "▶" {
                Style::default().fg(Color::Cyan)
            } else if entry.icon == "✅" {
                Style::default().fg(Color::Green)
            } else if entry.icon == "❌" {
                Style::default().fg(Color::Red)
            } else if entry.icon == "⚠️" {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            Line::from(vec![
                Span::styled(format!(" {} ", entry.icon), icon_style),
                Span::styled(&entry.message, Style::default()),
            ])
        })
        .collect();

    let log_widget = Paragraph::new(Text::from(log_lines)).wrap(Wrap { trim: false });
    frame.render_widget(log_widget, chunks[0]);

    // 进度条
    let (current, total) = app.progress;
    let ratio = if total > 0 {
        current as f64 / total as f64
    } else {
        0.0
    };
    let gauge = Gauge::default()
        .ratio(ratio.min(1.0))
        .label(format!(" {}/{} ", current, total))
        .style(Style::default().fg(Color::Cyan))
        .gauge_style(Style::default().bg(Color::DarkGray).fg(Color::Green));
    frame.render_widget(gauge, chunks[1]);
}

/// 摘要模式：执行结果
fn render_right_summary(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    let block = Block::default()
        .title(" 执行结果 ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let success = app.results.iter().filter(|r| r.changes_made).count();
    let failed = app.results.len().saturating_sub(success);

    let mut lines = vec![Line::from(vec![Span::raw("")])];

    // 每步结果
    for r in &app.results {
        let (icon, fg) = if r.changes_made {
            ("✅", Color::Green)
        } else {
            ("❌", Color::Red)
        };
        if r.changes_made {
            // 成功：只显示步骤名
            lines.push(Line::from(vec![
                Span::styled(format!(" {} ", icon), Style::default().fg(fg)),
                Span::styled(r.kind.label(), Style::default()),
            ]));
        } else {
            // 失败/跳过：显示原因
            lines.push(Line::from(vec![
                Span::styled(format!(" {} ", icon), Style::default().fg(fg)),
                Span::styled(r.kind.label(), Style::default()),
                Span::styled(format!(": {}", r.message), Style::default().dim()),
            ]));
        }
    }

    lines.push(Line::from(vec![Span::raw("")]));

    // 总计
    let stats = format!(" 总计: {} 成功, {} 失败/跳过", success, failed,);
    lines.push(Line::from(vec![Span::styled(
        stats,
        Style::default().bold(),
    )]));

    lines.push(Line::from(vec![Span::raw("")]));
    lines.push(Line::from(vec![Span::styled(
        " 按任意键返回步骤列表",
        Style::default().dim(),
    )]));

    let text = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(text, area);
}

// ---------------------------------------------------------------------------
// 底部快捷键栏
// ---------------------------------------------------------------------------

fn render_footer(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    let (text, style) = match app.mode {
        AppMode::Select => (
            " ↑↓/jk 移动 | Space 选择 | Enter 批量执行 | e 单项执行 | r 重新审计 | q 退出 ",
            Style::default().fg(Color::White).bg(Color::Rgb(30, 30, 50)),
        ),
        AppMode::Executing => (
            " 执行中... 按 Ctrl+C 中断 ",
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::Rgb(40, 20, 20)),
        ),
        AppMode::Summary => (
            " 执行完毕 | 按任意键返回步骤列表 ",
            Style::default().fg(Color::White).bg(Color::Rgb(20, 40, 20)),
        ),
    };

    frame.render_widget(Paragraph::new(Line::from(Span::styled(text, style))), area);
}

// ---------------------------------------------------------------------------
// 弹窗渲染（叠加层）
// ---------------------------------------------------------------------------

/// 在界面顶层渲染弹窗（输入 / 选择 / 粘贴）
fn render_popup(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    let popup = app.popup.as_ref().unwrap();

    // 统一弹窗尺寸逻辑
    let (title, height, content_lines, hint_line) = match popup {
        Popup::SshKeyUsername { value } => (
            " 目标用户名 ",
            5,
            render_username_input(value),
            " Enter 确认  Esc 取消 ",
        ),
        Popup::SshKeyUserSelect { users, selected } => (
            " 选择用户 ",
            (users.len() + 2).clamp(5, 12) as u16,
            render_string_list(users, *selected),
            " ↑↓ 选择  Enter 确认  Esc 取消 ",
        ),
        Popup::SshKeyAction { selected, .. } => (
            " 选择操作 ",
            7,
            render_select_options(&["生成新密钥对", "粘贴已有公钥", "跳过"], *selected),
            " ↑↓ 选择  Enter 确认  Esc 取消 ",
        ),
        Popup::SshKeyPaste { value, .. } => (
            " 粘贴公钥 ",
            5,
            render_pubkey_input(value),
            " Enter 确认  Esc 返回 ",
        ),
        Popup::SshKeyOverwrite { selected, .. } => (
            " 密钥已存在 ",
            7,
            render_select_options(&["重新创建 (覆盖现有密钥)", "取消"], *selected),
            " ↑↓ 选择  Enter 确认  Esc 返回 ",
        ),
        Popup::CreateUserUsername { value } => (
            " 新用户名 ",
            5,
            render_username_input(value),
            " Enter 确认  Esc 取消 ",
        ),
        Popup::CreateUserLockPw { lock, .. } => (
            " 锁定密码 ",
            7,
            render_select_options(&["是 (锁定密码, 强制密钥登录)", "否 (不锁定密码)"], if *lock { 0 } else { 1 }),
            " ↑↓ 选择  Enter 确认  Esc 返回 ",
        ),
        Popup::SshPortInput { value } => (
            " 新 SSH 端口 ",
            5,
            render_port_input(value),
            " Enter 确认  Esc 取消 ",
        ),
    };

    let width = area.width.clamp(36, 64);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let popup_area = ratatui::layout::Rect {
        x,
        y,
        width,
        height,
    };

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(Color::Rgb(25, 25, 45)));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // 内容区
    frame.render_widget(
        Paragraph::new(Text::from(content_lines)).wrap(Wrap { trim: false }),
        inner,
    );

    // 底部提示
    let hint_area = ratatui::layout::Rect {
        x: inner.x,
        y: inner.y + inner.height.saturating_sub(1),
        width: inner.width,
        height: 1,
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(hint_line, Style::default().dim()))),
        hint_area,
    );
}

/// 用户名输入框内容
fn render_username_input(value: &str) -> Vec<Line<'static>> {
    if value.is_empty() {
        vec![
            Line::from(vec![Span::raw("")]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled("输入用户名...", Style::default().dim().fg(Color::Gray)),
                Span::styled("█", Style::default().fg(Color::Cyan)),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![Span::raw("")]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(value.to_string(), Style::default().fg(Color::White)),
                Span::styled("█", Style::default().fg(Color::Cyan)),
            ]),
        ]
    }
}

/// 公钥粘贴框内容
fn render_pubkey_input(value: &str) -> Vec<Line<'static>> {
    if value.is_empty() {
        vec![
            Line::from(vec![Span::raw("")]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    "粘贴 ssh-ed25519 / ssh-rsa 公钥内容...",
                    Style::default().dim().fg(Color::Gray),
                ),
                Span::styled("█", Style::default().fg(Color::Cyan)),
            ]),
        ]
    } else {
        // 显示开头部分+光标
        let display = if value.len() > 50 {
            format!("{}...█", &value[..50])
        } else {
            format!("{}█", value)
        };
        vec![
            Line::from(vec![Span::raw("")]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(display, Style::default().fg(Color::White)),
            ]),
        ]
    }
}

/// 通用选项列表渲染
fn render_select_options(options: &[&'static str], selected: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![Span::raw("")])];
    for (i, opt) in options.iter().enumerate() {
        let prefix = if i == selected { " ▸ " } else { "   " };
        let style = if i == selected {
            Style::default().fg(Color::Cyan).bold()
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(*opt, style),
        ]));
    }
    lines
}

/// 动态字符串列表渲染（用于用户选择等）
fn render_string_list(items: &[String], selected: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![Span::raw("")])];
    for (i, item) in items.iter().enumerate() {
        let prefix = if i == selected { " ▸ " } else { "   " };
        let style = if i == selected {
            Style::default().fg(Color::Cyan).bold()
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(item.clone(), style),
        ]));
    }
    lines
}

/// SSH 端口输入框内容
fn render_port_input(value: &str) -> Vec<Line<'static>> {
    let current_port = system::detect_ssh_port();
    if value.is_empty() {
        vec![
            Line::from(vec![Span::raw("")]),
            Line::from(vec![
                Span::raw("  建议端口: "),
                Span::styled(
                    system::random_suggested_port().to_string(),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw("  当前: "),
                Span::styled(
                    current_port.to_string(),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled("输入 0-65535...", Style::default().dim().fg(Color::Gray)),
                Span::styled("█", Style::default().fg(Color::Cyan)),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![Span::raw("")]),
            Line::from(vec![
                Span::raw("  端口: "),
                Span::styled(value.to_string(), Style::default().fg(Color::White)),
                Span::styled("█", Style::default().fg(Color::Cyan)),
            ]),
        ]
    }
}
