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
//!
//! 执行阶段在后台线程进行，主循环保持响应：
//! - 实时展示当前步骤、已耗时、最近日志与命令输出尾部
//! - Ctrl+C 取消并回滚（raw 模式下没有 SIGINT，必须自己处理按键）

use std::io::{self, Stdout};
use std::sync::atomic::Ordering;
use std::time::Duration;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
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

use crate::application::job::{JobEvent, JobHandle, StepRunner};
use crate::application::orchestrator::HardeningOrchestrator;
use crate::domain::audit::{AuditReport, AuditStatus};
use crate::domain::mirror::PackageMirror;
use crate::domain::steps::{ExecuteParams, SshKeyAction, StepKind, StepOutcome, StepResult};
use crate::infrastructure::rollback;
use crate::infrastructure::system;
use crate::infrastructure::{artifacts, package_mirror};
use crate::presentation::cli;

// ---------------------------------------------------------------------------
// 类型别名与常量
// ---------------------------------------------------------------------------

type TuiTerminal = Terminal<CrosstermBackend<Stdout>>;

/// 事件轮询间隔（保证执行期间 UI 仍在刷新）
const POLL_INTERVAL: Duration = Duration::from_millis(150);
/// 实时输出尾随行数
const TAIL_LINES: usize = 8;
/// 实时输出尾随字节上限
const TAIL_BYTES: u64 = 32 * 1024;
/// 执行日志面板保留行数
const LOG_PANEL_LINES: usize = 12;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

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

/// 当前正在执行的步骤
#[derive(Debug, Clone)]
struct CurrentStep {
    kind: StepKind,
    live_log: String,
}

/// 等待启动的运行（镜像源选择完成后启动）
#[derive(Clone)]
struct PendingRun {
    selected: Vec<StepKind>,
    params: ExecuteParams,
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

    /// 临时软件源选择
    MirrorSelect { items: Vec<String>, selected: usize },
    /// 自定义软件源输入
    MirrorCustomInput {
        value: String,
        error: Option<String>,
    },
    /// 软件源连接失败：重试 / 更换源 / 取消执行
    MirrorFailedDialog { reason: String, selected: usize },
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
    progress: (usize, usize),
    /// TUI 弹窗（激活时覆盖主界面）
    popup: Option<Popup>,
    /// 后台任务
    job: Option<JobHandle>,
    /// 当前步骤（用于实时输出尾随）
    current: Option<CurrentStep>,
    /// 当前步骤输出的尾部
    live_tail: Vec<String>,
    /// 本次运行选择的临时软件源
    mirror: PackageMirror,
    /// 待启动/待重试的运行
    pending: Option<PendingRun>,
    /// 软件源连接失败原因（等待用户决策）
    mirror_failure: Option<String>,
    /// 状态栏提示
    status: String,
    /// 结果页滚动偏移
    summary_scroll: u16,
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
        job: None,
        current: None,
        live_tail: vec![],
        mirror: PackageMirror::Original,
        pending: None,
        mirror_failure: None,
        status: String::new(),
        summary_scroll: 0,
    };

    // 运行主循环
    let result = run_app(&mut terminal, &mut app, orchestrator);

    // 若有后台任务仍在运行，取消并等待其结束，避免留下孤儿进程
    if app.job.is_some() {
        rollback::INTERRUPTED.store(true, Ordering::SeqCst);
        if let Some(job) = app.job.take() {
            job.join();
        }
    }

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

        // 事件：非阻塞轮询，保证后台任务事件能被及时消费
        if event::poll(POLL_INTERVAL)? {
            let event = event::read()?;

            // Ctrl+C：raw 模式屏蔽了 SIGINT，必须显式处理按键
            if let Event::Key(key) = &event
                && key.kind == KeyEventKind::Press
                && is_ctrl_c(key)
            {
                if app.job.is_some() {
                    request_cancel(app);
                } else if app.popup.is_some() {
                    // 弹窗中按 Ctrl+C 视为取消弹窗，避免误退出丢失已选步骤
                    app.popup = None;
                    app.pending = None;
                    app.status = crate::i18n::tr("tui_mirror_cancelled").into();
                } else {
                    return Ok(());
                }
                continue;
            }

            // ── 弹窗激活时，优先处理 ──
            if app.popup.is_some() {
                handle_popup(app, terminal, orchestrator, event)?;
                continue;
            }

            match app.mode {
                AppMode::Select => {
                    if handle_select_mode(app, terminal, orchestrator, event)? {
                        return Ok(());
                    }
                },
                AppMode::Executing => handle_executing_mode(app, event),
                AppMode::Summary => handle_summary_mode(app, event, orchestrator),
            }
        }

        // 推进后台任务
        pump_job(app);
    }
}

fn is_ctrl_c(key: &KeyEvent) -> bool {
    key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)
}

/// 请求取消当前后台任务（由 StepRunner 负责停止并回滚）
fn request_cancel(app: &mut TuiApp) {
    rollback::INTERRUPTED.store(true, Ordering::SeqCst);
    app.status = crate::i18n::tr("tui_cancelling").into();
    app.logs.push(LogEntry {
        icon: "⚠️",
        message: crate::i18n::tr("tui_cancel_requested").into(),
    });
}

/// 消费后台任务事件
fn pump_job(app: &mut TuiApp) {
    let events = match &app.job {
        Some(job) => job.drain(),
        None => return,
    };

    let mut finished = false;
    for event in events {
        match event {
            JobEvent::StepStarted {
                kind,
                index,
                total,
                live_log,
            } => {
                mark_step_state(app, kind, StepExecState::Running);
                app.progress = (index, total);
                app.current = Some(CurrentStep { kind, live_log });
                app.live_tail.clear();
                app.logs.push(LogEntry {
                    icon: "▶",
                    message: crate::i18n::tr("tui_exec_running").replace("{step}", kind.label()),
                });
            },
            JobEvent::StepFinished(result) => {
                let icon = match result.outcome {
                    StepOutcome::Changed => {
                        mark_step_state(app, result.kind, StepExecState::Success);
                        "✅"
                    },
                    StepOutcome::Skipped => {
                        mark_step_state(app, result.kind, StepExecState::Idle);
                        "⏭"
                    },
                    StepOutcome::Failed => {
                        mark_step_state(app, result.kind, StepExecState::Failure);
                        "❌"
                    },
                };
                let first_line = result.message.lines().next().unwrap_or("").to_string();
                app.logs.push(LogEntry {
                    icon,
                    message: format!("{}: {}", result.kind.label(), first_line),
                });
                app.results.push(result);
            },
            JobEvent::Log(message) => app.logs.push(LogEntry {
                icon: "ℹ️",
                message,
            }),
            JobEvent::Interrupted => app.logs.push(LogEntry {
                icon: "⚠️",
                message: crate::i18n::tr("tui_exec_interrupted").into(),
            }),
            JobEvent::MirrorFailed { reason } => {
                app.mirror_failure = Some(reason);
            },
            JobEvent::AllFinished => finished = true,
        }
    }

    // 尾随当前步骤的输出文件
    if let Some(current) = &app.current {
        app.live_tail = artifacts::read_tail(&current.live_log, TAIL_LINES, TAIL_BYTES)
            .map(|text| text.lines().map(|l| l.to_string()).collect())
            .unwrap_or_default();
    }

    // 后台线程异常退出（如步骤 panic）：显式暴露，避免界面永久停在执行中
    if !finished
        && let Some(job) = &app.job
        && job.is_disconnected()
    {
        let kind = app
            .current
            .as_ref()
            .map(|current| current.kind)
            .unwrap_or(StepKind::SystemUpdate);
        app.logs.push(LogEntry {
            icon: "❌",
            message: crate::i18n::tr("tui_job_crashed").into(),
        });
        app.results
            .push(StepResult::failed(kind, crate::i18n::tr("tui_job_crashed")));
        finished = true;
    }

    if finished {
        if let Some(job) = app.job.take() {
            job.join();
        }
        app.progress = (app.progress.1, app.progress.1);
        app.current = None;
        app.status.clear();

        match app.mirror_failure.take() {
            // 软件源不可用：交回用户决策（重试 / 更换源 / 取消执行），不自动回退
            Some(reason) => {
                app.mode = AppMode::Select;
                app.popup = Some(Popup::MirrorFailedDialog {
                    reason,
                    selected: 0,
                });
            },
            None => {
                app.pending = None;
                app.mode = AppMode::Summary;
            },
        }
    }
}

// ---------------------------------------------------------------------------
// 各模式按键处理
// ---------------------------------------------------------------------------

/// 返回 true 表示需要退出 TUI
fn handle_select_mode(
    app: &mut TuiApp,
    terminal: &mut TuiTerminal,
    orchestrator: &HardeningOrchestrator,
    event: Event,
) -> anyhow::Result<bool> {
    let Event::Key(key) = event else {
        return Ok(false);
    };
    if key.kind != KeyEventKind::Press {
        return Ok(false);
    }

    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.cursor = app.cursor.saturating_sub(1);
        },
        KeyCode::Down | KeyCode::Char('j') => {
            app.cursor = app
                .cursor
                .saturating_add(1)
                .min(app.steps.len().saturating_sub(1));
        },
        KeyCode::Char(' ') => {
            if app.cursor < app.steps.len() {
                app.steps[app.cursor].checked ^= true;
            }
        },
        KeyCode::Char('a') => {
            // 全选/取消全选（可选步骤 9/10/11 仍需手动勾选）
            let all_on = app
                .steps
                .iter()
                .filter(|s| !s.kind.is_opt_in())
                .all(|s| s.checked);
            for step in &mut app.steps {
                if !step.kind.is_opt_in() {
                    step.checked = !all_on;
                }
            }
        },
        KeyCode::Enter => {
            let selected: Vec<StepKind> = app
                .steps
                .iter()
                .filter(|s| s.checked)
                .map(|s| s.kind)
                .collect();
            if selected.is_empty() {
                app.status = crate::i18n::tr("tui_no_selection").into();
                return Ok(false);
            }
            let params = suspend_for_params(terminal, &selected, &app.report);
            app.pending = Some(PendingRun { selected, params });
            begin_or_ask_mirror(app, terminal, orchestrator);
        },
        KeyCode::Char('e') => {
            if app.cursor >= app.steps.len() {
                return Ok(false);
            }
            let kind = app.steps[app.cursor].kind;

            // 单项执行：有交互需求的步骤用 TUI 弹窗
            match kind {
                StepKind::UserCreation => {
                    app.popup = Some(Popup::CreateUserUsername {
                        value: String::new(),
                    });
                    return Ok(false);
                },
                StepKind::SshKeySetup => {
                    let users = system::detect_sudo_users();
                    if users.is_empty() {
                        app.popup = Some(Popup::SshKeyUsername {
                            value: String::new(),
                        });
                    } else {
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
                    return Ok(false);
                },
                StepKind::SshPortChange => {
                    app.popup = Some(Popup::SshPortInput {
                        value: String::new(),
                    });
                    return Ok(false);
                },
                _ => {},
            }

            let params = suspend_for_params(terminal, &[kind], &app.report);
            app.pending = Some(PendingRun {
                selected: vec![kind],
                params,
            });
            begin_or_ask_mirror(app, terminal, orchestrator);
        },
        KeyCode::Char('r') => {
            app.status = crate::i18n::tr("tui_reauditing").into();
            terminal.draw(|f| render(f, app))?;
            app.report = orchestrator.audit();
            app.steps = init_steps(&app.report);
            app.logs.clear();
            app.results.clear();
            app.status.clear();
        },
        KeyCode::Char('q') => return Ok(true),
        _ => {},
    }
    Ok(false)
}

fn handle_executing_mode(app: &mut TuiApp, event: Event) {
    if let Event::Key(key) = event
        && key.kind == KeyEventKind::Press
        && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
    {
        app.status = crate::i18n::tr("tui_running_hint").into();
    }
}

fn handle_summary_mode(app: &mut TuiApp, event: Event, orchestrator: &HardeningOrchestrator) {
    let Event::Key(key) = event else {
        return;
    };
    if key.kind != KeyEventKind::Press {
        return;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.summary_scroll = app.summary_scroll.saturating_sub(1);
            return;
        },
        KeyCode::Down | KeyCode::Char('j') => {
            app.summary_scroll = app.summary_scroll.saturating_add(1);
            return;
        },
        KeyCode::PageUp => {
            app.summary_scroll = app.summary_scroll.saturating_sub(10);
            return;
        },
        KeyCode::PageDown => {
            app.summary_scroll = app.summary_scroll.saturating_add(10);
            return;
        },
        _ => {},
    }
    // 返回步骤列表并重新审计
    app.report = orchestrator.audit();
    app.steps = init_steps(&app.report);
    app.summary_scroll = 0;
    app.mode = AppMode::Select;
}

// ---------------------------------------------------------------------------
// 弹窗按键处理
// ---------------------------------------------------------------------------

fn handle_popup(
    app: &mut TuiApp,
    terminal: &mut TuiTerminal,
    orchestrator: &HardeningOrchestrator,
    event: Event,
) -> anyhow::Result<()> {
    let Event::Key(key) = event else {
        return Ok(());
    };
    if key.kind != KeyEventKind::Press {
        return Ok(());
    }

    let Some(ref mut p) = app.popup else {
        return Ok(());
    };

    match *p {
        Popup::MirrorSelect {
            ref items,
            ref mut selected,
        } => match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                *selected = selected.saturating_sub(1);
            },
            KeyCode::Down | KeyCode::Char('j') => {
                *selected = selected
                    .saturating_add(1)
                    .min(items.len().saturating_sub(1));
            },
            KeyCode::Enter => {
                let index = *selected;
                match PackageMirror::all().get(index).cloned() {
                    Some(mirror) => {
                        app.mirror = mirror;
                        app.popup = None;
                        start_pending(app, orchestrator);
                    },
                    // 列表最后一项为"自定义输入源"
                    None => {
                        app.popup = Some(Popup::MirrorCustomInput {
                            value: String::new(),
                            error: None,
                        });
                    },
                }
            },
            // 取消选择 → 回退原始软件源并继续执行
            KeyCode::Esc => {
                app.popup = None;
                app.mirror = PackageMirror::Original;
                app.status = crate::i18n::tr("tui_mirror_use_original").into();
                start_pending(app, orchestrator);
            },
            _ => {},
        },
        Popup::MirrorCustomInput {
            ref mut value,
            ref mut error,
        } => match key.code {
            KeyCode::Char(c) => {
                if value.chars().count() < 120 {
                    value.push(c);
                }
                *error = None;
            },
            KeyCode::Backspace => {
                value.pop();
                *error = None;
            },
            KeyCode::Enter if !value.is_empty() => match PackageMirror::custom(value) {
                Ok(mirror) => {
                    app.mirror = mirror;
                    app.popup = None;
                    start_pending(app, orchestrator);
                },
                Err(e) => *error = Some(e.message().to_string()),
            },
            // Esc 返回上一级（预设源列表）
            KeyCode::Esc => open_mirror_popup(app),
            _ => {},
        },
        Popup::MirrorFailedDialog {
            reason: _,
            ref mut selected,
        } => match key.code {
            KeyCode::Up | KeyCode::Char('k') => *selected = selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                *selected = selected.saturating_add(1).min(2);
            },
            KeyCode::Enter => match *selected {
                // 重试（沿用当前源）
                0 => {
                    app.popup = None;
                    start_pending(app, orchestrator);
                },
                // 更换源
                1 => {
                    app.popup = None;
                    begin_or_ask_mirror(app, terminal, orchestrator);
                },
                // 取消执行（未做任何修改）
                _ => {
                    app.popup = None;
                    app.pending = None;
                    app.status = crate::i18n::tr("mirror_abort_hint").into();
                },
            },
            KeyCode::Esc => {
                app.popup = None;
                app.pending = None;
                app.status = crate::i18n::tr("mirror_abort_hint").into();
            },
            _ => {},
        },
        Popup::SshKeyUsername { ref mut value } => match key.code {
            KeyCode::Char(c) => value.push(c),
            KeyCode::Backspace => {
                value.pop();
            },
            KeyCode::Enter if !value.is_empty() => {
                let username = value.clone();
                app.popup = Some(Popup::SshKeyAction {
                    username,
                    selected: 0,
                });
            },
            KeyCode::Esc => app.popup = None,
            _ => {},
        },
        Popup::SshKeyUserSelect {
            ref users,
            ref mut selected,
        } => match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                *selected = selected.saturating_sub(1);
            },
            KeyCode::Down | KeyCode::Char('j') => {
                *selected = selected
                    .saturating_add(1)
                    .min(users.len().saturating_sub(1));
            },
            KeyCode::Enter => {
                let username = users[*selected].clone();
                app.popup = Some(Popup::SshKeyAction {
                    username,
                    selected: 0,
                });
            },
            KeyCode::Esc => app.popup = None,
            _ => {},
        },
        Popup::SshKeyAction {
            ref username,
            ref mut selected,
        } => match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                *selected = selected.saturating_sub(1);
            },
            KeyCode::Down | KeyCode::Char('j') => {
                *selected = selected.saturating_add(1).min(2);
            },
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
                        queue_single_run(
                            app,
                            StepKind::SshKeySetup,
                            ExecuteParams {
                                ssh_key_username: Some(u),
                                ssh_key_action: Some(SshKeyAction::GenerateNew),
                                ..Default::default()
                            },
                            orchestrator,
                        );
                    }
                },
                1 => {
                    let u = username.clone();
                    app.popup = Some(Popup::SshKeyPaste {
                        username: u,
                        value: String::new(),
                    });
                },
                _ => {
                    app.popup = None;
                },
            },
            KeyCode::Esc => app.popup = None,
            _ => {},
        },
        Popup::SshKeyPaste {
            ref username,
            ref mut value,
        } => match key.code {
            KeyCode::Char(c) => value.push(c),
            KeyCode::Backspace => {
                value.pop();
            },
            KeyCode::Enter if !value.is_empty() => {
                let u = username.clone();
                let pk = value.clone();
                app.popup = None;
                queue_single_run(
                    app,
                    StepKind::SshKeySetup,
                    ExecuteParams {
                        ssh_key_username: Some(u),
                        ssh_key_action: Some(SshKeyAction::PasteKey(pk)),
                        ..Default::default()
                    },
                    orchestrator,
                );
            },
            KeyCode::Esc => {
                let u = username.clone();
                app.popup = Some(Popup::SshKeyAction {
                    username: u,
                    selected: 0,
                });
            },
            _ => {},
        },
        Popup::SshKeyOverwrite {
            ref username,
            ref mut selected,
        } => match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                *selected = 0;
            },
            KeyCode::Down | KeyCode::Char('j') => {
                *selected = 1;
            },
            KeyCode::Enter => match *selected {
                0 => {
                    let u = username.clone();
                    app.popup = None;
                    // 先删旧密钥再重建（删除动作随后由步骤重新注册回滚）
                    let home = system::home_dir(&u);
                    for f in ["id_ed25519", "id_ed25519.pub"] {
                        let p = format!("{}/.ssh/{}", home, f);
                        let _ = std::fs::remove_file(&p);
                    }
                    queue_single_run(
                        app,
                        StepKind::SshKeySetup,
                        ExecuteParams {
                            ssh_key_username: Some(u),
                            ssh_key_action: Some(SshKeyAction::GenerateNew),
                            ..Default::default()
                        },
                        orchestrator,
                    );
                },
                _ => {
                    let u = username.clone();
                    app.popup = Some(Popup::SshKeyAction {
                        username: u,
                        selected: 0,
                    });
                },
            },
            KeyCode::Esc => {
                let u = username.clone();
                app.popup = Some(Popup::SshKeyAction {
                    username: u,
                    selected: 0,
                });
            },
            _ => {},
        },
        // ── 创建用户 ──
        Popup::CreateUserUsername { ref mut value } => match key.code {
            KeyCode::Char(c) if c.is_alphanumeric() || c == '-' || c == '_' => {
                if value.len() < 32 {
                    value.push(c);
                }
            },
            KeyCode::Backspace => {
                value.pop();
            },
            KeyCode::Enter if !value.is_empty() => {
                let username = value.clone();
                app.popup = Some(Popup::CreateUserLockPw {
                    username,
                    lock: true,
                });
            },
            KeyCode::Esc => app.popup = None,
            _ => {},
        },
        Popup::CreateUserLockPw {
            ref username,
            ref mut lock,
        } => match key.code {
            KeyCode::Up | KeyCode::Char('k') => *lock = true,
            KeyCode::Down | KeyCode::Char('j') => *lock = false,
            KeyCode::Enter => {
                let username = username.clone();
                let lock_password = *lock;
                app.popup = None;
                queue_single_run(
                    app,
                    StepKind::UserCreation,
                    ExecuteParams {
                        new_username: Some(username.clone()),
                        lock_password,
                        ssh_key_username: Some(username),
                        ssh_key_action: Some(SshKeyAction::GenerateNew),
                        ..Default::default()
                    },
                    orchestrator,
                );
            },
            KeyCode::Esc => {
                let u = username.clone();
                app.popup = Some(Popup::CreateUserUsername { value: u });
            },
            _ => {},
        },
        // ── SSH 端口 ──
        Popup::SshPortInput { ref mut value } => match key.code {
            KeyCode::Char(c) if c.is_ascii_digit() => {
                if value.len() < 5 {
                    value.push(c);
                }
            },
            KeyCode::Backspace => {
                value.pop();
            },
            KeyCode::Enter if !value.is_empty() => {
                if let Ok(port) = value.parse::<u16>()
                    && port > 0
                {
                    app.popup = None;
                    queue_single_run(
                        app,
                        StepKind::SshPortChange,
                        ExecuteParams {
                            new_ssh_port: Some(port),
                            ..Default::default()
                        },
                        orchestrator,
                    );
                }
            },
            KeyCode::Esc => app.popup = None,
            _ => {},
        },
    }

    terminal.draw(|f| render(f, app))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 执行启动
// ---------------------------------------------------------------------------

/// 需要询问临时软件源时先弹窗，否则直接启动
fn begin_or_ask_mirror(
    app: &mut TuiApp,
    terminal: &mut TuiTerminal,
    orchestrator: &HardeningOrchestrator,
) {
    let needs_mirror = app
        .pending
        .as_ref()
        .is_some_and(|p| p.selected.iter().any(|s| s.touches_package_manager()));

    if !needs_mirror {
        start_pending(app, orchestrator);
        return;
    }

    // 探测延迟期间先给出提示，避免看起来卡住
    app.status = crate::i18n::tr("tui_mirror_probing").into();
    let _ = terminal.draw(|f| render(f, app));
    open_mirror_popup(app);
    app.status.clear();
}

/// 打开镜像源选择弹窗（默认选中上次使用的镜像）
fn open_mirror_popup(app: &mut TuiApp) {
    let items = mirror_items();
    let selected = PackageMirror::all()
        .iter()
        .position(|m| *m == app.mirror)
        .unwrap_or(0);
    app.popup = Some(Popup::MirrorSelect { items, selected });
}

/// 镜像选项（含延迟）
fn mirror_items() -> Vec<String> {
    let mut items: Vec<String> = PackageMirror::all()
        .iter()
        .map(|mirror| match mirror.probe_host() {
            None => mirror.label(),
            Some(_) => match package_mirror::probe_latency(mirror) {
                Some(latency) => format!(
                    "{} ({}{}ms)",
                    mirror.label(),
                    crate::i18n::tr("mirror_latency_prefix"),
                    latency.as_millis()
                ),
                None => format!(
                    "{} ({})",
                    mirror.label(),
                    crate::i18n::tr("mirror_unreachable")
                ),
            },
        })
        .collect();
    items.push(crate::i18n::tr("mirror_custom_entry").to_string());
    items
}

/// 单项执行：直接排队并启动（若涉及包管理器则先询问镜像源）
fn queue_single_run(
    app: &mut TuiApp,
    kind: StepKind,
    params: ExecuteParams,
    orchestrator: &HardeningOrchestrator,
) {
    app.pending = Some(PendingRun {
        selected: vec![kind],
        params,
    });
    if kind.touches_package_manager() {
        open_mirror_popup(app);
        app.status.clear();
    } else {
        start_pending(app, orchestrator);
    }
}

/// 启动排队中的运行（后台线程）
fn start_pending(app: &mut TuiApp, orchestrator: &HardeningOrchestrator) {
    // 保留 pending：源连接失败后用户可能重试或更换源
    let Some(pending) = app.pending.clone() else {
        return;
    };

    app.logs.clear();
    app.results.clear();
    app.live_tail.clear();
    app.summary_scroll = 0;
    app.progress = (0, pending.selected.len());
    for step in &mut app.steps {
        step.state = StepExecState::Idle;
    }
    app.current = None;
    app.mode = AppMode::Executing;
    app.status.clear();

    let runner = StepRunner::new(orchestrator.logger()).with_mirror(app.mirror.clone());
    app.job = Some(runner.spawn(pending.selected, pending.params));
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
    StepKind::all()
        .iter()
        .map(|kind| StepItem {
            kind: *kind,
            // 可选步骤（9/10/11）默认不勾选，其余默认勾选未安全配置的项
            checked: kind.default_checked(report),
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
    let title_text = crate::i18n::tr("tui_title");
    let title = Line::from(vec![
        Span::styled(
            format!(" U2Secure v{} ", version),
            Style::default().fg(Color::White).bg(Color::Blue),
        ),
        Span::styled(
            format!(" — {} ", title_text),
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
        .title(format!(" {} ", crate::i18n::tr("tui_audit_report")))
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
        .title(format!(
            " {} ",
            crate::i18n::tr("tui_steps_title").replace("{n}", &app.steps.len().to_string())
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let items: Vec<ListItem> = app
        .steps
        .iter()
        .map(|step| {
            let status_icon = step.kind.check_default_status(&app.report).icon();
            let checkbox = if step.checked { "[✓]" } else { "[ ]" };
            let opt_in = if step.kind.is_opt_in() {
                crate::i18n::tr("step_opt_in_tag")
            } else {
                ""
            };
            let label = step.kind.label();

            // 根据执行状态调整样式
            let (prefix, style) = match step.state {
                StepExecState::Running => ("▶ ", Style::default().fg(Color::Cyan).bold()),
                StepExecState::Success => ("✓ ", Style::default().fg(Color::Green)),
                StepExecState::Failure => ("✗ ", Style::default().fg(Color::Red)),
                StepExecState::Idle => ("  ", Style::default()),
            };

            let content = format!(
                " {} {} {} {} {}",
                prefix, checkbox, label, opt_in, status_icon
            );
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
        .title(format!(" {} ", crate::i18n::tr("tui_help_title")))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let selected_count = app.steps.iter().filter(|s| s.checked).count();

    let mut lines = vec![
        Line::from(vec![Span::raw("")]),
        Line::from(vec![
            Span::styled("  ↑↓/jk", Style::default().bold()),
            Span::raw(format!("  {}", crate::i18n::tr("tui_help_move"))),
        ]),
        Line::from(vec![
            Span::styled(" Space", Style::default().bold()),
            Span::raw(format!("  {}", crate::i18n::tr("tui_help_toggle"))),
        ]),
        Line::from(vec![
            Span::styled(" a", Style::default().bold()),
            Span::raw(format!("  {}", crate::i18n::tr("tui_help_all"))),
        ]),
        Line::from(vec![
            Span::styled(" Enter", Style::default().bold()),
            Span::raw(format!("  {}", crate::i18n::tr("tui_help_batch"))),
        ]),
        Line::from(vec![
            Span::styled(" e", Style::default().bold()),
            Span::raw(format!("  {}", crate::i18n::tr("tui_help_single"))),
        ]),
        Line::from(vec![
            Span::styled(" r", Style::default().bold()),
            Span::raw(format!("  {}", crate::i18n::tr("tui_help_reauth"))),
        ]),
        Line::from(vec![
            Span::styled(" q", Style::default().bold()),
            Span::raw(format!("  {}", crate::i18n::tr("tui_help_quit"))),
        ]),
        Line::from(vec![Span::raw("")]),
        Line::from(vec![Span::styled(
            crate::i18n::tr("tui_selected_count").replace("{n}", &selected_count.to_string()),
            Style::default().fg(Color::Cyan),
        )]),
        Line::from(vec![Span::styled(
            crate::i18n::tr("tui_opt_in_hint"),
            Style::default().dim(),
        )]),
        Line::from(vec![Span::styled(
            crate::i18n::tr("tui_single_hint"),
            Style::default().dim(),
        )]),
    ];

    if !app.status.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            format!(" {} ", app.status),
            Style::default().fg(Color::Yellow),
        )]));
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// 执行中：当前步骤 + 耗时 + 实时输出 + 进度条
fn render_right_executing(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    let block = Block::default()
        .title(format!(" {} ", crate::i18n::tr("tui_exec_title")))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // 上：状态头；中：日志；下：进度条
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);

    // ── 状态头 ──
    let elapsed = app
        .job
        .as_ref()
        .map(|job| job.started_at.elapsed())
        .unwrap_or_default();
    let spin = SPINNER[(elapsed.as_millis() / 120) as usize % SPINNER.len()];

    let (index, total) = app.progress;
    let headline = match &app.current {
        Some(current) => crate::i18n::tr("tui_exec_running")
            .replace("{step}", current.kind.label())
            .to_string(),
        None => crate::i18n::tr("tui_exec_preparing").to_string(),
    };
    let mut header_lines = vec![
        Line::from(vec![
            Span::styled(format!(" {spin} "), Style::default().fg(Color::Cyan).bold()),
            Span::styled(headline, Style::default().bold()),
        ]),
        Line::from(vec![
            Span::styled(
                format!("   {} ", crate::i18n::tr("tui_exec_progress")),
                Style::default().dim(),
            ),
            Span::styled(
                format!("{}/{}", index + 1, total),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                format!(
                    "   {} {}",
                    crate::i18n::tr("tui_exec_elapsed"),
                    format_duration(elapsed)
                ),
                Style::default().dim(),
            ),
        ]),
        Line::from(vec![Span::styled(
            format!("   {}", crate::i18n::tr("tui_exec_cancel_hint")),
            Style::default().fg(Color::Yellow),
        )]),
    ];
    if !app.status.is_empty() {
        header_lines.push(Line::from(vec![Span::styled(
            format!("   {}", app.status),
            Style::default().fg(Color::Yellow),
        )]));
    }
    frame.render_widget(Paragraph::new(Text::from(header_lines)), chunks[0]);

    // ── 日志 + 实时输出 ──
    let mut lines: Vec<Line> = app
        .logs
        .iter()
        .rev()
        .take(LOG_PANEL_LINES)
        .rev()
        .map(|entry| {
            let icon_style = match entry.icon {
                "▶" => Style::default().fg(Color::Cyan),
                "✅" => Style::default().fg(Color::Green),
                "❌" => Style::default().fg(Color::Red),
                "⚠️" => Style::default().fg(Color::Yellow),
                "⏭" => Style::default().fg(Color::Yellow),
                _ => Style::default().dim(),
            };
            Line::from(vec![
                Span::styled(format!(" {} ", entry.icon), icon_style),
                Span::styled(entry.message.clone(), Style::default()),
            ])
        })
        .collect();

    if !app.live_tail.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            format!(" {} ", crate::i18n::tr("tui_exec_live_output")),
            Style::default().fg(Color::DarkGray),
        )]));
        for line in &app.live_tail {
            lines.push(Line::from(vec![Span::styled(
                format!("   {line}"),
                Style::default().fg(Color::DarkGray),
            )]));
        }
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
        chunks[1],
    );

    // ── 进度条 ──
    let ratio = if total > 0 {
        (index as f64 / total as f64).min(1.0)
    } else {
        0.0
    };
    let gauge = Gauge::default()
        .ratio(ratio)
        .label(format!(" {}/{} ", index, total))
        .style(Style::default().fg(Color::Cyan))
        .gauge_style(Style::default().bg(Color::DarkGray).fg(Color::Green));
    frame.render_widget(gauge, chunks[2]);
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

/// 摘要模式：执行结果
fn render_right_summary(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    let block = Block::default()
        .title(format!(" {} ", crate::i18n::tr("tui_result_title")))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let changed = app
        .results
        .iter()
        .filter(|r| r.outcome == StepOutcome::Changed)
        .count();
    let skipped = app
        .results
        .iter()
        .filter(|r| r.outcome == StepOutcome::Skipped)
        .count();
    let failed = app
        .results
        .iter()
        .filter(|r| r.outcome == StepOutcome::Failed)
        .count();

    let mut lines = vec![Line::from(vec![Span::raw("")])];

    for result in &app.results {
        let fg = match result.outcome {
            StepOutcome::Changed => Color::Green,
            StepOutcome::Skipped => Color::Yellow,
            StepOutcome::Failed => Color::Red,
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", result.outcome.icon()),
                Style::default().fg(fg),
            ),
            Span::styled(result.kind.label(), Style::default().bold()),
            Span::styled(
                format!(" [{}]", result.outcome.label()),
                Style::default().fg(fg),
            ),
        ]));
        for line in result.message.lines() {
            lines.push(Line::from(vec![Span::styled(
                format!("     {line}"),
                Style::default().dim(),
            )]));
        }
        for artifact in &result.artifacts {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("     {} ", crate::i18n::tr("tui_result_artifact")),
                    Style::default().dim(),
                ),
                Span::styled(artifact.clone(), Style::default().fg(Color::DarkGray)),
            ]));
        }
    }

    lines.push(Line::from(vec![Span::raw("")]));
    let stats = crate::i18n::tr("tui_result_summary")
        .replace("{ok}", &changed.to_string())
        .replace("{skip}", &skipped.to_string())
        .replace("{fail}", &failed.to_string());
    lines.push(Line::from(vec![Span::styled(
        stats,
        Style::default().bold(),
    )]));
    lines.push(Line::from(vec![Span::styled(
        format!(
            " {} {}",
            crate::i18n::tr("tui_result_report_dir"),
            artifacts::dir_display()
        ),
        Style::default().fg(Color::Cyan),
    )]));
    lines.push(Line::from(vec![Span::styled(
        format!(
            " {} {}",
            crate::i18n::tr("tui_result_view"),
            artifacts::dir_display()
        ),
        Style::default().dim(),
    )]));
    lines.push(Line::from(vec![Span::raw("")]));
    lines.push(Line::from(vec![Span::styled(
        crate::i18n::tr("tui_result_return"),
        Style::default().dim(),
    )]));

    let text = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.summary_scroll, 0));

    frame.render_widget(text, area);
}

// ---------------------------------------------------------------------------
// 底部快捷键栏
// ---------------------------------------------------------------------------

fn render_footer(frame: &mut Frame, area: ratatui::layout::Rect, app: &TuiApp) {
    let (text, style) = match app.mode {
        AppMode::Select => (
            crate::i18n::tr("tui_footer_select"),
            Style::default().fg(Color::White).bg(Color::Rgb(30, 30, 50)),
        ),
        AppMode::Executing => (
            crate::i18n::tr("tui_footer_exec"),
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::Rgb(40, 20, 20)),
        ),
        AppMode::Summary => (
            crate::i18n::tr("tui_footer_summary"),
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
        Popup::MirrorSelect { items, selected } => (
            format!(" {} ", crate::i18n::tr("tui_mirror_title")),
            (items.len() + 5).clamp(6, 14) as u16,
            render_mirror_options(items, *selected),
            crate::i18n::tr("tui_hint_updown_enter_esc"),
        ),
        Popup::MirrorCustomInput { value, error } => (
            format!(" {} ", crate::i18n::tr("tui_mirror_custom_title")),
            if error.is_some() { 7 } else { 6 },
            render_mirror_custom_input(value, error.as_deref()),
            crate::i18n::tr("tui_hint_enter_esc_back"),
        ),
        Popup::MirrorFailedDialog { reason, selected } => (
            format!(" {} ", crate::i18n::tr("tui_mirror_failed_title")),
            9,
            render_mirror_failed(reason, *selected),
            crate::i18n::tr("tui_hint_updown_enter_esc"),
        ),
        Popup::SshKeyUsername { value } => (
            format!(" {} ", crate::i18n::tr("tui_popup_username")),
            5,
            render_username_input(value),
            crate::i18n::tr("tui_hint_enter_esc"),
        ),
        Popup::SshKeyUserSelect { users, selected } => (
            format!(" {} ", crate::i18n::tr("tui_popup_select_user")),
            (users.len() + 4).clamp(5, 16) as u16,
            render_string_list(users, *selected),
            crate::i18n::tr("tui_hint_updown_enter_esc"),
        ),
        Popup::SshKeyAction { selected, .. } => (
            format!(" {} ", crate::i18n::tr("tui_popup_select_action")),
            7,
            render_select_options(
                &[
                    crate::i18n::tr("tui_popup_gen_key"),
                    crate::i18n::tr("tui_popup_paste_key"),
                    crate::i18n::tr("tui_popup_skip"),
                ],
                *selected,
            ),
            crate::i18n::tr("tui_hint_updown_enter_esc"),
        ),
        Popup::SshKeyPaste { value, .. } => (
            format!(" {} ", crate::i18n::tr("tui_popup_paste_title")),
            5,
            render_pubkey_input(value),
            crate::i18n::tr("tui_hint_enter_esc_back"),
        ),
        Popup::SshKeyOverwrite { selected, .. } => (
            format!(" {} ", crate::i18n::tr("tui_popup_overwrite_title")),
            7,
            render_select_options(
                &[
                    crate::i18n::tr("tui_popup_overwrite_yes"),
                    crate::i18n::tr("tui_popup_overwrite_no"),
                ],
                *selected,
            ),
            crate::i18n::tr("tui_hint_updown_enter_esc_back"),
        ),
        Popup::CreateUserUsername { value } => (
            format!(" {} ", crate::i18n::tr("tui_popup_new_user")),
            5,
            render_username_input(value),
            crate::i18n::tr("tui_hint_enter_esc"),
        ),
        Popup::CreateUserLockPw { lock, .. } => (
            format!(" {} ", crate::i18n::tr("tui_popup_lock_title")),
            7,
            render_select_options(
                &[
                    crate::i18n::tr("tui_popup_lock_yes"),
                    crate::i18n::tr("tui_popup_lock_no"),
                ],
                if *lock { 0 } else { 1 },
            ),
            crate::i18n::tr("tui_hint_updown_enter_esc_back"),
        ),
        Popup::SshPortInput { value } => (
            format!(" {} ", crate::i18n::tr("tui_popup_port_title")),
            5,
            render_port_input(value),
            crate::i18n::tr("tui_hint_enter_esc"),
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

/// 镜像选项列表（含延迟说明）
fn render_mirror_options(items: &[String], selected: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![Span::styled(
        format!("  {}", crate::i18n::tr("tui_mirror_hint")),
        Style::default().dim(),
    )])];
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

/// 自定义软件源输入框
fn render_mirror_custom_input(value: &str, error: Option<&str>) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![Span::styled(
        format!("  {}", crate::i18n::tr("tui_mirror_custom_hint")),
        Style::default().dim(),
    )])];
    if value.is_empty() {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                crate::i18n::tr("tui_mirror_custom_placeholder"),
                Style::default().dim().fg(Color::Gray),
            ),
            Span::styled("█", Style::default().fg(Color::Cyan)),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(value.to_string(), Style::default().fg(Color::White)),
            Span::styled("█", Style::default().fg(Color::Cyan)),
        ]));
    }
    if let Some(error) = error {
        lines.push(Line::from(vec![Span::styled(
            format!("  {error}"),
            Style::default().fg(Color::Red),
        )]));
    }
    lines
}

/// 软件源连接失败对话框
fn render_mirror_failed(reason: &str, selected: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![Span::styled(
        format!("  {reason}"),
        Style::default().fg(Color::Red),
    )])];
    lines.extend(render_select_options(
        &crate::presentation::mirror_failure_options(),
        selected,
    ));
    lines
}

/// 用户名输入框内容
fn render_username_input(value: &str) -> Vec<Line<'static>> {
    if value.is_empty() {
        vec![
            Line::from(vec![Span::raw("")]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    crate::i18n::tr("tui_popup_enter_user"),
                    Style::default().dim().fg(Color::Gray),
                ),
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

/// 公钥粘贴框内容（按 char 边界截断，避免多字节 panic）
fn render_pubkey_input(value: &str) -> Vec<Line<'static>> {
    if value.is_empty() {
        vec![
            Line::from(vec![Span::raw("")]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    crate::i18n::tr("tui_popup_paste_hint"),
                    Style::default().dim().fg(Color::Gray),
                ),
                Span::styled("█", Style::default().fg(Color::Cyan)),
            ]),
        ]
    } else {
        let mut display: String = value.chars().take(50).collect();
        if value.chars().count() > 50 {
            display.push_str("...");
        }
        display.push('█');
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
                Span::raw("  "),
                Span::styled(
                    crate::i18n::tr("tui_popup_port_suggest")
                        .replace("{port}", &system::random_suggested_port().to_string()),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    crate::i18n::tr("tui_popup_port_current")
                        .replace("{port}", &current_port.to_string()),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    crate::i18n::tr("tui_popup_port_placeholder"),
                    Style::default().dim().fg(Color::Gray),
                ),
                Span::styled("█", Style::default().fg(Color::Cyan)),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![Span::raw("")]),
            Line::from(vec![
                Span::raw("  port: "),
                Span::styled(value.to_string(), Style::default().fg(Color::White)),
                Span::styled("█", Style::default().fg(Color::Cyan)),
            ]),
        ]
    }
}
