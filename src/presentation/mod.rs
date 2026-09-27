pub mod cli;
pub mod tui;

/// 软件源连接失败后的决策项：重试 / 更换源 / 取消执行
pub fn mirror_failure_options() -> [&'static str; 3] {
    [
        crate::i18n::tr("mirror_action_retry"),
        crate::i18n::tr("mirror_action_change"),
        crate::i18n::tr("mirror_action_abort"),
    ]
}
