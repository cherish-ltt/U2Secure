use crate::application::job::execution_plan;
use crate::domain::mirror::PackageMirror;
use crate::domain::steps::{ExecuteParams, SshKeyAction, StepKind};
use crate::i18n::tr;

#[derive(Clone)]
pub(super) struct RunPlan {
    pub selected: Vec<StepKind>,
    pub params: ExecuteParams,
    pub mirror: PackageMirror,
}

impl RunPlan {
    pub fn new(selected: &[StepKind], params: ExecuteParams, mirror: PackageMirror) -> Self {
        Self {
            selected: execution_plan(selected),
            params,
            mirror,
        }
    }

    pub fn lines(&self) -> Vec<String> {
        let mut lines: Vec<_> = self
            .selected
            .iter()
            .enumerate()
            .map(|(index, kind)| format!("{}. {}", index + 1, kind.label()))
            .collect();
        lines.push(String::new());

        if self.selected.contains(&StepKind::UserCreation) {
            lines.push(
                tr("plan_new_user").replace(
                    "{user}",
                    self.params
                        .new_username
                        .as_deref()
                        .unwrap_or(tr("plan_unset")),
                ),
            );
            lines.push(
                tr(if self.params.lock_password {
                    "plan_user_locked"
                } else {
                    "plan_user_unlocked"
                })
                .into(),
            );
            lines.push(tr("plan_user_key").into());
        }
        if self.selected.contains(&StepKind::SshPortChange) {
            let port = self
                .params
                .new_ssh_port
                .map(|port| port.to_string())
                .unwrap_or_else(|| tr("plan_unset").into());
            lines.push(tr("plan_ssh_port").replace("{port}", &port));
        }
        if self.selected.contains(&StepKind::SshKeySetup) {
            let action = match &self.params.ssh_key_action {
                Some(SshKeyAction::GenerateNew) => tr("plan_key_generate"),
                Some(SshKeyAction::ReplaceExisting) => tr("plan_key_replace"),
                Some(SshKeyAction::PasteKey(_)) => tr("plan_key_paste"),
                None => tr("plan_unset"),
            };
            lines.push(
                tr("plan_ssh_key")
                    .replace(
                        "{user}",
                        self.params
                            .ssh_key_username
                            .as_deref()
                            .unwrap_or(tr("plan_unset")),
                    )
                    .replace("{action}", action),
            );
            if self.selected.contains(&StepKind::UserCreation)
                && self.params.new_username.is_some()
                && self.params.new_username == self.params.ssh_key_username
                && matches!(self.params.ssh_key_action, Some(SshKeyAction::GenerateNew))
            {
                lines.push(tr("plan_key_duplicate").into());
            }
        }
        let mirror = if self.selected.iter().any(StepKind::touches_package_manager) {
            match self.mirror.probe_host() {
                Some(host) => format!("{} ({host})", self.mirror.label()),
                None => self.mirror.label(),
            }
        } else {
            tr("plan_mirror_unused").into()
        };
        lines.push(tr("plan_mirror").replace("{mirror}", &mirror));
        if self.selected.contains(&StepKind::RestartSsh) {
            lines.push(
                tr(if self.params.apply_ssh_changes {
                    "plan_ssh_authorized"
                } else {
                    "plan_ssh_not_authorized"
                })
                .into(),
            );
        }
        if self.selected.contains(&StepKind::Ufw) {
            lines.push(tr("plan_ufw_conditional").into());
        }
        lines.push(tr("plan_conditions").into());
        lines.push(tr("plan_cancel_scope").into());
        lines
    }
}

pub(super) fn choices() -> [&'static str; 3] {
    [tr("plan_execute"), tr("plan_edit"), tr("plan_cancel")]
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
