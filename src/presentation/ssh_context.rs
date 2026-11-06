use dialoguer::{Confirm, Input};

use crate::domain::errors::DomainError;
use crate::domain::ssh_context::{SshAuthentication, SshContext};
use crate::i18n::tr;

pub(crate) fn interactive(
    query: impl FnOnce(&SshContext) -> Result<SshAuthentication, DomainError>,
) -> String {
    println!(
        "{}\n{}",
        tr("ssh_context_title"),
        tr("ssh_context_input_hint")
    );
    run_with(
        |key| {
            Input::<String>::new()
                .with_prompt(tr(key))
                .allow_empty(true)
                .interact_text()
                .map_err(|error| DomainError::SystemCommandFailed(error.to_string()))
        },
        |context| {
            println!("{}\n{}", context.connection_spec(), tr("ssh_context_scope"));
            Confirm::new()
                .with_prompt(tr("ssh_context_confirm"))
                .default(false)
                .interact()
                .map_err(|error| DomainError::SystemCommandFailed(error.to_string()))
        },
        query,
    )
}

fn run_with(
    read: impl FnMut(&'static str) -> Result<String, DomainError>,
    confirm: impl FnOnce(&SshContext) -> Result<bool, DomainError>,
    query: impl FnOnce(&SshContext) -> Result<SshAuthentication, DomainError>,
) -> String {
    let context = match collect_with(read) {
        Ok(Some(context)) => context,
        Ok(None) => return tr("ssh_context_cancelled").into(),
        Err(error) => return failure(&error),
    };
    match confirm(&context) {
        Ok(true) => render(&context, query(&context)),
        Ok(false) => tr("ssh_context_cancelled").into(),
        Err(error) => failure(&error),
    }
}

fn collect_with(
    mut read: impl FnMut(&'static str) -> Result<String, DomainError>,
) -> Result<Option<SshContext>, DomainError> {
    let mut values = Vec::with_capacity(5);
    for key in [
        "ssh_context_user",
        "ssh_context_addr",
        "ssh_context_host",
        "ssh_context_laddr",
        "ssh_context_lport",
    ] {
        let value = read(key)?;
        if value.trim().is_empty() {
            return Ok(None);
        }
        values.push(value);
    }
    SshContext::parse(&values[0], &values[1], &values[2], &values[3], &values[4]).map(Some)
}

pub(crate) fn render(
    context: &SshContext,
    result: Result<SshAuthentication, DomainError>,
) -> String {
    let detail = match result {
        Ok(auth) => format!(
            "{}\nPasswordAuthentication: {}\nKbdInteractiveAuthentication: {}\nPermitRootLogin: {}\n{}",
            tr("ssh_context_read"),
            auth.password_authentication,
            auth.kbd_interactive_authentication,
            auth.permit_root_login,
            tr(if auth.matches_baseline() {
                "ssh_context_baseline_matches"
            } else {
                "ssh_context_baseline_differs"
            }),
        ),
        Err(error) => failure(&error),
    };
    format!(
        "{}\n{}\n\n{}\n\n{}",
        tr("ssh_context_title"),
        context.connection_spec(),
        detail,
        tr("ssh_context_scope"),
    )
}

fn failure(error: &impl std::fmt::Display) -> String {
    let reason: String = error
        .to_string()
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .collect();
    tr("ssh_context_failed").replace("{reason}", &reason)
}

#[cfg(test)]
#[path = "ssh_context_tests.rs"]
mod tests;
