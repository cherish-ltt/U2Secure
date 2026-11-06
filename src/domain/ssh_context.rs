use std::net::IpAddr;

use super::errors::DomainError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshContext {
    user: String,
    addr: IpAddr,
    host: String,
    laddr: IpAddr,
    lport: u16,
}

impl SshContext {
    pub fn parse(
        user: &str,
        addr: &str,
        host: &str,
        laddr: &str,
        lport: &str,
    ) -> Result<Self, DomainError> {
        if user.is_empty()
            || user.len() > 256
            || !user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-.@$".contains(&byte))
        {
            return Err(invalid("user"));
        }
        let addr = addr.parse().map_err(|_| invalid("addr"))?;
        if !valid_host(host) {
            return Err(invalid("host"));
        }
        let laddr = laddr.parse().map_err(|_| invalid("laddr"))?;
        let lport = lport
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| invalid("lport"))?;
        Ok(Self {
            user: user.into(),
            addr,
            host: host.into(),
            laddr,
            lport,
        })
    }

    pub fn connection_spec(&self) -> String {
        format!(
            "user={},addr={},host={},laddr={},lport={}",
            self.user, self.addr, self.host, self.laddr, self.lport
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SshAuthentication {
    pub password_authentication: String,
    pub kbd_interactive_authentication: String,
    pub permit_root_login: String,
}

impl SshAuthentication {
    pub fn matches_baseline(&self) -> bool {
        self.password_authentication == "no"
            && self.kbd_interactive_authentication == "no"
            && matches!(
                self.permit_root_login.as_str(),
                "no" | "prohibit-password" | "without-password"
            )
    }
}

fn valid_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host
            .strip_suffix('.')
            .unwrap_or(host)
            .split('.')
            .all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
            })
}

fn invalid(field: &str) -> DomainError {
    DomainError::ParseError(crate::i18n::tr("ssh_context_invalid").replace("{field}", field))
}
