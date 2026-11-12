//! CIDR allow-list for incoming peers.
//!
//! An empty list allows everyone (the historical behaviour). A non-empty list
//! only accepts peers whose address matches one of the parsed ranges. Invalid
//! entries make the list fail closed: the configuration is rejected by the
//! tray/CLI, and a hand-edited settings file refuses all connections so a typo
//! cannot silently widen access.

use std::net::IpAddr;

#[derive(Clone, Debug, Default)]
pub struct Acl {
    raw: String,
    rules: Vec<Cidr>,
    invalid: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cidr {
    net: IpAddr,
    prefix: u8,
}

/// Validates a list before saving it from the tray or CLI.
pub fn check(raw: &str) -> Result<(), String> {
    Acl::check(raw)
}

impl Acl {
    /// Parses a comma/space separated list. Invalid tokens are recorded so the
    /// caller can reject the configuration.
    pub fn parse(raw: &str) -> Self {
        let mut rules = Vec::new();
        let mut invalid = Vec::new();
        for token in raw.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            if token.is_empty() {
                continue;
            }
            match Cidr::parse(token) {
                Ok(rule) => rules.push(rule),
                Err(_) => invalid.push(token.to_string()),
            }
        }
        Acl {
            raw: raw.to_string(),
            rules,
            invalid,
        }
    }

    /// Validates a list before saving it from the tray or CLI.
    pub fn check(raw: &str) -> Result<(), String> {
        if raw.trim().is_empty() {
            return Ok(());
        }
        let acl = Self::parse(raw);
        if !acl.invalid.is_empty() {
            return Err(format!(
                "invalid CIDR entr{}: {}",
                if acl.invalid.len() == 1 { "y" } else { "ies" },
                acl.invalid.join(", ")
            ));
        }
        if acl.rules.is_empty() {
            return Err("no valid CIDR entries".to_string());
        }
        Ok(())
    }

    /// True when `ip` is allowed. Empty ACL = allow all; a malformed ACL fails
    /// closed (deny all) even if some entries parsed successfully.
    pub fn allows(&self, ip: IpAddr) -> bool {
        if self.raw.trim().is_empty() {
            return true;
        }
        if !self.invalid.is_empty() {
            return false;
        }
        let ip = normalize(ip);
        self.rules.iter().any(|rule| rule.contains(ip))
    }

    pub fn is_empty(&self) -> bool {
        self.raw.trim().is_empty()
    }

    pub fn invalid_entries(&self) -> &[String] {
        &self.invalid
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

impl Cidr {
    fn parse(token: &str) -> Result<Self, String> {
        let (addr, prefix) = match token.split_once('/') {
            Some((addr, prefix)) => {
                let prefix = prefix
                    .parse::<u8>()
                    .map_err(|_| format!("invalid prefix in {token}"))?;
                (addr, Some(prefix))
            }
            None => (token, None),
        };
        let parsed: IpAddr = addr
            .parse()
            .map_err(|_| format!("invalid address in {token}"))?;

        // An IPv4-mapped IPv6 CIDR (::ffff:192.168.1.0/120) is expressed in
        // IPv6 bits; translate it to the corresponding IPv4 prefix so it can
        // match plain IPv4 peers.
        let (net, prefix) = match parsed {
            IpAddr::V4(v4) => (IpAddr::V4(v4), prefix.unwrap_or(32)),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => {
                    let p = prefix.unwrap_or(32).saturating_sub(96);
                    (IpAddr::V4(v4), p)
                }
                None => (IpAddr::V6(v6), prefix.unwrap_or(128)),
            },
        };
        let max = match net {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(format!("prefix /{prefix} is too large for {token}"));
        }
        Ok(Cidr { net, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// Treat IPv4-mapped IPv6 peers as IPv4 so a `192.168.1.0/24` rule also works
/// on dual-stack sockets.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_list_allows_everyone() {
        assert!(Acl::parse("").allows(ip("203.0.113.7")));
        assert!(Acl::parse("   ").allows(ip("2001:db8::1")));
    }

    #[test]
    fn ipv4_cidr_and_bare_host() {
        let acl = Acl::parse("192.168.1.0/24");
        assert!(acl.allows(ip("192.168.1.1")));
        assert!(acl.allows(ip("192.168.1.255")));
        assert!(!acl.allows(ip("192.168.2.1")));

        let host = Acl::parse("10.1.2.3");
        assert!(host.allows(ip("10.1.2.3")));
        assert!(!host.allows(ip("10.1.2.4")));
    }

    #[test]
    fn ipv6_cidr_and_bare_host() {
        let acl = Acl::parse("2001:db8::/32");
        assert!(acl.allows(ip("2001:db8::1")));
        assert!(acl.allows(ip("2001:db8:ffff::1")));
        assert!(!acl.allows(ip("2001:db9::1")));

        let host = Acl::parse("::1");
        assert!(host.allows(ip("::1")));
        assert!(!host.allows(ip("::2")));
    }

    #[test]
    fn ipv4_mapped_peers_match_ipv4_rules() {
        let acl = Acl::parse("192.168.1.0/24");
        assert!(acl.allows(ip("::ffff:192.168.1.5")));

        let v6 = Acl::parse("::ffff:192.168.1.0/120");
        assert!(v6.allows(ip("192.168.1.5")));
    }

    #[test]
    fn multiple_entries_and_separators() {
        let acl = Acl::parse("10.0.0.0/8, 192.168.0.0/16; 172.16.1.5");
        assert!(acl.allows(ip("10.2.3.4")));
        assert!(acl.allows(ip("192.168.9.9")));
        assert!(acl.allows(ip("172.16.1.5")));
        assert!(!acl.allows(ip("8.8.8.8")));
    }

    #[test]
    fn invalid_entries_fail_closed() {
        let acl = Acl::parse("10.0.0.0/8, not-a-cidr");
        assert!(!acl.allows(ip("10.2.3.4")));
        assert_eq!(acl.invalid_entries(), ["not-a-cidr"]);
    }

    #[test]
    fn check_reports_bad_configuration() {
        assert!(Acl::check("").is_ok());
        assert!(Acl::check("10.0.0.0/8, 192.168.0.0/16").is_ok());
        assert!(Acl::check("10.0.0.0/33").is_err());
        assert!(Acl::check("wat").is_err());
        assert!(Acl::check(",,, ; ").is_err());
    }
}
