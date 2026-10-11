//! Source-IP allowlists (ACL) for every port this server exposes.
//!
//! Three levels exist, all of them optional and all of them enforced *before*
//! the transport handshake, so an unlisted peer costs nothing and never gets a
//! single byte of protocol reply:
//!
//! ```toml
//! [server]
//! bind_addr = "0.0.0.0:21000"
//! # 1) Control port: who may open control channels (hospital-side clients).
//! allowed_client_ips = ["203.0.113.0/24", "198.51.100.7"]
//!
//! # 2) Default for every service port (visitors): used when a service has no
//! #    `allowed_ips` of its own.
//! allowed_visitor_ips = ["10.8.0.0/16"]
//!
//! # enforce (default) drops unlisted sources, observe only logs them.
//! acl_mode = "enforce"
//!
//! [server.services.port-20005]
//! # 3) This port only: overrides the default above. Use
//! #    ["0.0.0.0/0", "::/0"] to keep one port completely open.
//! allowed_ips = ["198.51.100.7"]
//! ```
//!
//! Empty / missing lists mean "no restriction" (backward compatible). Entries
//! are single IPv4/IPv6 addresses or CIDR blocks; `::ffff:a.b.c.d` is accepted
//! as its IPv4 form. An invalid entry rejects the whole configuration at load
//! time, and if one ever reaches the runtime the list fails closed.

use std::fmt::{Debug, Formatter};
use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::error;

/// How a source that is not on the list is treated.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AclMode {
    /// Drop the connection without any reply (default).
    #[default]
    Enforce,
    /// Only log what would have been dropped, let it through.
    Observe,
}

/// Outcome of one ACL check.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AclDecision {
    /// The source is allowed (or the list is empty).
    Allow,
    /// The source is not listed: drop it.
    Deny,
    /// The source is not listed but `acl_mode = "observe"`: log and continue.
    ObserveDeny,
}

/// One parsed entry: a network plus its prefix length.
#[derive(Copy, Clone, PartialEq, Eq)]
enum IpNetSpec {
    V4 { net: u32, prefix: u8 },
    V6 { net: u128, prefix: u8 },
}

impl Debug for IpNetSpec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            IpNetSpec::V4 { net, prefix } => write!(f, "{}/{}", std::net::Ipv4Addr::from(*net), prefix),
            IpNetSpec::V6 { net, prefix } => write!(f, "{}/{}", std::net::Ipv6Addr::from(*net), prefix),
        }
    }
}

/// Collapses IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) into IPv4 so a
/// dual-stack listener matches IPv4 rules no matter how the peer is reported.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

impl IpNetSpec {
    /// Parses `"a.b.c.d"`, `"a.b.c.d/len"`, `"::1"` or `"2001:db8::/32"`.
    fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };

        let parsed: IpAddr = addr_part
            .parse()
            .map_err(|_| anyhow::anyhow!("`{}` is not a valid IP address", addr_part))?;

        // A mapped address is folded into IPv4: `::ffff:1.2.3.0/120` means
        // `1.2.3.0/24`, and prefixes below /96 have no IPv4 equivalent.
        let (ip, switched_bits) = match parsed {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => (IpAddr::V4(v4), 96u8),
                None => (IpAddr::V6(v6), 0u8),
            },
            v4 => (v4, 0u8),
        };

        let max_prefix = match ip {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        let prefix = match prefix_part {
            Some(p) => p
                .parse::<u8>()
                .map_err(|_| anyhow::anyhow!("`{}` is not a valid prefix length", p))?,
            None => switched_bits + max_prefix,
        };
        if prefix > switched_bits + max_prefix {
            bail!(
                "prefix length /{} is out of range for {}",
                prefix,
                addr_part
            );
        }
        if prefix < switched_bits {
            bail!(
                "`{}` is an IPv4-mapped address, its prefix cannot be shorter than /{}",
                addr_part,
                switched_bits
            );
        }
        let prefix = prefix - switched_bits;

        Ok(match ip {
            IpAddr::V4(v4) => IpNetSpec::V4 {
                net: u32::from(v4) & v4_mask(prefix),
                prefix,
            },
            IpAddr::V6(v6) => IpNetSpec::V6 {
                net: u128::from(v6) & v6_mask(prefix),
                prefix,
            },
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, normalize_ip(ip)) {
            (IpNetSpec::V4 { net, prefix }, IpAddr::V4(v4)) => {
                let mask = v4_mask(*prefix);
                (u32::from(v4) & mask) == (*net & mask)
            }
            (IpNetSpec::V6 { net, prefix }, IpAddr::V6(v6)) => {
                let mask = v6_mask(*prefix);
                (u128::from(v6) & mask) == (*net & mask)
            }
            // Different address families never match.
            _ => false,
        }
    }
}

/// Rejects a bad entry while the configuration is being loaded.
pub fn validate_entries<'a, I>(items: I) -> Result<()>
where
    I: IntoIterator<Item = &'a String>,
{
    for raw in items {
        IpNetSpec::parse(raw).with_context(|| format!("Invalid ACL entry `{}`", raw))?;
    }
    Ok(())
}

/// A parsed allowlist ready for lookups.
///
/// `None` marks an unusable list (an entry failed to parse): the list then
/// fails closed and refuses everything, which is noticed immediately instead of
/// silently turning into an open port.
#[derive(Debug, Clone, Default)]
pub struct AclList(Option<Vec<IpNetSpec>>);

impl AclList {
    /// Parses configuration entries; an empty list means "no restriction".
    pub fn parse(items: &[String]) -> Self {
        let mut out = Vec::with_capacity(items.len());
        for raw in items {
            match IpNetSpec::parse(raw) {
                Ok(net) => out.push(net),
                Err(e) => {
                    error!("Allowlist disabled (fail closed): {:#}", e);
                    return AclList(None);
                }
            }
        }
        AclList(Some(out))
    }

    /// One-line description for startup / reload logs.
    pub fn describe(&self) -> String {
        match &self.0 {
            None => "INVALID -> refusing every source".to_string(),
            Some(v) if v.is_empty() => "open (no restriction)".to_string(),
            Some(v) => format!(
                "{} entr{}",
                v.len(),
                if v.len() == 1 { "y" } else { "ies" }
            ),
        }
    }

    /// Decides whether `ip` may connect.
    pub fn decide(&self, mode: AclMode, ip: IpAddr) -> AclDecision {
        match &self.0 {
            None => AclDecision::Deny,
            Some(list) if list.is_empty() => AclDecision::Allow,
            Some(list) if list.iter().any(|net| net.contains(ip)) => AclDecision::Allow,
            Some(_) => match mode {
                AclMode::Enforce => AclDecision::Deny,
                AclMode::Observe => AclDecision::ObserveDeny,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    fn list(items: &[&str]) -> AclList {
        AclList::parse(&items.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn parse_accepts_plain_and_cidr() {
        assert_eq!(IpNetSpec::parse("1.2.3.4").unwrap(), IpNetSpec::V4 { net: 0x0102_0304, prefix: 32 });
        assert_eq!(IpNetSpec::parse("10.0.0.0/8").unwrap(), IpNetSpec::V4 { net: 0x0a00_0000, prefix: 8 });
        assert_eq!(IpNetSpec::parse(" 192.168.1.0/24 ").unwrap(), IpNetSpec::V4 { net: 0xc0a8_0100, prefix: 24 });
        assert_eq!(IpNetSpec::parse("::1").unwrap(), IpNetSpec::V6 { net: 1, prefix: 128 });
        assert_eq!(IpNetSpec::parse("0.0.0.0/0").unwrap(), IpNetSpec::V4 { net: 0, prefix: 0 });
    }

    #[test]
    fn parse_masks_host_bits() {
        // `10.1.2.3/8` has host bits set; they must be masked away.
        assert_eq!(IpNetSpec::parse("10.1.2.3/8").unwrap(), IpNetSpec::V4 { net: 0x0a00_0000, prefix: 8 });
    }

    #[test]
    fn parse_folds_mapped_addresses() {
        assert_eq!(IpNetSpec::parse("::ffff:1.2.3.4").unwrap(), IpNetSpec::V4 { net: 0x0102_0304, prefix: 32 });
        assert_eq!(
            IpNetSpec::parse("::ffff:1.2.3.0/120").unwrap(),
            IpNetSpec::V4 { net: 0x0102_0300, prefix: 24 }
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        for bad in ["", "abc", "1.2.3.4/33", "::1/129", "1.2.3.4/x", "::ffff:1.2.3.0/90"] {
            assert!(IpNetSpec::parse(bad).is_err(), "{} should be rejected", bad);
        }
    }

    #[test]
    fn contains_respects_prefix_boundaries() {
        let net = IpNetSpec::parse("10.0.0.0/8").unwrap();
        assert!(net.contains(v4("10.0.0.0")));
        assert!(net.contains(v4("10.1.2.3")));
        assert!(net.contains(v4("10.255.255.255")));
        assert!(!net.contains(v4("11.0.0.1")));
        assert!(!net.contains(v4("9.255.255.255")));

        let v6net = IpNetSpec::parse("2001:db8::/32").unwrap();
        assert!(v6net.contains(v6("2001:db8::1")));
        assert!(!v6net.contains(v6("2001:db9::1")));

        // Families do not cross.
        assert!(!net.contains(v6("2001:db8::1")));
        assert!(!v6net.contains(v4("10.1.2.3")));
    }

    #[test]
    fn contains_matches_dual_stack_peers() {
        // A dual-stack listener reports an IPv4 peer as an IPv4-mapped address.
        let net = IpNetSpec::parse("198.51.100.0/24").unwrap();
        assert!(net.contains(v6("::ffff:198.51.100.7")));
    }

    #[test]
    fn contain_all_matches_everything() {
        let net = IpNetSpec::parse("0.0.0.0/0").unwrap();
        assert!(net.contains(v4("1.2.3.4")));
        assert!(net.contains(v4("255.255.255.255")));
        assert!(!net.contains(v6("2001:db8::1")));
    }

    #[test]
    fn empty_list_allows_everything() {
        let acl = list(&[]);
        assert_eq!(acl.describe(), "open (no restriction)");
        assert_eq!(acl.decide(AclMode::Enforce, v4("203.0.113.9")), AclDecision::Allow);
        assert_eq!(acl.decide(AclMode::Observe, v6("2001:db8::1")), AclDecision::Allow);
    }

    #[test]
    fn enforce_mode_drops_unlisted_sources() {
        let acl = list(&["10.0.0.0/8", "198.51.100.7"]);
        assert_eq!(acl.decide(AclMode::Enforce, v4("10.9.9.9")), AclDecision::Allow);
        assert_eq!(acl.decide(AclMode::Enforce, v4("198.51.100.7")), AclDecision::Allow);
        assert_eq!(acl.decide(AclMode::Enforce, v4("198.51.100.8")), AclDecision::Deny);
        assert_eq!(acl.decide(AclMode::Enforce, v6("2001:db8::1")), AclDecision::Deny);
    }

    #[test]
    fn observe_mode_logs_but_allows() {
        let acl = list(&["10.0.0.0/8"]);
        assert_eq!(acl.decide(AclMode::Observe, v4("203.0.113.9")), AclDecision::ObserveDeny);
        assert_eq!(acl.decide(AclMode::Observe, v4("10.0.0.1")), AclDecision::Allow);
    }

    #[test]
    fn invalid_entry_fails_closed() {
        // A typo must never silently open the port: everything is refused.
        let acl = list(&["10.0.0.0/8", "oops"]);
        assert!(acl.describe().starts_with("INVALID"), "{}", acl.describe());
        assert_eq!(acl.decide(AclMode::Enforce, v4("10.0.0.1")), AclDecision::Deny);
        assert_eq!(acl.decide(AclMode::Observe, v4("10.0.0.1")), AclDecision::Deny);
    }

    #[test]
    fn validate_entries_reports_the_offender() {
        let ok = vec!["10.0.0.0/8".to_string()];
        assert!(validate_entries(&ok).is_ok());
        let bad = vec!["10.0.0.0/8".to_string(), "nope".to_string()];
        let err = validate_entries(&bad).unwrap_err().to_string();
        assert!(err.contains("nope"), "error should name the bad entry: {}", err);
    }
}
