//! The stack's static configuration (`docs/design.md`, "`net`"): its
//! address and prefix and its gateway, from the kernel command line's
//! `net.ip=<a.b.c.d>/<n>` and `net.gw=<a.b.c.d>`. Root runs
//! [`Config::parse`] before it starts anything and passes the result to
//! `net` in two words ([`Config::to_words`]), which net's entry checks
//! again ([`Config::from_words`]).
//!
//! On QEMU each word defaults to [`Config::QEMU`]'s half, user
//! networking's `10.0.2.15/24` via `10.0.2.2`; on Hyper-V there is no
//! default. A prefix runs from 8 to 30; the address must be a host of its
//! subnet, neither its network nor its broadcast address, and unicast
//! (not in `0.0.0.0/8`, `127.0.0.0/8` or from `224.0.0.0` up); the gateway
//! must be another host of the same subnet.

use core::fmt;

use libsys::cmdline;

use crate::ipv4::Ip;

/// The address, the prefix and the gateway, checked: only
/// [`Config::new`] makes one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Config {
    address: Ip,
    /// The prefix length, [`Config::MIN_PREFIX`] to [`Config::MAX_PREFIX`].
    prefix: u8,
    gateway: Ip,
}

/// Why a configuration was refused: root prints the text and fails the
/// test.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigError<'a> {
    /// `net.ip` or `net.gw` missing with no default (Hyper-V).
    NoAddress,
    /// `net.ip`'s value is not `<a.b.c.d>/<n>`.
    NotAnAddress(&'a str),
    /// `net.gw`'s value is not `<a.b.c.d>`.
    NotAGateway(&'a str),
    /// A prefix outside 8 to 30.
    Prefix(u8),
    /// An address that is not a unicast host of its subnet.
    Address(Ip, u8),
    /// A gateway that is not another host of the address's subnet.
    Gateway(Config),
}

impl fmt::Display for ConfigError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ConfigError::NoAddress => {
                f.write_str("net: no address: pass net.ip=<a.b.c.d>/<n> net.gw=<a.b.c.d>")
            }
            ConfigError::NotAnAddress(v) => {
                write!(f, "net: net.ip=\"{v}\" is not <a.b.c.d>/<n>")
            }
            ConfigError::NotAGateway(v) => write!(f, "net: net.gw=\"{v}\" is not <a.b.c.d>"),
            ConfigError::Prefix(n) => write!(
                f,
                "net: prefix /{n} is not from {} to {}",
                Config::MIN_PREFIX,
                Config::MAX_PREFIX
            ),
            ConfigError::Address(ip, n) => {
                write!(f, "net: {ip}/{n} is not a unicast host address")
            }
            ConfigError::Gateway(c) => write!(
                f,
                "net: gateway {} is not another host of {}/{}",
                c.gateway,
                c.network(),
                c.prefix
            ),
        }
    }
}

impl Config {
    /// QEMU user networking's: `10.0.2.15/24` via `10.0.2.2`.
    pub const QEMU: Config = Config {
        address: Ip::new(10, 0, 2, 15),
        prefix: 24,
        gateway: Ip::new(10, 0, 2, 2),
    };
    pub const MIN_PREFIX: u8 = 8;
    pub const MAX_PREFIX: u8 = 30;

    pub const fn address(&self) -> Ip {
        self.address
    }

    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    pub const fn gateway(&self) -> Ip {
        self.gateway
    }

    /// Checks a configuration.
    pub fn new(address: Ip, prefix: u8, gateway: Ip) -> Result<Config, ConfigError<'static>> {
        if !(Config::MIN_PREFIX..=Config::MAX_PREFIX).contains(&prefix) {
            return Err(ConfigError::Prefix(prefix));
        }
        let c = Config {
            address,
            prefix,
            gateway,
        };
        if !address.is_unicast() || !c.is_host(address) {
            return Err(ConfigError::Address(address, prefix));
        }
        if !c.is_host(gateway) || gateway == address {
            return Err(ConfigError::Gateway(c));
        }
        Ok(c)
    }

    /// The configuration the command line gives, each of `net.ip` and
    /// `net.gw` defaulting to `default`'s (QEMU's, or none on Hyper-V).
    pub fn parse(cmdline: &str, default: Option<Config>) -> Result<Config, ConfigError<'_>> {
        let (address, prefix) = match cmdline::value(cmdline, "net.ip") {
            Some(v) => parse_address(v).ok_or(ConfigError::NotAnAddress(v))?,
            None => {
                let d = default.ok_or(ConfigError::NoAddress)?;
                (d.address, d.prefix)
            }
        };
        let gateway = match cmdline::value(cmdline, "net.gw") {
            Some(v) => Ip::parse(v).ok_or(ConfigError::NotAGateway(v))?,
            None => default.ok_or(ConfigError::NoAddress)?.gateway,
        };
        Config::new(address, prefix, gateway)
    }

    /// The subnet mask.
    pub const fn mask(&self) -> u32 {
        u32::MAX << (32 - self.prefix)
    }

    /// The subnet's network address.
    pub const fn network(&self) -> Ip {
        Ip::from_u32(self.address.to_u32() & self.mask())
    }

    /// The subnet's broadcast address.
    pub const fn broadcast(&self) -> Ip {
        Ip::from_u32(self.address.to_u32() | !self.mask())
    }

    /// Whether `ip` is in the subnet.
    pub const fn contains(&self, ip: Ip) -> bool {
        (ip.to_u32() ^ self.address.to_u32()) & self.mask() == 0
    }

    /// Whether `ip` is a host of the subnet: in it, and neither its
    /// network nor its broadcast address.
    pub fn is_host(&self, ip: Ip) -> bool {
        self.contains(ip) && ip != self.network() && ip != self.broadcast()
    }

    /// Where a packet to `dst` goes first: `dst` in the subnet, else the
    /// gateway.
    pub fn next_hop(&self, dst: Ip) -> Ip {
        if self.contains(dst) {
            dst
        } else {
            self.gateway
        }
    }

    /// net's arguments (`docs/design.md`, "Arguments"): `rdi` the address
    /// in bits 0 to 31 and the prefix in bits 32 to 39, `rsi` the gateway,
    /// `rdx` and `rcx` 0.
    pub const fn to_words(&self) -> [u64; 4] {
        [
            self.address.to_u32() as u64 | (self.prefix as u64) << 32,
            self.gateway.to_u32() as u64,
            0,
            0,
        ]
    }

    /// The configuration in net's arguments, checked again; `None` for
    /// words [`Config::to_words`] never makes.
    pub fn from_words(w: [u64; 4]) -> Option<Config> {
        if w[0] >> 40 != 0 || w[1] >> 32 != 0 || w[2] != 0 || w[3] != 0 {
            return None;
        }
        Config::new(
            Ip::from_u32(w[0] as u32),
            (w[0] >> 32) as u8,
            Ip::from_u32(w[1] as u32),
        )
        .ok()
    }
}

/// `10.0.2.15/24 via 10.0.2.2`.
impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{} via {}", self.address, self.prefix, self.gateway)
    }
}

/// `<a.b.c.d>/<n>`, `n` a decimal of one or two digits without a leading
/// zero; its range is [`Config::new`]'s to check.
fn parse_address(v: &str) -> Option<(Ip, u8)> {
    let (ip, n) = v.split_once('/')?;
    let digits = !n.is_empty()
        && n.len() <= 2
        && n.bytes().all(|b| b.is_ascii_digit())
        && (n == "0" || !n.starts_with('0'));
    if !digits {
        return None;
    }
    Some((Ip::parse(ip)?, n.parse().ok()?))
}
