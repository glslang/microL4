//! Channel offers (`vmbus_chanmsg_choffer`): what vmbus keeps of each, the
//! device types it names, and the table of up to 32.

use core::fmt;

/// A GUID as VMBus carries it: 16 bytes, the first three fields
/// little-endian.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// The GUID whose text is `s`, as `f8615163-df3e-46c5-913f-f2d2f965ed0e`;
    /// `None` for anything else.
    pub const fn parse(s: &str) -> Option<Guid> {
        let s = s.as_bytes();
        if s.len() != 36 || s[8] != b'-' || s[13] != b'-' || s[18] != b'-' || s[23] != b'-' {
            return None;
        }
        // The text's bytes, in order, then put in wire order.
        let mut t = [0u8; 16];
        let mut i = 0;
        let mut j = 0;
        while i < 36 {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                i += 1;
                continue;
            }
            let (Some(hi), Some(lo)) = (hex(s[i]), hex(s[i + 1])) else {
                return None;
            };
            t[j] = hi << 4 | lo;
            j += 1;
            i += 2;
        }
        let order = WIRE_ORDER;
        let mut g = [0u8; 16];
        let mut k = 0;
        while k < 16 {
            g[order[k]] = t[k];
            k += 1;
        }
        Some(Guid(g))
    }

    /// The device type's name, for the ones vmbus knows.
    pub fn name(&self) -> Option<&'static str> {
        KNOWN.iter().find(|(g, _)| g == self).map(|&(_, n)| n)
    }
}

/// Which wire byte each text byte is: FreeBSD's `hyperv_guid2str` prints
/// bytes 3, 2, 1, 0, 5, 4, 7, 6, then 8 to 15.
const WIRE_ORDER: [usize; 16] = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];

const fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const fn guid(s: &str) -> Guid {
    match Guid::parse(s) {
        Some(g) => g,
        None => panic!("a GUID's text"),
    }
}

/// The synthetic network adapter (FreeBSD's `hn_guid`, `if_hn.c`).
pub const NETVSC: Guid = guid("f8615163-df3e-46c5-913f-f2d2f965ed0e");

/// The device types vmbus names in its offer lines. From FreeBSD's
/// drivers (read 2026-11-27): netvsc (`if_hn.c`), storvsc
/// (`hv_storvsc_drv_freebsd.c`), mouse (`hv_hid.c`), heartbeat, shutdown
/// and time sync (`vmbus_heartbeat.c`, `vmbus_shutdown.c`,
/// `vmbus_timesync.c`), KVP (`hv_kvp.c`) and VSS (`hv_snapshot.c`); the
/// synthetic video's and the keyboard's from memory.
pub const KNOWN: [(Guid, &str); 10] = [
    (NETVSC, "netvsc"),
    (guid("ba6163d9-04a1-4d29-b605-72e2ffb1dc7f"), "storvsc"),
    (
        guid("da0a7802-e377-4aac-8e77-0558eb1073f8"),
        "synthetic video",
    ),
    (guid("f912ad6d-2b17-48ea-bd65-f927a61c7684"), "keyboard"),
    (guid("cfa8b69e-5b4a-4cc0-b98b-8ba1a1f3f95a"), "mouse"),
    (guid("57164f39-9115-4e78-ab55-382f3bd5422d"), "heartbeat"),
    (guid("0e0b6031-5213-4934-818b-38d90ced39db"), "shutdown"),
    (guid("9527e630-d0ae-497b-adce-e80ab0175caf"), "time sync"),
    (guid("a9a0f4e7-5a45-4d96-b827-8a841e8c03e6"), "KVP"),
    (guid("35fa2e29-ea23-4236-96ae-3a6ebacba440"), "VSS"),
];

/// As FreeBSD's `hyperv_guid2str` prints it.
impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, &w) in WIRE_ORDER.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{:02x}", self.0[w])?;
        }
        Ok(())
    }
}

/// What vmbus keeps of an offer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Offer {
    /// `chm_chanid`: the channel ID, 1 to 2,047.
    pub channel: u32,
    /// `chm_chtype`: the device type.
    pub kind: Guid,
    /// `chm_chinst`: the device instance.
    pub instance: Guid,
    /// `chm_subidx`: 0 for a primary channel.
    pub subchannel: u16,
    /// `chm_flags1`: bit 0 `HASMNF`, the host may monitor the channel.
    pub flags1: u8,
    /// `chm_montrig`: the monitor trigger, group `montrig / 32`.
    pub montrig: u8,
    /// `chm_flags2`.
    pub flags2: u16,
    /// `chm_connid`: the connection the guest signals the channel on,
    /// below 2^24.
    pub connection: u32,
}

impl Offer {
    /// The highest channel ID (`VMBUS_CHAN_MAX` - 1): the SIEF slot's
    /// 2,048 flags.
    pub const MAX_CHANNEL: u32 = 2047;
    /// Connection IDs have 24 bits (TLFS `HV_CONNECTION_ID`).
    pub const CONNECTIONS: u32 = 1 << 24;

    /// Whether the host may monitor the channel (`HASMNF`).
    pub fn has_mnf(&self) -> bool {
        self.flags1 & 1 != 0
    }

    /// Whether it is a primary netvsc channel: the one vmbus opens.
    pub fn is_netvsc(&self) -> bool {
        self.kind == NETVSC && self.subchannel == 0
    }
}

/// `vmbus: offer <id>: <name>, connection <c>`, then `, sub-channel <n>`
/// for a sub-channel and `, monitor trigger <t>` for an offer with
/// `HASMNF`: with `netvsc.mnf=1`, netvsc signals such a channel through
/// the monitor page and any other with `SignalEvent`, so the log says
/// which the host took.
impl fmt::Display for Offer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vmbus: offer {}: ", self.channel)?;
        match self.kind.name() {
            Some(n) => f.write_str(n)?,
            None => write!(f, "{}", self.kind)?,
        }
        write!(f, ", connection {}", self.connection)?;
        if self.subchannel != 0 {
            write!(f, ", sub-channel {}", self.subchannel)?;
        }
        if self.has_mnf() {
            write!(f, ", monitor trigger {}", self.montrig)?;
        }
        Ok(())
    }
}

/// Why an offer is not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A channel ID of 0 or above 2,047.
    Channel,
    /// A connection ID with reserved bits set.
    Connection,
    /// A second offer of a channel ID already kept.
    Repeated,
    /// 32 offers are kept already.
    Full,
}

/// The offers kept: at most [`Offers::MAX`], each a distinct channel ID.
#[derive(Clone, Debug)]
pub struct Offers {
    list: [Offer; Offers::MAX],
    len: usize,
}

impl Default for Offers {
    fn default() -> Offers {
        Offers {
            list: [Offer::default(); Offers::MAX],
            len: 0,
        }
    }
}

impl Offers {
    pub const MAX: usize = 32;

    /// Keeps `o`, or says why not.
    pub fn add(&mut self, o: Offer) -> Result<(), Refused> {
        if o.channel == 0 || o.channel > Offer::MAX_CHANNEL {
            return Err(Refused::Channel);
        }
        if o.connection >= Offer::CONNECTIONS {
            return Err(Refused::Connection);
        }
        if self.get(o.channel).is_some() {
            return Err(Refused::Repeated);
        }
        let slot = self.list.get_mut(self.len).ok_or(Refused::Full)?;
        *slot = o;
        self.len += 1;
        Ok(())
    }

    /// The offer of `channel`.
    pub fn get(&self, channel: u32) -> Option<&Offer> {
        self.iter().find(|o| o.channel == channel)
    }

    /// Forgets the offer of `channel`; returns it.
    pub fn remove(&mut self, channel: u32) -> Option<Offer> {
        let i = self.iter().position(|o| o.channel == channel)?;
        let o = self.list[i];
        self.list.copy_within(i + 1..self.len, i);
        self.len -= 1;
        Some(o)
    }

    /// The first primary netvsc offer.
    pub fn netvsc(&self) -> Option<&Offer> {
        self.iter().find(|o| o.is_netvsc())
    }

    /// The highest channel ID kept.
    pub fn max_channel(&self) -> Option<u32> {
        self.iter().map(|o| o.channel).max()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Offer> {
        self.list[..self.len].iter()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
