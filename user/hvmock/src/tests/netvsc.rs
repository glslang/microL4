//! The netvsc device's own round trips, with the test as the guest on the
//! rings: NVSP's answers, an RNDIS control request through the request
//! page and its answer in a receive section, a frame each way, and the
//! faults the device records for a guest that breaks its rules.

use super::*;
use crate::device::read_bytes;
use crate::netvsc::{self, Netvsc, nvs, packet_msg, rndis, words};
use crate::ring::{FLAG_COMPLETION, Packet, kind as pk};

const RX: u32 = 0x100;
const TX: u32 = 0x101;

/// Makes GPADL `gpadl` of `count` channel-frame pages from `first`.
fn gpadl(m: &Machine, h: &mut Host<'_>, gpadl: u32, first: u64, count: u64) {
    let base = CHANNEL / PAGE + first;
    let n = count.min(26);
    h.post_message(1, 1, &gpadl_conn(14, gpadl, base, count, n));
    let mut at = base + n;
    while at < base + count {
        let end = (at + 28).min(base + count);
        h.post_message(1, 1, &gpadl_subconn(gpadl, at..end));
        at = end;
    }
    assert_eq!(take(m, h), Some(wire::gpadl_connresp(14, gpadl, 0)));
}

/// An open channel 14 with the netvsc device and its two buffers' GPADLs.
fn nic_host(m: &Machine, cfg: netvsc::Config) -> (Host<'_>, Netvsc) {
    let nic = Netvsc::new(cfg);
    let mut h = contacted(m, Config::default());
    h.attach(14, Box::new(nic.clone()));
    let first = CHANNEL / PAGE;
    h.post_message(1, 1, &gpadl_conn(14, 7, first, RING_PAGES, 26));
    h.post_message(1, 1, &gpadl_subconn(7, first + 26..first + 32));
    assert_eq!(take(m, &mut h), Some(wire::gpadl_connresp(14, 7, 0)));
    h.post_message(1, 1, &chopen(14, 7, 16));
    assert_eq!(take(m, &mut h), Some(wire::chopen_resp(14, 14, 0)));
    gpadl(m, &mut h, RX, 256, 256);
    gpadl(m, &mut h, TX, 64, 192);
    assert!(h.log().is_empty(), "{:?}", h.log());
    (h, nic)
}

fn out(m: &Machine) -> Ring<crate::machine::Page<'_>> {
    Ring::new(m.window(CHANNEL, 16 * PAGE))
}

fn inb(m: &Machine) -> Ring<crate::machine::Page<'_>> {
    Ring::new(m.window(CHANNEL + 16 * PAGE, 16 * PAGE))
}

fn nvs_msg(w: &[u32]) -> Vec<u8> {
    let mut v = words(w);
    v.resize(40, 0);
    v
}

/// The guest writes a packet and signals; the host runs; the guest reads
/// what came back.
fn exchange(
    m: &Machine,
    h: &mut Host<'_>,
    kind: u16,
    flags: u16,
    xid: u64,
    ext: &[u8],
    body: &[u8],
) -> Vec<Packet> {
    out(m).write_ext(kind, flags, xid, ext, body).unwrap();
    h.signal_event(14, 0);
    while h.step() {}
    inb(m).read_all().unwrap()
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

#[test]
fn the_netvsc_device_answers_nvsp_rndis_and_frames() {
    let m = Machine::new();
    let (mut h, nic) = nic_host(&m, netvsc::Config::default());
    // INIT: refused for 4, taken for 5.
    let p = exchange(
        &m,
        &mut h,
        pk::INBAND,
        FLAG_COMPLETION,
        1,
        &[],
        &nvs_msg(&[nvs::INIT, nvs::V5, nvs::V5]),
    );
    assert_eq!((p[0].kind, p[0].xid), (pk::COMP, 1));
    assert_eq!(u32_at(p[0].body(), 0), nvs::INIT_RESP);
    assert_eq!(u32_at(p[0].body(), 12), nvs::OK);
    exchange(
        &m,
        &mut h,
        pk::INBAND,
        0,
        0,
        &[],
        &nvs_msg(&[nvs::NDIS_CONF, 1514, 0, 8, 0]),
    );
    exchange(
        &m,
        &mut h,
        pk::INBAND,
        0,
        0,
        &[],
        &nvs_msg(&[nvs::NDIS_INIT, 6, 30]),
    );
    let p = exchange(
        &m,
        &mut h,
        pk::INBAND,
        FLAG_COMPLETION,
        4,
        &[],
        &nvs_msg(&[nvs::RXBUF_CONN, RX, 0xCAFE]),
    );
    let b = p[0].body();
    assert_eq!(
        (u32_at(b, 0), u32_at(b, 4), u32_at(b, 8)),
        (nvs::RXBUF_CONNRESP, nvs::OK, 1)
    );
    assert_eq!(
        (u32_at(b, 12), u32_at(b, 16), u32_at(b, 20)),
        (0, 1728, 606)
    );
    let p = exchange(
        &m,
        &mut h,
        pk::INBAND,
        FLAG_COMPLETION,
        5,
        &[],
        &nvs_msg(&[nvs::CHIM_CONN, TX, 0xFACE]),
    );
    assert_eq!(u32_at(p[0].body(), 8), 6144);
    // RNDIS INITIALIZE through the request page: the GPA packet's
    // completion, then the answer in a receive section.
    let req = words(&[rndis::INITIALIZE, 24, 1 << 16, 1, 0, 2048]);
    m.ram()
        .write(netvsc::REQUEST_PAGE as usize * PAGE as usize, &req);
    let mut ext = words(&[0, 1, 24, 0]);
    ext.extend_from_slice(&netvsc::REQUEST_PAGE.to_le_bytes());
    let p = exchange(
        &m,
        &mut h,
        pk::GPA,
        FLAG_COMPLETION,
        1 << 16,
        &ext,
        &nvs_msg(&[nvs::RNDIS, 1, nvs::CHIM_NONE, 0]),
    );
    assert_eq!((p[0].kind, p[0].xid), (pk::COMP, 1 << 16));
    assert_eq!(p[1].kind, pk::RXBUF);
    let hd = &p[1].bytes[..p[1].header_len];
    assert_eq!((u32_at(hd, 16) & 0xFFFF, u32_at(hd, 20)), (0xCAFE, 1));
    let (len, ofs) = (u32_at(hd, 24) as usize, u32_at(hd, 28) as usize);
    let rx = m.view_of(&h, RX);
    let a = read_bytes(&rx, ofs, len);
    assert_eq!(
        (u32_at(&a, 0), u32_at(&a, 8), u32_at(&a, 12)),
        (rndis::INITIALIZE_CMPLT, 1 << 16, 0)
    );
    // Acknowledged, the section goes back.
    let free = nic.free_sections();
    exchange(
        &m,
        &mut h,
        pk::COMP,
        0,
        p[1].xid,
        &[],
        &netvsc::rndis_ack(nvs::OK),
    );
    assert_eq!(nic.free_sections(), free + 1);
    // A frame out of section 3, completed.
    let f = vec![0x5A; 60];
    let mut msg = packet_msg(&f, false);
    msg.truncate(44 + 60);
    let tx = m.view_of(&h, TX);
    tx.write(3 * 6144, &msg);
    let p = exchange(
        &m,
        &mut h,
        pk::INBAND,
        FLAG_COMPLETION,
        (1 << 32) + 3,
        &[],
        &nvs_msg(&[nvs::RNDIS, 0, 3, 104]),
    );
    assert_eq!((p[0].kind, p[0].xid), (pk::COMP, (1 << 32) + 3));
    assert_eq!(u32_at(p[0].body(), 0), nvs::RNDIS_ACK);
    assert_eq!(nic.take_sent(), [f]);
    assert!(nic.faults().is_empty(), "{:?}", nic.faults());
    assert_eq!(nic.unacked(), 0);
}

#[test]
fn the_netvsc_device_records_a_guest_that_breaks_its_rules() {
    let m = Machine::new();
    let (mut h, nic) = nic_host(
        &m,
        netvsc::Config {
            hold_completions: true,
            ..netvsc::Config::default()
        },
    );
    let data = nvs_msg(&[nvs::RNDIS, 0, 3, 104]);
    // A data packet before CHIM_CONN.
    exchange(&m, &mut h, pk::INBAND, FLAG_COMPLETION, 1 << 32, &[], &data);
    exchange(
        &m,
        &mut h,
        pk::INBAND,
        FLAG_COMPLETION,
        1,
        &[],
        &nvs_msg(&[nvs::INIT, nvs::V5, nvs::V5]),
    );
    // NDIS 6.1 with NVSP 5; a short NVS message.
    exchange(
        &m,
        &mut h,
        pk::INBAND,
        0,
        0,
        &[],
        &nvs_msg(&[nvs::NDIS_INIT, 6, 1]),
    );
    exchange(
        &m,
        &mut h,
        pk::INBAND,
        0,
        0,
        &[],
        &words(&[nvs::NDIS_CONF, 1514]),
    );
    exchange(
        &m,
        &mut h,
        pk::INBAND,
        FLAG_COMPLETION,
        5,
        &[],
        &nvs_msg(&[nvs::CHIM_CONN, TX, 0xFACE]),
    );
    // The same section twice before its completion.
    let tx = m.view_of(&h, TX);
    let mut msg = packet_msg(&[0x5A; 60], false);
    msg.truncate(104);
    tx.write(3 * 6144, &msg);
    exchange(
        &m,
        &mut h,
        pk::INBAND,
        FLAG_COMPLETION,
        (1 << 32) + 3,
        &[],
        &data,
    );
    exchange(
        &m,
        &mut h,
        pk::INBAND,
        FLAG_COMPLETION,
        (1 << 32) + 3,
        &[],
        &data,
    );
    // An acknowledgement of nothing; a GPA packet naming another page.
    exchange(
        &m,
        &mut h,
        pk::COMP,
        0,
        77,
        &[],
        &netvsc::rndis_ack(nvs::OK),
    );
    let mut ext = words(&[0, 1, 24, 0]);
    ext.extend_from_slice(&(netvsc::REQUEST_PAGE + 1).to_le_bytes());
    exchange(
        &m,
        &mut h,
        pk::GPA,
        FLAG_COMPLETION,
        1,
        &ext,
        &nvs_msg(&[nvs::RNDIS, 1, nvs::CHIM_NONE, 0]),
    );
    let faults = nic.faults();
    for want in [
        "a data packet before CHIM_CONN",
        "NDIS_INIT 6.1 with NVSP Some(327680)",
        "an NVS message of 8 bytes",
        "section 3 sent again",
        "an acknowledgement of 0x4d, which is not outstanding",
        "a GPA packet naming 24 bytes at 0 of page 0x221",
    ] {
        assert!(
            faults.iter().any(|f| f.starts_with(want)),
            "{want:?} not in {faults:#?}"
        );
    }
    assert_eq!(faults.len(), 6, "{faults:#?}");
}

impl Machine {
    /// GPADL `handle`'s pages as one window, as the host holds them.
    fn view_of<'a>(&'a self, h: &'a Host<'_>, handle: u32) -> crate::machine::View<'a> {
        self.view(&h.gpadl(handle).expect("a GPADL").pages)
    }
}
