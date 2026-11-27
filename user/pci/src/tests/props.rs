//! Random configuration spaces: the scan against a reference that works
//! out which functions are reachable from the headers alone, and BAR
//! sizing and the plan on mutated virtio-net headers, checked against the
//! plan's invariants.

use std::collections::BTreeSet;
use std::vec::Vec;

use proptest::prelude::*;

use super::model::{Header, Space};
use super::plan::nic;
use super::scan::{at, visit};
use crate::{Address, Bars, Function, PAGE, Plan, Range, WalkEnd, size};

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 256 },
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// A header of random bytes, often with a layout that matters (a device,
/// a bridge, either multi-function) and a secondary bus below 8.
fn header() -> impl Strategy<Value = Header> {
    (
        proptest::collection::vec(any::<u8>(), 256),
        prop_oneof![Just(0u8), Just(1), Just(0x80), Just(0x81), any::<u8>()],
        0u8..8,
        prop_oneof![3 => Just(false), 1 => Just(true)],
    )
        .prop_map(|(bytes, ty, secondary, absent)| {
            let mut h = Header {
                bytes: bytes.try_into().unwrap(),
                sizes: [0; 6],
            };
            h.bytes[0x0E] = ty;
            h.bytes[0x19] = secondary;
            if absent {
                h.bytes[0] = 0xFF;
                h.bytes[1] = 0xFF;
            } else if h.bytes[0..2] == [0xFF, 0xFF] {
                h.bytes[0] = 0;
            }
            h
        })
}

fn segment() -> impl Strategy<Value = Vec<(Address, Header)>> {
    proptest::collection::vec((0u8..8, 0u8..4, 0u8..8, header()), 0..24).prop_map(|v| {
        let mut seen = BTreeSet::new();
        v.into_iter()
            .map(|(b, d, f, h)| (at(b, d, f), h))
            .filter(|(a, _)| seen.insert(*a))
            .collect()
    })
}

/// The functions a scan must visit, from the headers alone: bus `start`,
/// then each bridge's secondary bus in the range; on each, a device whose
/// function 0 answers, with functions 1 to 7 that answer if function 0 is
/// multi-function.
fn reachable(fs: &[(Address, Header)], range: Range) -> BTreeSet<Address> {
    let answers = |a: &Address| {
        fs.iter()
            .find(|(x, _)| x == a)
            .filter(|(_, h)| h.bytes[0..2] != [0xFF, 0xFF])
            .map(|(_, h)| h)
    };
    let mut buses = BTreeSet::from([range.start_bus]);
    let mut out = BTreeSet::new();
    loop {
        let before = (buses.len(), out.len());
        for (a, h) in fs {
            if !buses.contains(&a.bus) || answers(a).is_none() {
                continue;
            }
            let zero = Address { function: 0, ..*a };
            let Some(h0) = answers(&zero) else { continue };
            if a.function != 0 && h0.bytes[0x0E] & 0x80 == 0 {
                continue;
            }
            out.insert(*a);
            if h.bytes[0x0E] & 0x7F == 1 && range.contains(h.bytes[0x19]) {
                buses.insert(h.bytes[0x19]);
            }
        }
        if (buses.len(), out.len()) == before {
            return out;
        }
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn the_scan_visits_exactly_the_reachable_functions_once(
        fs in segment(),
        start in 0u8..3,
        end in 3u8..8,
    ) {
        let range = Range { segment: 0, start_bus: start, end_bus: end };
        let mut s = Space::new(&fs);
        let (seen, r) = visit(&mut s, range);
        let r = r.unwrap();
        let got: BTreeSet<_> = seen.iter().map(|f| f.address).collect();
        prop_assert_eq!(got.len(), seen.len(), "a function visited twice");
        prop_assert_eq!(&got, &reachable(&fs, range));
        prop_assert_eq!(r.functions, seen.len());
        prop_assert_eq!(r.buses, s.reached.len());
        prop_assert!(s.reached.iter().all(|&b| range.contains(b)));
        for f in &seen {
            let caps = f.capabilities.as_slice();
            let offsets: BTreeSet<_> = caps.iter().map(|c| c.offset).collect();
            prop_assert_eq!(offsets.len(), caps.len());
            prop_assert!(caps.iter().all(|c| c.offset >= 0x40 && c.offset % 4 == 0));
            if f.status & 0x10 == 0 || f.layout() > 1 {
                prop_assert_eq!(f.capabilities.end, WalkEnd::NoList);
            }
        }
    }

    /// Bytes from 0x34 on and every BAR's value and size changed at
    /// random: sizing never writes a BAR that decodes and restores
    /// everything, and a plan, when there is one, keeps every rule.
    #[test]
    fn plans_of_mutated_headers_keep_their_rules(
        edits in proptest::collection::vec((0x34usize..0x100, any::<u8>()), 0..12),
        bars in proptest::collection::vec((0usize..6, any::<u64>(), 2u32..40), 0..4),
    ) {
        let mut h = nic();
        for (i, value, bits) in bars {
            h = h.bar(i, value, 1 << bits);
        }
        for (at, b) in edits {
            h.bytes[at] = b;
        }
        let m = h.model();
        let f = Function::read(&m, at(0, 2, 0)).unwrap();
        let before = m.header();
        let bars = size(&m, &f);
        prop_assert!(m.violations.borrow().is_empty());
        prop_assert_eq!(m.header(), before);
        if let Ok(p) = Plan::virtio_net(&f, &m, &bars) {
            check(&p, &bars)?;
        }
    }
}

fn check(p: &Plan, bars: &Bars) -> Result<(), TestCaseError> {
    let mut pages = Vec::new();
    for r in &p.regions {
        let bar = bars.memory(r.bar).unwrap();
        prop_assert!(r.length >= r.kind.min_length() && r.length <= crate::virtio::MAX_REGION);
        prop_assert!(r.paddr >= bar.base && r.paddr + u64::from(r.length) <= bar.base + bar.size);
        prop_assert!(r.page() >= bar.base && r.page() + r.pages() * PAGE <= bar.base + bar.size);
        prop_assert!(u64::from(r.in_page()) + u64::from(r.length) <= crate::virtio::REGION_WINDOW);
        pages.extend((0..r.pages()).map(|k| r.page() + k * PAGE));
    }
    let n = pages.len();
    pages.sort_unstable();
    pages.dedup();
    prop_assert_eq!(pages.len(), n, "regions share a page");
    let touched = |start: u64, bytes: u64| start / PAGE..(start + bytes).div_ceil(PAGE);
    for k in touched(p.table, p.msix.table_bytes()).chain(touched(p.pba, p.msix.pba_bytes())) {
        prop_assert!(
            !pages.contains(&(k * PAGE)),
            "a region shares the table's or PBA's page"
        );
    }
    prop_assert!(u64::from(p.entry0_in_page()) + 16 <= PAGE);
    prop_assert!(p.notify_off_multiplier % 2 == 0);
    prop_assert_eq!(p.page_count() as usize, n);
    Ok(())
}
