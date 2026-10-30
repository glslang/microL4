//! The kernel device window (`docs/design.md`, "The kernel half"): one page
//! table of 4 KiB uncached pages at the top of the address space, through
//! which, and only through which, the kernel reaches the local APIC, the I/O
//! APICs and the HPET.

/// The window's first byte: the last 2 MiB of the address space.
pub const KERNEL_DEVICE_BASE: u64 = 0xFFFF_FFFF_FFE0_0000;
/// The local APIC's page.
pub const LAPIC_PAGE: usize = 0;
/// I/O APIC `i`'s page, `i` < [`MAX_IOAPICS`], in MADT order.
pub const fn ioapic_page(i: usize) -> usize {
    1 + i
}
/// The most I/O APICs the window maps; a MADT with more is a boot panic.
pub const MAX_IOAPICS: usize = 4;
/// The HPET's page.
pub const HPET_PAGE: usize = 5;
/// Pages the window maps; the rest of its page table is empty.
pub const PAGES: usize = 6;

/// The 4 KiB physical page each window page maps, if any. A device's
/// registers are at its page's virtual address plus their offset in the
/// page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceWindow {
    pub pages: [Option<u64>; PAGES],
}

impl DeviceWindow {
    /// The virtual address of window page `page`.
    pub const fn virt(page: usize) -> u64 {
        KERNEL_DEVICE_BASE + (page as u64) * 4096
    }

    /// The virtual address at which the window maps physical address
    /// `phys`, if a window page holds it.
    pub fn virt_of(&self, phys: u64) -> Option<u64> {
        let page = phys & !0xFFF;
        self.pages
            .iter()
            .position(|p| *p == Some(page))
            .map(|i| Self::virt(i) + (phys & 0xFFF))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_the_design() {
        assert_eq!(DeviceWindow::virt(LAPIC_PAGE), 0xFFFF_FFFF_FFE0_0000);
        assert_eq!(DeviceWindow::virt(ioapic_page(0)), 0xFFFF_FFFF_FFE0_1000);
        assert_eq!(
            DeviceWindow::virt(ioapic_page(MAX_IOAPICS - 1)),
            0xFFFF_FFFF_FFE0_4000
        );
        assert_eq!(DeviceWindow::virt(HPET_PAGE), 0xFFFF_FFFF_FFE0_5000);
        assert!(ioapic_page(MAX_IOAPICS - 1) < HPET_PAGE && HPET_PAGE < PAGES);
    }

    #[test]
    fn virt_of_keeps_the_offset() {
        let mut w = DeviceWindow::default();
        w.pages[LAPIC_PAGE] = Some(0xFEE0_0000);
        w.pages[HPET_PAGE] = Some(0xFED0_0000);
        assert_eq!(w.virt_of(0xFEE0_00B0), Some(KERNEL_DEVICE_BASE + 0xB0));
        assert_eq!(
            w.virt_of(0xFED0_00F0),
            Some(DeviceWindow::virt(HPET_PAGE) + 0xF0)
        );
        assert_eq!(w.virt_of(0xFEC0_0000), None);
    }
}
