//! `pci`'s host tests (`docs/design.md`, "Code and tests", the PCI row):
//! the q35 fixture, synthetic spaces with bridges, bus loops,
//! multi-function devices, capability loops and bad pointers, 64-bit BARs,
//! regions outside a BAR or sharing the MSI-X table's page, and the BAR
//! sizing sequence on a model that fails it if decode is on; then random
//! spaces. Every test runs under Miri, the proptests with fewer cases.

mod bars;
mod model;
mod msix;
mod plan;
mod props;
mod q35;
mod scan;
