//! The reference model of the capability core.
//!
//! Plain maps and vectors, no cleverness and no performance tricks:
//!
//! - **Objects** are every object from boot and retype, never removed, so an
//!   [`ObjId`] names one incarnation for good. An object is live while some
//!   slot's entry names it.
//! - **Slots** map a slot address to an [`Entry`]: its capability, whether it
//!   is original, its depth, the object it names, its parent and its ordered
//!   children. An absent key is an empty slot.
//! - **The derivation forest** is explicit. A child of an original source
//!   becomes its first child; a copy of a plain copy becomes a sibling right
//!   after its source; deleting an entry splices its children into its
//!   parent's child list at its place; Move and swaps carry an entry, with its
//!   place, to the new address. An entry whose ancestors are all deleted sits
//!   at the top of its derivation list ([`Parent::List`]), in order, so the
//!   preorder of each list is the order the implementation's linked list must
//!   have (`docs/design.md`, "Derivation tracking"; ADR 0012).
//!
//! Every operation is atomic. Deletion transliterates the Zombie algorithm of
//! `docs/design.md`, "Deletion and finalisation", which is seL4's
//! `cteDelete`, `finaliseSlot`, `reduceZombie` and `capSwapForDelete`
//! (`src/object/cnode.c`), keeping its recursion: here the recursion is the
//! specification, not a risk.
//!
//! The model records the hook calls the kernel would see, as
//! [`l4core::testing::Event`] values, and answers `finalise` as
//! [`l4core::testing::TestKernel`] does: a cleanup capability only for the
//! last IRQHandler capability.

use std::collections::{BTreeMap, BTreeSet};

use l4core::cap::{
    Cap, CapType, ENDPOINT_BITS, FRAME_2M_BITS, FRAME_4K_BITS, MAX_CNODE_RADIX,
    MAX_DERIVATION_DEPTH, MAX_UNTYPED_BITS, MIN_CNODE_RADIX, MIN_UNTYPED_BITS, NOTIFICATION_BITS,
    PAGING_STRUCTURE_BITS, RETYPE_FAN_OUT_LIMIT, Rights, SLOT_BITS, SLOT_SIZE, TCB_BITS,
    TCB_SLOT_REPLY, TCB_SLOTS,
};
use l4core::cdt::DepthExceeded;
use l4core::error::{LookupFailure, SyscallError};
use l4core::slot::SlotAddr;
use l4core::testing::Event;
use l4core::untyped::RetypeArgs;

/// An object's index in [`Model::objects`]; never reused.
pub type ObjId = usize;

/// A kernel object with memory, made at boot or by retype.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// The type of capability that names it.
    pub ty: CapType,
    pub paddr: u64,
    pub size_bits: u32,
    pub device: bool,
    /// The untyped it was retyped from; `None` for boot objects.
    pub from: Option<ObjId>,
}

impl Object {
    /// The first byte past the object.
    pub fn end(&self) -> u64 {
        self.paddr + (1u64 << self.size_bits)
    }
}

/// Where an entry hangs in the derivation forest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parent {
    /// At the top of derivation list `id`: a root, or an entry whose
    /// ancestors have all been deleted.
    List(u64),
    /// A child of the entry in this slot.
    Slot(SlotAddr),
}

/// A non-empty slot.
#[derive(Clone, Debug)]
pub struct Entry {
    pub cap: Cap,
    /// The capability may have children.
    pub original: bool,
    /// Depth in its tree, counting deleted ancestors; only ever set at
    /// insertion.
    pub depth: u32,
    pub parent: Parent,
    /// In preorder.
    pub children: Vec<SlotAddr>,
    /// The object the capability names: a Zombie names its container and a
    /// reply capability its TCB. `None` for capabilities without memory.
    pub obj: Option<ObjId>,
    /// Unique per inserted capability and kept through moves, swaps and the
    /// change to a Zombie, so a step can follow one capability.
    pub uid: u64,
}

/// A slot address that no real slot has (fake memory starts far above it),
/// used to park an entry while two entries swap places.
fn parked() -> SlotAddr {
    SlotAddr::new(SLOT_SIZE).unwrap()
}

/// The slot `index` slots after `base`.
pub fn slot_at(base: u64, index: u64) -> SlotAddr {
    SlotAddr::new(base + index * SLOT_SIZE).expect("slot address")
}

/// A mask of the low `bits` bits; `bits` may be 64.
fn low_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// The `width` bits of `cptr` just below bit `top`.
fn field(cptr: u64, top: u32, width: u32) -> u64 {
    debug_assert!(width <= top && top <= 64);
    let mask = (1u128 << width) - 1;
    (((cptr as u128) >> (top - width)) & mask) as u64
}

fn missing_source() -> SyscallError {
    SyscallError::FailedLookup {
        source: true,
        failure: LookupFailure::MissingCapability { bits_left: 0 },
    }
}

/// An `Untyped_Retype` object type (`docs/abi.md`, "Object types and
/// sizes").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Untyped,
    Tcb,
    Endpoint,
    Notification,
    CNode,
    Frame4K,
    Frame2M,
    PageTable,
    PageDirectory,
    Pdpt,
    Pml4,
}

impl Kind {
    fn from_number(n: u64) -> Option<Kind> {
        Some(match n {
            0 => Kind::Untyped,
            1 => Kind::Tcb,
            2 => Kind::Endpoint,
            3 => Kind::Notification,
            4 => Kind::CNode,
            5 => Kind::Frame4K,
            6 => Kind::Frame2M,
            7 => Kind::PageTable,
            8 => Kind::PageDirectory,
            9 => Kind::Pdpt,
            10 => Kind::Pml4,
            _ => return None,
        })
    }

    /// log2 of the object's size, once `size_bits` has passed its range
    /// check.
    fn object_bits(self, size_bits: u64) -> u32 {
        match self {
            Kind::Untyped => size_bits as u32,
            Kind::CNode => size_bits as u32 + SLOT_BITS,
            Kind::Tcb => TCB_BITS,
            Kind::Endpoint => ENDPOINT_BITS,
            Kind::Notification => NOTIFICATION_BITS,
            Kind::Frame4K => FRAME_4K_BITS,
            Kind::Frame2M => FRAME_2M_BITS,
            Kind::PageTable | Kind::PageDirectory | Kind::Pdpt | Kind::Pml4 => {
                PAGING_STRUCTURE_BITS
            }
        }
    }

    /// Device untyped yields only Frames and device untyped.
    fn allowed_from_device(self) -> bool {
        matches!(self, Kind::Untyped | Kind::Frame4K | Kind::Frame2M)
    }

    /// The capability retype makes: every right the type uses, the device
    /// bit of the untyped for memory types, and a new untyped's watermark 0.
    fn new_cap(self, paddr: u64, bits: u32, device: bool) -> Cap {
        let rw = Rights(Rights::WRITE.0 | Rights::READ.0);
        let plain = |ty| Cap::new(ty, paddr, bits, Rights::NONE, false, 0);
        match self {
            Kind::Untyped => Cap::untyped(paddr, bits, device, 0),
            Kind::CNode => Cap::cnode(paddr, bits - SLOT_BITS, 0, 0),
            Kind::Tcb => plain(CapType::Tcb),
            Kind::Endpoint => Cap::new(CapType::Endpoint, paddr, bits, Rights::ALL, false, 0),
            Kind::Notification => Cap::new(CapType::Notification, paddr, bits, rw, false, 0),
            Kind::Frame4K | Kind::Frame2M => Cap::new(CapType::Frame, paddr, bits, rw, device, 0),
            Kind::PageTable => plain(CapType::PageTable),
            Kind::PageDirectory => plain(CapType::PageDirectory),
            Kind::Pdpt => plain(CapType::Pdpt),
            Kind::Pml4 => plain(CapType::Pml4),
        }
    }
}

/// The data word of Mint, Mutate and Rotate on a CNode capability: guard
/// size in bits 0 to 5, guard above; `guard_size + radix` must fit 64.
fn with_guard(cap: Cap, data: u64) -> Result<Cap, SyscallError> {
    let guard_size = (data & 0x3F) as u32;
    if guard_size + cap.radix() > 64 {
        return Err(SyscallError::IllegalOperation);
    }
    let guard = (data >> 6) & low_mask(guard_size);
    Ok(cap.with_data(guard_size as u64 | (guard << 6)))
}

/// A Mint data word applied to a derived capability (`docs/abi.md`,
/// "Capability data"): the capability, and whether the data makes it
/// original (a new badge).
fn mint_data(cap: Cap, data: u64) -> Result<(Cap, bool), SyscallError> {
    match cap.cap_type() {
        CapType::Endpoint | CapType::Notification => {
            if cap.badge() != 0 {
                Err(SyscallError::IllegalOperation)
            } else if data == 0 {
                Ok((cap, false))
            } else {
                Ok((cap.with_data(data), true))
            }
        }
        CapType::CNode => Ok((with_guard(cap, data)?, false)),
        // Narrowing a Hypervisor capability is M9 (`docs/design.md`,
        // Derivation tracking, "Built when"); until then only data 0, a
        // Copy, is defined.
        CapType::Hypervisor if data != 0 => Err(SyscallError::IllegalOperation),
        _ => Ok((cap, false)),
    }
}

/// A Mutate or Rotate data word (`docs/abi.md`, "Capability data").
fn mutate_data(cap: Cap, data: u64) -> Result<Cap, SyscallError> {
    match cap.cap_type() {
        CapType::Endpoint | CapType::Notification => Err(SyscallError::IllegalOperation),
        CapType::CNode => with_guard(cap, data),
        CapType::Hypervisor if data != 0 => Err(SyscallError::IllegalOperation),
        _ => Ok(cap),
    }
}

/// Whether what finalisation leaves lets the slot `at` empty: nothing, or a
/// Zombie with nothing left to clear, or with only itself left in its own
/// container's slot 0 (seL4 `capRemovable`).
fn removable(rest: Cap, at: SlotAddr) -> bool {
    match rest.cap_type() {
        CapType::Null => true,
        CapType::Zombie => {
            let n = rest.zombie_slots();
            n == 0 || (n == 1 && rest.object() == at.get())
        }
        other => panic!("finalisation left a {other:?}"),
    }
}

/// Whether `rest` is a Zombie in its own container's slot 0 (seL4
/// `capCyclicZombie`).
fn cyclic(rest: Cap, at: SlotAddr) -> bool {
    rest.cap_type() == CapType::Zombie && rest.object() == at.get()
}

/// The reference model.
#[derive(Clone, Debug, Default)]
pub struct Model {
    slots: BTreeMap<SlotAddr, Entry>,
    /// The top-level entries of each derivation list, in order.
    lists: BTreeMap<u64, Vec<SlotAddr>>,
    objects: Vec<Object>,
    events: Vec<Event>,
    /// How often each object was finalised as the last capability of each
    /// type (a TCB counts once as `Tcb`, and its master once as `Reply`).
    finalised: BTreeMap<(ObjId, CapType), u32>,
    next_list: u64,
    next_uid: u64,
}

impl Model {
    pub fn new() -> Model {
        Model::default()
    }

    // Objects.

    /// Records a new object.
    pub fn add_object(
        &mut self,
        ty: CapType,
        paddr: u64,
        size_bits: u32,
        device: bool,
        from: Option<ObjId>,
    ) -> ObjId {
        self.objects.push(Object {
            ty,
            paddr,
            size_bits,
            device,
            from,
        });
        self.objects.len() - 1
    }

    /// Every object ever made.
    pub fn objects(&self) -> &[Object] {
        &self.objects
    }

    /// The live objects: those some slot names.
    pub fn referenced(&self) -> BTreeSet<ObjId> {
        self.slots.values().filter_map(|e| e.obj).collect()
    }

    /// How often `id` was finalised as the last capability of type `ty`.
    pub fn finalised(&self, id: ObjId, ty: CapType) -> u32 {
        self.finalised.get(&(id, ty)).copied().unwrap_or(0)
    }

    /// The first slot and slot count of every live CNode and TCB.
    pub fn containers(&self) -> Vec<(SlotAddr, u64)> {
        self.referenced()
            .into_iter()
            .filter_map(|id| {
                let o = &self.objects[id];
                match o.ty {
                    CapType::CNode => {
                        Some((slot_at(o.paddr, 0), 1u64 << (o.size_bits - SLOT_BITS)))
                    }
                    CapType::Tcb => Some((slot_at(o.paddr, 0), TCB_SLOTS)),
                    _ => None,
                }
            })
            .collect()
    }

    // Slots and the forest.

    /// The capability in `at`; Null if empty.
    pub fn cap(&self, at: SlotAddr) -> Cap {
        self.slots.get(&at).map_or(Cap::NULL, |e| e.cap)
    }

    pub fn entry(&self, at: SlotAddr) -> Option<&Entry> {
        self.slots.get(&at)
    }

    /// Every non-empty slot.
    pub fn entries(&self) -> &BTreeMap<SlotAddr, Entry> {
        &self.slots
    }

    /// The nearest surviving ancestor of the capability in `at`.
    pub fn parent(&self, at: SlotAddr) -> Option<SlotAddr> {
        match self.slots.get(&at)?.parent {
            Parent::Slot(p) => Some(p),
            Parent::List(_) => None,
        }
    }

    pub fn has_children(&self, at: SlotAddr) -> bool {
        self.slots.get(&at).is_some_and(|e| !e.children.is_empty())
    }

    /// Whether no other capability anywhere names the same object.
    pub fn is_final(&self, at: SlotAddr) -> bool {
        let cap = self.cap(at);
        !self
            .slots
            .iter()
            .any(|(&s, e)| s != at && e.cap.same_object(&cap))
    }

    /// Every derivation list in preorder, which is the order of the
    /// implementation's linked list.
    pub fn lists(&self) -> Vec<Vec<SlotAddr>> {
        self.lists
            .values()
            .map(|tops| {
                let mut out = Vec::new();
                let mut stack: Vec<SlotAddr> = tops.iter().rev().copied().collect();
                while let Some(s) = stack.pop() {
                    out.push(s);
                    stack.extend(self.slots[&s].children.iter().rev().copied());
                }
                out
            })
            .collect()
    }

    /// The hook calls since the last call.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    fn siblings_mut(&mut self, p: Parent) -> &mut Vec<SlotAddr> {
        match p {
            Parent::List(id) => self.lists.get_mut(&id).expect("derivation list"),
            Parent::Slot(s) => &mut self.slots.get_mut(&s).expect("parent entry").children,
        }
    }

    fn new_entry(
        &mut self,
        cap: Cap,
        original: bool,
        depth: u32,
        parent: Parent,
        obj: Option<ObjId>,
    ) -> Entry {
        self.next_uid += 1;
        Entry {
            cap,
            original,
            depth,
            parent,
            children: Vec::new(),
            obj,
            uid: self.next_uid,
        }
    }

    /// Puts `cap` in the empty slot `at` as the root of a list of its own.
    pub fn insert_root(&mut self, at: SlotAddr, cap: Cap, obj: Option<ObjId>) {
        assert!(!self.slots.contains_key(&at), "root into a full slot");
        let id = self.next_list;
        self.next_list += 1;
        self.lists.insert(id, vec![at]);
        let e = self.new_entry(cap, true, 0, Parent::List(id), obj);
        self.slots.insert(at, e);
    }

    /// Puts `cap`, derived from the capability in `src`, in the empty slot
    /// `dst`: the first child of an original source, or a sibling right after
    /// a plain copy. Only a child can be too deep.
    pub fn insert_derived(
        &mut self,
        src: SlotAddr,
        dst: SlotAddr,
        cap: Cap,
        original: bool,
        obj: Option<ObjId>,
    ) -> Result<(), DepthExceeded> {
        assert!(
            src != dst && !self.slots.contains_key(&dst),
            "derive into a full slot"
        );
        let s = &self.slots[&src];
        let (depth, parent, child) = if s.original {
            (s.depth + 1, Parent::Slot(src), true)
        } else {
            (s.depth, s.parent, false)
        };
        if depth > MAX_DERIVATION_DEPTH {
            return Err(DepthExceeded);
        }
        let sib = self.siblings_mut(parent);
        let pos = if child {
            0
        } else {
            sib.iter().position(|&x| x == src).unwrap() + 1
        };
        sib.insert(pos, dst);
        let e = self.new_entry(cap, original, depth, parent, obj);
        self.slots.insert(dst, e);
        Ok(())
    }

    /// Removes the entry in `at`, splicing its children into its parent's
    /// child list at its place.
    fn unlink(&mut self, at: SlotAddr) {
        let e = self.slots.remove(&at).expect("unlink an empty slot");
        let sib = self.siblings_mut(e.parent);
        let i = sib.iter().position(|&x| x == at).unwrap();
        sib.splice(i..=i, e.children.iter().copied());
        for c in &e.children {
            self.slots.get_mut(c).unwrap().parent = e.parent;
        }
        if let Parent::List(id) = e.parent
            && self.lists[&id].is_empty()
        {
            self.lists.remove(&id);
        }
    }

    /// Moves the entry in `from`, with its place in the forest, to the empty
    /// slot `to`.
    fn rename(&mut self, from: SlotAddr, to: SlotAddr) {
        assert!(!self.slots.contains_key(&to), "move into a full slot");
        let e = self.slots.remove(&from).expect("move an empty slot");
        let sib = self.siblings_mut(e.parent);
        let i = sib.iter().position(|&x| x == from).unwrap();
        sib[i] = to;
        for c in &e.children {
            self.slots.get_mut(c).unwrap().parent = Parent::Slot(to);
        }
        self.slots.insert(to, e);
    }

    /// Moves `cap` (the capability in `src`, perhaps with new data) to the
    /// empty slot `dst` with its place in the forest.
    fn move_slot(&mut self, cap: Cap, src: SlotAddr, dst: SlotAddr) {
        self.rename(src, dst);
        self.slots.get_mut(&dst).unwrap().cap = cap;
        self.events.push(Event::Moved {
            cap,
            from: src,
            to: dst,
        });
    }

    /// Swaps two slots, each entry with its place: `cap1`, from `slot1`,
    /// goes to `slot2` and `cap2` to `slot1`. Either may be empty.
    fn swap_slots(&mut self, cap1: Cap, slot1: SlotAddr, cap2: Cap, slot2: SlotAddr) {
        assert!(slot1 != slot2);
        let has1 = self.slots.contains_key(&slot1);
        let has2 = self.slots.contains_key(&slot2);
        if has1 {
            self.rename(slot1, parked());
        }
        if has2 {
            self.rename(slot2, slot1);
            self.slots.get_mut(&slot1).unwrap().cap = cap2;
            self.events.push(Event::Moved {
                cap: cap2,
                from: slot2,
                to: slot1,
            });
        }
        if has1 {
            self.rename(parked(), slot2);
            self.slots.get_mut(&slot2).unwrap().cap = cap1;
            self.events.push(Event::Moved {
                cap: cap1,
                from: slot1,
                to: slot2,
            });
        }
    }

    // Derivation: Copy, Mint and their checks.

    /// seL4's `deriveCap`: the capability a copy of the one in `src` starts
    /// as. Refuses what cannot be copied and an untyped with children; a
    /// Frame copy is unmapped (its mapping record cleared).
    pub fn derive(&self, src: SlotAddr) -> Result<Cap, SyscallError> {
        let cap = self.cap(src);
        match cap.cap_type() {
            CapType::Null
            | CapType::Zombie
            | CapType::Reply
            | CapType::IrqControl
            | CapType::IoPortControl
            | CapType::Pdpt
            | CapType::PageDirectory
            | CapType::PageTable => Err(SyscallError::IllegalOperation),
            CapType::Untyped if self.has_children(src) => Err(SyscallError::RevokeFirst),
            CapType::Frame => Ok(cap.with_data(0)),
            _ => Ok(cap),
        }
    }

    /// Inserts a derived capability. A copied untyped keeps the source's
    /// watermark and the source's goes to its size (seL4
    /// `setUntypedCapAsFull`).
    fn install(
        &mut self,
        src: SlotAddr,
        dst: SlotAddr,
        cap: Cap,
        original: bool,
    ) -> Result<(), SyscallError> {
        let obj = self.slots[&src].obj;
        self.insert_derived(src, dst, cap, original, obj)
            .map_err(|DepthExceeded| SyscallError::IllegalOperation)?;
        if cap.cap_type() == CapType::Untyped {
            let e = self.slots.get_mut(&src).unwrap();
            e.cap = e.cap.with_data(1u64 << e.cap.size_bits());
        }
        Ok(())
    }

    fn masked(cap: Cap, rights: u64) -> Cap {
        cap.with_rights(Rights(cap.rights().0 & (rights & 0xF) as u8))
    }

    /// `CNode_Copy`, after slot lookup.
    pub fn copy(&mut self, src: SlotAddr, dst: SlotAddr, rights: u64) -> Result<(), SyscallError> {
        if !self.cap(dst).is_null() {
            return Err(SyscallError::DeleteFirst);
        }
        if self.cap(src).is_null() {
            return Err(missing_source());
        }
        let cap = Self::masked(self.derive(src)?, rights);
        let original = cap.cap_type() == CapType::Untyped;
        self.install(src, dst, cap, original)
    }

    /// `CNode_Mint`, after slot lookup.
    pub fn mint(
        &mut self,
        src: SlotAddr,
        dst: SlotAddr,
        rights: u64,
        data: u64,
    ) -> Result<(), SyscallError> {
        if !self.cap(dst).is_null() {
            return Err(SyscallError::DeleteFirst);
        }
        if self.cap(src).is_null() {
            return Err(missing_source());
        }
        let cap = Self::masked(self.derive(src)?, rights);
        let (cap, badged) = mint_data(cap, data)?;
        let original = badged || cap.cap_type() == CapType::Untyped;
        self.install(src, dst, cap, original)
    }

    /// A derived copy installed outside a CNode invocation, as the TCB
    /// installs of M5 do: `derive`, then a plain (not original) insert.
    pub fn derive_into(&mut self, src: SlotAddr, dst: SlotAddr) -> Result<(), SyscallError> {
        let cap = self.derive(src)?;
        assert!(
            cap.cap_type() != CapType::Untyped,
            "derive_into takes no untyped"
        );
        let obj = self.slots[&src].obj;
        self.insert_derived(src, dst, cap, false, obj)
            .map_err(|DepthExceeded| SyscallError::IllegalOperation)
    }

    /// Writes the mapping record of the Frame or paging structure in `at`, as
    /// `l4core::vspace` will when it maps one (M5).
    pub fn set_mapping(&mut self, at: SlotAddr, record: u64) {
        let e = self.slots.get_mut(&at).expect("map an empty slot");
        assert!(matches!(
            e.cap.cap_type(),
            CapType::Frame | CapType::PageTable | CapType::PageDirectory | CapType::Pdpt
        ));
        e.cap = e.cap.with_data(record);
    }

    // Move, Mutate, Rotate.

    /// `CNode_Move`, after slot lookup.
    pub fn move_cap(&mut self, src: SlotAddr, dst: SlotAddr) -> Result<(), SyscallError> {
        if !self.cap(dst).is_null() {
            return Err(SyscallError::DeleteFirst);
        }
        if self.cap(src).is_null() {
            return Err(missing_source());
        }
        let cap = self.cap(src);
        self.move_slot(cap, src, dst);
        Ok(())
    }

    /// `CNode_Mutate`, after slot lookup.
    pub fn mutate(&mut self, src: SlotAddr, dst: SlotAddr, data: u64) -> Result<(), SyscallError> {
        if !self.cap(dst).is_null() {
            return Err(SyscallError::DeleteFirst);
        }
        if self.cap(src).is_null() {
            return Err(missing_source());
        }
        let cap = mutate_data(self.cap(src), data)?;
        self.move_slot(cap, src, dst);
        Ok(())
    }

    /// `CNode_Rotate`, after slot lookup: the pivot's capability, with
    /// `dst_data`, to `dst`; the source's, with `pivot_data`, to the pivot. A
    /// swap when `dst` is `src`.
    pub fn rotate(
        &mut self,
        dst: SlotAddr,
        dst_data: u64,
        pivot: SlotAddr,
        pivot_data: u64,
        src: SlotAddr,
    ) -> Result<(), SyscallError> {
        if pivot == src || pivot == dst {
            return Err(SyscallError::IllegalOperation);
        }
        if dst != src && !self.cap(dst).is_null() {
            return Err(SyscallError::DeleteFirst);
        }
        if self.cap(src).is_null() || self.cap(pivot).is_null() {
            return Err(missing_source());
        }
        let new_src = mutate_data(self.cap(src), pivot_data)?;
        let new_pivot = mutate_data(self.cap(pivot), dst_data)?;
        if dst == src {
            self.swap_slots(new_src, src, new_pivot, pivot);
        } else {
            self.move_slot(new_pivot, pivot, dst);
            self.move_slot(new_src, src, pivot);
        }
        Ok(())
    }

    // Delete and revoke.

    /// `CNode_Delete`, after slot lookup: an exposed deletion.
    pub fn delete(&mut self, at: SlotAddr) {
        self.cte_delete(at, true);
    }

    /// `CNode_Revoke`, after slot lookup: deletes the first remaining
    /// descendant, in preorder, until there is none, re-reading `at` each
    /// time.
    pub fn revoke(&mut self, at: SlotAddr) {
        while let Some(&first) = self.slots.get(&at).and_then(|e| e.children.first()) {
            self.cte_delete(first, true);
        }
    }

    /// seL4's `cteDelete`.
    fn cte_delete(&mut self, at: SlotAddr, exposed: bool) {
        let (success, cleanup) = self.finalise_slot(at, exposed);
        if exposed || success {
            self.empty_slot(at, cleanup);
        }
    }

    /// seL4's `finaliseSlot`: finalises the capability in `at` until the slot
    /// can be emptied. `false` only when a nested deletion leaves a Zombie in
    /// its own container's slot 0.
    fn finalise_slot(&mut self, at: SlotAddr, immediate: bool) -> (bool, Option<Cap>) {
        loop {
            let cap = self.cap(at);
            if cap.is_null() {
                return (true, None);
            }
            let last = self.is_final(at);
            let (rest, cleanup) = self.finalise_cap(at, cap, last);
            if removable(rest, at) {
                return (true, cleanup);
            }
            // The capability becomes, in place, a Zombie, keeping its node.
            self.slots.get_mut(&at).unwrap().cap = rest;
            if !immediate && cyclic(rest, at) {
                return (false, cleanup);
            }
            self.reduce_zombie(at, immediate);
        }
    }

    /// seL4's `finaliseCap`: what deleting `cap` leaves in its slot, and the
    /// cleanup to pass on. The kernel's finalise hook runs for every type
    /// but CNode and Zombie.
    fn finalise_cap(&mut self, at: SlotAddr, cap: Cap, last: bool) -> (Cap, Option<Cap>) {
        match cap.cap_type() {
            CapType::CNode => {
                let rest = if last {
                    Cap::zombie(cap.object(), cap.size_bits(), 1u64 << cap.radix(), false)
                } else {
                    Cap::NULL
                };
                (rest, None)
            }
            CapType::Zombie => (cap, None),
            CapType::Tcb => {
                let cleanup = self.finalise_hook(at, cap, last);
                let rest = if last {
                    Cap::zombie(cap.object(), cap.size_bits(), TCB_SLOTS, true)
                } else {
                    Cap::NULL
                };
                (rest, cleanup)
            }
            _ => (Cap::NULL, self.finalise_hook(at, cap, last)),
        }
    }

    /// The kernel's finalise hook, answered as `TestKernel` answers it.
    fn finalise_hook(&mut self, at: SlotAddr, cap: Cap, last: bool) -> Option<Cap> {
        self.events.push(Event::Finalise { cap, last });
        if last
            && cap.cap_type() != CapType::Untyped
            && let Some(id) = self.slots[&at].obj
        {
            *self.finalised.entry((id, cap.cap_type())).or_default() += 1;
        }
        (last && cap.cap_type() == CapType::IrqHandler).then_some(cap)
    }

    /// seL4's `reduceZombie`. Exposed: deletes the highest slot left, nested,
    /// and counts it. Nested: swaps the Zombie into its container's slot 0,
    /// so the caller goes on with what was there.
    fn reduce_zombie(&mut self, at: SlotAddr, immediate: bool) {
        let z = self.cap(at);
        assert_eq!(z.cap_type(), CapType::Zombie);
        let ptr = z.object();
        let n = z.zombie_slots();
        let tcb = z.zombie_is_tcb();
        assert!(n > 0, "reducing a finished Zombie");
        if immediate {
            let end = slot_at(ptr, n - 1);
            self.cte_delete(end, false);
            let now = self.cap(at);
            match now.cap_type() {
                CapType::Null => {}
                CapType::Zombie
                    if now.object() == ptr
                        && now.zombie_slots() == n
                        && now.zombie_is_tcb() == tcb =>
                {
                    assert!(self.cap(end).is_null(), "cleared slot not empty");
                    self.slots.get_mut(&at).unwrap().cap = now.with_zombie_slots(n - 1);
                }
                CapType::Zombie => {
                    assert!(
                        now.object() == at.get() && ptr != at.get(),
                        "expected a self-referential Zombie"
                    );
                }
                other => panic!("clearing a container left a {other:?} behind"),
            }
        } else {
            assert!(ptr != at.get(), "cyclic Zombie in a nested reduce");
            let p = slot_at(ptr, 0);
            let there = self.cap(p);
            if there.cap_type() == CapType::Zombie {
                assert!(
                    there.object() != ptr,
                    "moving a self-referential Zombie aside"
                );
            }
            self.swap_slots(there, p, z, at);
        }
    }

    /// seL4's `emptySlot`.
    fn empty_slot(&mut self, at: SlotAddr, cleanup: Option<Cap>) {
        if !self.cap(at).is_null() {
            self.unlink(at);
            if let Some(c) = cleanup {
                self.events.push(Event::AfterDelete(c));
            }
        }
    }

    // Retype.

    /// `Untyped_Retype` after slot lookup: `dest` is the capability the
    /// destination lookup found. Checks in `docs/abi.md`'s order, then
    /// `docs/design.md`, "Retype", steps 1 to 6.
    pub fn retype(
        &mut self,
        untyped: SlotAddr,
        dest: Cap,
        args: RetypeArgs,
    ) -> Result<(), SyscallError> {
        let ut = self.cap(untyped);
        assert_eq!(ut.cap_type(), CapType::Untyped, "retype of a non-untyped");
        let kind = Kind::from_number(args.object_type).ok_or(SyscallError::InvalidArgument(0))?;
        match kind {
            Kind::Untyped
                if !(MIN_UNTYPED_BITS as u64..=MAX_UNTYPED_BITS as u64)
                    .contains(&args.size_bits) =>
            {
                return Err(SyscallError::RangeError {
                    min: MIN_UNTYPED_BITS as u64,
                    max: MAX_UNTYPED_BITS as u64,
                });
            }
            Kind::CNode
                if !(MIN_CNODE_RADIX as u64..=MAX_CNODE_RADIX as u64).contains(&args.size_bits) =>
            {
                return Err(SyscallError::RangeError {
                    min: MIN_CNODE_RADIX as u64,
                    max: MAX_CNODE_RADIX as u64,
                });
            }
            _ => {}
        }
        if dest.cap_type() != CapType::CNode {
            return Err(SyscallError::FailedLookup {
                source: false,
                failure: LookupFailure::MissingCapability { bits_left: 0 },
            });
        }
        let nslots = 1u64 << dest.radix();
        if args.node_offset > nslots - 1 {
            return Err(SyscallError::RangeError {
                min: 0,
                max: nslots - 1,
            });
        }
        if args.num_objects < 1 || args.num_objects > RETYPE_FAN_OUT_LIMIT {
            return Err(SyscallError::RangeError {
                min: 1,
                max: RETYPE_FAN_OUT_LIMIT,
            });
        }
        if args.num_objects > nslots - args.node_offset {
            return Err(SyscallError::RangeError {
                min: 1,
                max: nslots - args.node_offset,
            });
        }
        let dests: Vec<SlotAddr> = (0..args.num_objects)
            .map(|i| slot_at(dest.object(), args.node_offset + i))
            .collect();
        if dests.iter().any(|&d| !self.cap(d).is_null()) {
            return Err(SyscallError::DeleteFirst);
        }
        // Step 1: with no children, start at 0 (after a reset).
        let start = if self.has_children(untyped) {
            ut.watermark()
        } else {
            0
        };
        let size = 1u64 << ut.size_bits();
        let bits = kind.object_bits(args.size_bits);
        // Step 2.
        let free = size - start;
        if (free >> bits) < args.num_objects {
            return Err(SyscallError::NotEnoughMemory(free));
        }
        // Step 3.
        if ut.is_device() && !kind.allowed_from_device() {
            return Err(SyscallError::InvalidArgument(0));
        }
        if self.slots[&untyped].depth >= MAX_DERIVATION_DEPTH {
            return Err(SyscallError::IllegalOperation);
        }
        // Step 4: the reset is invisible to the model; the watermark moves.
        let aligned = start.div_ceil(1u64 << bits) << bits;
        let watermark = aligned + (args.num_objects << bits);
        self.slots.get_mut(&untyped).unwrap().cap = ut.with_data(watermark);
        // Steps 5 and 6.
        let from = self.slots[&untyped].obj;
        for (i, &d) in dests.iter().enumerate() {
            let paddr = ut.object() + aligned + ((i as u64) << bits);
            let cap = kind.new_cap(paddr, bits, ut.is_device());
            let id = self.add_object(cap.cap_type(), paddr, bits, ut.is_device(), from);
            self.events.push(Event::InitObject(cap));
            self.insert_derived(untyped, d, cap, true, Some(id))
                .expect("depth checked above");
            if kind == Kind::Tcb {
                let master = Cap::reply(paddr, true, true);
                self.insert_root(slot_at(paddr, TCB_SLOT_REPLY), master, Some(id));
            }
        }
        Ok(())
    }

    // Lookups.

    /// `resolve(root, cptr, n)` of `docs/design.md`, "Resolution": the slot
    /// reached and the bits left there.
    pub fn resolve(
        &self,
        root: Cap,
        cptr: u64,
        bits: u32,
    ) -> Result<(SlotAddr, u32), LookupFailure> {
        assert!(bits <= 64);
        if root.cap_type() != CapType::CNode {
            return Err(LookupFailure::InvalidRoot);
        }
        let mut node = root;
        let mut n = bits;
        loop {
            let gs = node.guard_size();
            let radix = node.radix();
            let guard = node.guard();
            if gs > n || field(cptr, n, gs) != guard {
                return Err(LookupFailure::GuardMismatch {
                    bits_left: n,
                    guard,
                    guard_size: gs,
                });
            }
            if radix + gs > n {
                return Err(LookupFailure::DepthMismatch {
                    bits_left: n,
                    bits_found: radix + gs,
                });
            }
            let index = field(cptr, n - gs, radix);
            n -= radix + gs;
            let slot = slot_at(node.object(), index);
            if n == 0 {
                return Ok((slot, 0));
            }
            let next = self.cap(slot);
            if next.cap_type() == CapType::CNode {
                node = next;
            } else {
                return Ok((slot, n));
            }
        }
    }

    /// A capability lookup: 64 bits, bits left ignored.
    pub fn lookup_cap(&self, root: Cap, cptr: u64) -> Result<SlotAddr, LookupFailure> {
        self.resolve(root, cptr, 64).map(|(s, _)| s)
    }

    /// A slot argument: the root must be a CNode, `depth` 1 to 64, and
    /// exactly `depth` bits resolve.
    pub fn lookup_slot(
        &self,
        root: Cap,
        index: u64,
        depth: u64,
        source: bool,
    ) -> Result<SlotAddr, SyscallError> {
        let failed = |failure| SyscallError::FailedLookup { source, failure };
        if root.cap_type() != CapType::CNode {
            return Err(failed(LookupFailure::InvalidRoot));
        }
        if !(1..=64).contains(&depth) {
            return Err(SyscallError::RangeError { min: 1, max: 64 });
        }
        match self.resolve(root, index, depth as u32) {
            Err(f) => Err(failed(f)),
            Ok((slot, 0)) => Ok(slot),
            Ok((_, bits_left)) => Err(failed(LookupFailure::DepthMismatch {
                bits_left,
                bits_found: 0,
            })),
        }
    }
}
