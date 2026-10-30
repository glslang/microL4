//! Capabilities: the two-word representation, types, rights and data words.
//!
//! `docs/design.md`, "Kernel objects", and `docs/abi.md`, "Capabilities",
//! specify everything here. A capability is `data` plus a `header` shared by
//! every type; the all-zero capability is Null, so zeroed memory is a table of
//! empty slots.

/// A CNode slot is `1 << SLOT_BITS` bytes.
pub const SLOT_BITS: u32 = 5;
/// Bytes in one slot.
pub const SLOT_SIZE: u64 = 1 << SLOT_BITS;
/// Smallest untyped, 16 bytes.
pub const MIN_UNTYPED_BITS: u32 = 4;
/// Largest untyped, 128 TiB.
pub const MAX_UNTYPED_BITS: u32 = 47;
/// Smallest CNode, 2 slots.
pub const MIN_CNODE_RADIX: u32 = 1;
/// Largest CNode, `2^47` bytes.
pub const MAX_CNODE_RADIX: u32 = 42;
/// Most objects one `Untyped_Retype` creates.
pub const RETYPE_FAN_OUT_LIMIT: u64 = 256;
/// Deepest derivation a slot can record.
pub const MAX_DERIVATION_DEPTH: u32 = 4095;

/// Size of a TCB, `2^11` bytes.
pub const TCB_BITS: u32 = 11;
/// Size of an endpoint, `2^5` bytes.
pub const ENDPOINT_BITS: u32 = 5;
/// Size of a notification, `2^6` bytes.
pub const NOTIFICATION_BITS: u32 = 6;
/// Size of every paging structure, `2^13` bytes: the hardware table plus its
/// back-references.
pub const PAGING_STRUCTURE_BITS: u32 = 13;
/// A small frame, 4 KiB.
pub const FRAME_4K_BITS: u32 = 12;
/// A large frame, 2 MiB.
pub const FRAME_2M_BITS: u32 = 21;

/// Slots a TCB holds at offset 0.
pub const TCB_SLOTS: u64 = 5;
/// TCB slot holding the CSpace root.
pub const TCB_SLOT_CSPACE: u64 = 0;
/// TCB slot holding the VSpace root.
pub const TCB_SLOT_VSPACE: u64 = 1;
/// TCB slot holding the IPC buffer frame.
pub const TCB_SLOT_IPC_BUFFER: u64 = 2;
/// TCB slot holding the thread's master reply capability.
pub const TCB_SLOT_REPLY: u64 = 3;
/// TCB slot holding the reply capability of the thread's caller.
pub const TCB_SLOT_CALLER: u64 = 4;

/// Highest physical address bit a capability can name: bits 4 to 51.
const OBJECT_ADDR_MASK: u64 = ((1 << 52) - 1) & !0xF;

/// The kernel-internal capability type tag, bits 0 to 4 of the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum CapType {
    /// An empty slot.
    Null = 0,
    /// Untyped memory; `data` is the watermark in bytes from the base.
    Untyped = 1,
    /// A thread control block.
    Tcb = 2,
    /// A synchronous IPC endpoint; `data` is the badge.
    Endpoint = 3,
    /// A notification; `data` is the badge.
    Notification = 4,
    /// A CNode; `data` holds the guard.
    CNode = 5,
    /// A 4 KiB or 2 MiB frame; `data` is the mapping record.
    Frame = 6,
    /// A level-1 paging structure.
    PageTable = 7,
    /// A level-2 paging structure.
    PageDirectory = 8,
    /// A level-3 paging structure.
    Pdpt = 9,
    /// A level-4 paging structure, the root of a VSpace.
    Pml4 = 10,
    /// The interrupt controller, one at boot.
    IrqControl = 11,
    /// The right to one interrupt; `data` is the IRQ.
    IrqHandler = 12,
    /// The I/O port controller, one at boot.
    IoPortControl = 13,
    /// A range of I/O ports; `data` is the range.
    IoPort = 14,
    /// Hyper-V hypercalls and SynIC access.
    Hypervisor = 15,
    /// A reply capability; `data` bit 0 marks a TCB's master.
    Reply = 16,
    /// A CNode or TCB being destroyed; kernel-internal.
    Zombie = 17,
}

impl CapType {
    /// Decodes a tag. Unknown tags decode as Null, so decoding is total.
    pub const fn from_tag(tag: u64) -> CapType {
        match tag {
            1 => CapType::Untyped,
            2 => CapType::Tcb,
            3 => CapType::Endpoint,
            4 => CapType::Notification,
            5 => CapType::CNode,
            6 => CapType::Frame,
            7 => CapType::PageTable,
            8 => CapType::PageDirectory,
            9 => CapType::Pdpt,
            10 => CapType::Pml4,
            11 => CapType::IrqControl,
            12 => CapType::IrqHandler,
            13 => CapType::IoPortControl,
            14 => CapType::IoPort,
            15 => CapType::Hypervisor,
            16 => CapType::Reply,
            17 => CapType::Zombie,
            _ => CapType::Null,
        }
    }
}

/// An object type number, as `Untyped_Retype` takes it (`docs/abi.md`,
/// "Object types and sizes").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum ObjectType {
    Untyped = 0,
    Tcb = 1,
    Endpoint = 2,
    Notification = 3,
    CNode = 4,
    Frame4K = 5,
    Frame2M = 6,
    PageTable = 7,
    PageDirectory = 8,
    Pdpt = 9,
    Pml4 = 10,
}

impl ObjectType {
    /// Every object type, in number order.
    pub const ALL: [ObjectType; 11] = [
        ObjectType::Untyped,
        ObjectType::Tcb,
        ObjectType::Endpoint,
        ObjectType::Notification,
        ObjectType::CNode,
        ObjectType::Frame4K,
        ObjectType::Frame2M,
        ObjectType::PageTable,
        ObjectType::PageDirectory,
        ObjectType::Pdpt,
        ObjectType::Pml4,
    ];

    /// Decodes an object type number; 11 and up are reserved.
    pub const fn from_number(n: u64) -> Option<ObjectType> {
        if n < ObjectType::ALL.len() as u64 {
            Some(ObjectType::ALL[n as usize])
        } else {
            None
        }
    }

    /// The capability type that names an object of this type.
    pub const fn cap_type(self) -> CapType {
        match self {
            ObjectType::Untyped => CapType::Untyped,
            ObjectType::Tcb => CapType::Tcb,
            ObjectType::Endpoint => CapType::Endpoint,
            ObjectType::Notification => CapType::Notification,
            ObjectType::CNode => CapType::CNode,
            ObjectType::Frame4K | ObjectType::Frame2M => CapType::Frame,
            ObjectType::PageTable => CapType::PageTable,
            ObjectType::PageDirectory => CapType::PageDirectory,
            ObjectType::Pdpt => CapType::Pdpt,
            ObjectType::Pml4 => CapType::Pml4,
        }
    }

    /// log2 of the object's size. `size_bits` is the `Untyped_Retype`
    /// argument: an untyped's size, or a CNode's radix; other types ignore it.
    /// The caller has checked it against the type's range.
    pub const fn object_bits(self, size_bits: u32) -> u32 {
        match self {
            ObjectType::Untyped => size_bits,
            ObjectType::Tcb => TCB_BITS,
            ObjectType::Endpoint => ENDPOINT_BITS,
            ObjectType::Notification => NOTIFICATION_BITS,
            ObjectType::CNode => size_bits + SLOT_BITS,
            ObjectType::Frame4K => FRAME_4K_BITS,
            ObjectType::Frame2M => FRAME_2M_BITS,
            ObjectType::PageTable
            | ObjectType::PageDirectory
            | ObjectType::Pdpt
            | ObjectType::Pml4 => PAGING_STRUCTURE_BITS,
        }
    }

    /// The rights a capability made by retype carries: every right its type
    /// uses (`docs/abi.md`, "Rights").
    pub const fn full_rights(self) -> Rights {
        match self {
            ObjectType::Endpoint => Rights::ALL,
            ObjectType::Notification | ObjectType::Frame4K | ObjectType::Frame2M => {
                Rights(Rights::WRITE.0 | Rights::READ.0)
            }
            _ => Rights::NONE,
        }
    }
}

/// A rights word: Write, Read, Grant and GrantReply in bits 0 to 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Rights(pub u8);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const WRITE: Rights = Rights(1);
    pub const READ: Rights = Rights(2);
    pub const GRANT: Rights = Rights(4);
    pub const GRANT_REPLY: Rights = Rights(8);
    pub const ALL: Rights = Rights(0xF);

    /// The rights in a rights word; bits 4 to 63 are ignored.
    pub const fn from_word(word: u64) -> Rights {
        Rights((word & 0xF) as u8)
    }

    /// The rights in both.
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    /// Whether every right in `other` is in `self`.
    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }
}

/// A capability: a per-type data word and a header common to every type.
///
/// | Header bits | Field |
/// | --- | --- |
/// | 0 to 4 | type tag |
/// | 5 to 10 | `size_bits`, log2 of the object's size; 0 without memory |
/// | 11 to 14 | rights |
/// | 15 | device memory |
/// | 16 to 63 | bits 4 to 51 of the object's physical address |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct Cap {
    pub data: u64,
    pub header: u64,
}

const _: () = assert!(core::mem::size_of::<Cap>() == 16);

impl Cap {
    /// The empty capability.
    pub const NULL: Cap = Cap { data: 0, header: 0 };

    /// Builds a capability. `object` must be 16-byte aligned and below
    /// `2^52`; `size_bits` must be below 64.
    pub const fn new(
        ty: CapType,
        object: u64,
        size_bits: u32,
        rights: Rights,
        device: bool,
        data: u64,
    ) -> Cap {
        debug_assert!(object & !OBJECT_ADDR_MASK == 0);
        debug_assert!(size_bits < 64);
        let header = (ty as u64)
            | ((size_bits as u64 & 0x3F) << 5)
            | ((rights.0 as u64 & 0xF) << 11)
            | ((device as u64) << 15)
            | ((object & OBJECT_ADDR_MASK) << 12);
        Cap { data, header }
    }

    /// The type tag; an unknown tag reads as Null.
    pub const fn cap_type(&self) -> CapType {
        CapType::from_tag(self.header & 0x1F)
    }

    /// Whether this is the empty capability's type.
    pub const fn is_null(&self) -> bool {
        matches!(self.cap_type(), CapType::Null)
    }

    /// log2 of the object's size; 0 for capabilities without memory.
    pub const fn size_bits(&self) -> u32 {
        ((self.header >> 5) & 0x3F) as u32
    }

    /// The rights field.
    pub const fn rights(&self) -> Rights {
        Rights(((self.header >> 11) & 0xF) as u8)
    }

    /// Whether the object is device memory (Untyped, Frame).
    pub const fn is_device(&self) -> bool {
        (self.header >> 15) & 1 == 1
    }

    /// The object's physical address; 0 for capabilities without memory.
    pub const fn object(&self) -> u64 {
        (self.header >> 12) & OBJECT_ADDR_MASK
    }

    /// This capability with its rights replaced.
    pub const fn with_rights(self, rights: Rights) -> Cap {
        Cap {
            data: self.data,
            header: (self.header & !(0xF << 11)) | ((rights.0 as u64 & 0xF) << 11),
        }
    }

    /// This capability with its data word replaced.
    pub const fn with_data(self, data: u64) -> Cap {
        Cap {
            data,
            header: self.header,
        }
    }

    /// Whether `self` and `other` name the same object, as seL4's
    /// `sameObjectAs` decides it: same type and address, plus the same size
    /// for Frames, the same IRQ for IRQHandlers and the same range for
    /// IOPorts. Untyped, control and Hypervisor capabilities never share an
    /// object, and neither do Zombies.
    pub fn same_object(&self, other: &Cap) -> bool {
        let ty = self.cap_type();
        if ty != other.cap_type() {
            return false;
        }
        match ty {
            CapType::Null
            | CapType::Untyped
            | CapType::IrqControl
            | CapType::IoPortControl
            | CapType::Hypervisor
            | CapType::Zombie => false,
            CapType::IrqHandler | CapType::IoPort => self.data == other.data,
            CapType::Frame | CapType::CNode => {
                self.object() == other.object() && self.size_bits() == other.size_bits()
            }
            CapType::Tcb
            | CapType::Endpoint
            | CapType::Notification
            | CapType::PageTable
            | CapType::PageDirectory
            | CapType::Pdpt
            | CapType::Pml4
            | CapType::Reply => self.object() == other.object(),
        }
    }

    // Untyped.

    /// An untyped capability with its watermark at `watermark` bytes.
    pub const fn untyped(base: u64, size_bits: u32, device: bool, watermark: u64) -> Cap {
        Cap::new(
            CapType::Untyped,
            base,
            size_bits,
            Rights::NONE,
            device,
            watermark,
        )
    }

    /// An untyped's watermark, in bytes from its base.
    pub const fn watermark(&self) -> u64 {
        self.data
    }

    // Endpoint and Notification.

    /// The badge of an Endpoint or Notification capability; 0 is unbadged.
    pub const fn badge(&self) -> u64 {
        self.data
    }

    // CNode.

    /// A CNode capability for `2^radix` slots at `object`, with a guard.
    pub const fn cnode(object: u64, radix: u32, guard_size: u32, guard: u64) -> Cap {
        Cap::new(
            CapType::CNode,
            object,
            radix + SLOT_BITS,
            Rights::NONE,
            false,
            cnode_data(guard_size, guard),
        )
    }

    /// A CNode capability's radix: its slot count is `2^radix`.
    pub const fn radix(&self) -> u32 {
        self.size_bits().saturating_sub(SLOT_BITS)
    }

    /// A CNode capability's guard size in bits.
    pub const fn guard_size(&self) -> u32 {
        (self.data & 0x3F) as u32
    }

    /// A CNode capability's guard; only its low `guard_size` bits are set.
    pub const fn guard(&self) -> u64 {
        self.data >> 6
    }

    // Reply.

    /// A reply capability naming the TCB at `tcb`.
    pub const fn reply(tcb: u64, master: bool, grant: bool) -> Cap {
        let rights = if grant { Rights::GRANT } else { Rights::NONE };
        Cap::new(CapType::Reply, tcb, TCB_BITS, rights, false, master as u64)
    }

    /// Whether a reply capability is its TCB's master.
    pub const fn is_reply_master(&self) -> bool {
        self.data & 1 == 1
    }

    // Zombie.

    /// A Zombie for the container whose slots start at `container`:
    /// `slots` slots left to clear, `tcb` if the container is a TCB.
    pub const fn zombie(container: u64, size_bits: u32, slots: u64, tcb: bool) -> Cap {
        debug_assert!(slots < (1 << 48));
        Cap::new(
            CapType::Zombie,
            container,
            size_bits,
            Rights::NONE,
            false,
            (slots & ((1 << 48) - 1)) | ((tcb as u64) << 63),
        )
    }

    /// A Zombie's count of slots left to clear.
    pub const fn zombie_slots(&self) -> u64 {
        self.data & ((1 << 48) - 1)
    }

    /// Whether a Zombie's container is a TCB.
    pub const fn zombie_is_tcb(&self) -> bool {
        self.data >> 63 == 1
    }

    /// This Zombie with its count replaced.
    pub const fn with_zombie_slots(self, slots: u64) -> Cap {
        Cap::zombie(self.object(), self.size_bits(), slots, self.zombie_is_tcb())
    }
}

/// The data word of a CNode capability, the layout of seL4's
/// `seL4_CNode_CapData`: guard size in bits 0 to 5, guard in bits 6 to 63.
/// Bits of `guard` above `guard_size` are dropped.
pub const fn cnode_data(guard_size: u32, guard: u64) -> u64 {
    let guard_size = guard_size & 0x3F;
    let guard = guard & low_mask(guard_size);
    (guard_size as u64) | (guard << 6)
}

/// A mask of the low `bits` bits; `bits` may be 64.
pub const fn low_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let cap = Cap::new(
            CapType::Frame,
            0x000F_FFFF_FFFF_F000,
            21,
            Rights::ALL,
            true,
            7,
        );
        assert_eq!(cap.cap_type(), CapType::Frame);
        assert_eq!(cap.object(), 0x000F_FFFF_FFFF_F000);
        assert_eq!(cap.size_bits(), 21);
        assert_eq!(cap.rights(), Rights::ALL);
        assert!(cap.is_device());
        assert_eq!(cap.data, 7);
    }

    #[test]
    fn zero_is_null_and_unknown_tags_decode_as_null() {
        assert!(Cap::NULL.is_null());
        assert!(
            Cap {
                data: 0,
                header: 18
            }
            .is_null()
        );
        assert!(
            Cap {
                data: 5,
                header: 31
            }
            .is_null()
        );
    }

    #[test]
    fn cnode_guard_is_masked() {
        let cap = Cap::cnode(0x1000, 4, 3, 0xFF);
        assert_eq!(cap.radix(), 4);
        assert_eq!(cap.guard_size(), 3);
        assert_eq!(cap.guard(), 0b111);
        let wide = Cap::cnode(0x1000, 4, 60, u64::MAX);
        assert_eq!(wide.guard_size(), 60);
        assert_eq!(wide.guard(), u64::MAX >> 6);
    }

    #[test]
    fn zombie_fields() {
        let z = Cap::zombie(0x2000, TCB_BITS, TCB_SLOTS, true);
        assert_eq!(z.cap_type(), CapType::Zombie);
        assert_eq!(z.object(), 0x2000);
        assert_eq!(z.zombie_slots(), 5);
        assert!(z.zombie_is_tcb());
        assert_eq!(z.with_zombie_slots(4).zombie_slots(), 4);
        assert!(z.with_zombie_slots(4).zombie_is_tcb());
    }

    #[test]
    fn same_object_rules() {
        let f = Cap::new(CapType::Frame, 0x1000, 12, Rights::ALL, false, 0);
        assert!(f.same_object(&f.with_rights(Rights::READ).with_data(9)));
        let big = Cap::new(CapType::Frame, 0x1000, 21, Rights::ALL, false, 0);
        assert!(!f.same_object(&big));
        let u = Cap::untyped(0x1000, 12, false, 0);
        assert!(!u.same_object(&u));
        let ep = Cap::new(CapType::Endpoint, 0x40, 5, Rights::ALL, false, 0);
        assert!(ep.same_object(&ep.with_data(3)));
        let irq = Cap::new(CapType::IrqHandler, 0, 0, Rights::NONE, false, 4);
        assert!(!irq.same_object(&irq.with_data(5)));
    }

    #[test]
    fn object_types_and_sizes() {
        assert_eq!(ObjectType::from_number(4), Some(ObjectType::CNode));
        assert_eq!(ObjectType::from_number(11), None);
        assert_eq!(ObjectType::CNode.object_bits(3), 8);
        assert_eq!(ObjectType::Pml4.object_bits(0), 13);
        assert_eq!(ObjectType::Endpoint.full_rights(), Rights::ALL);
    }
}
