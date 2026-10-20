use std::ops::RangeInclusive;

use fugue_sleigh_language::processor::{
    ContextSet as SleighContextSet, ContextUpdate as SleighContextUpdate,
    DefaultSymbol as SleighDefaultSymbol, DefaultSymbolAddress as SleighDefaultSymbolAddress,
    DefaultSymbolKind, RegisterLanes as SleighRegisterLanes, SegmentOp as SleighSegmentOp,
    SegmentedAddressSpace as SleighSegmentedAddressSpace, StorageLocation as SleighStorageLocation,
    TrackedSet as SleighTrackedSet, TrackedSetUpdate as SleighTrackedSetUpdate,
    VolatileRange as SleighVolatileRange,
};

use crate::dynamic::convention::InjectPayload;
use crate::dynamic::install::Install;
use crate::pcode::Varnode;
use crate::processor::{
    ContextSet as StaticContextSet, ContextUpdate as StaticContextUpdate,
    DefaultSymbol as StaticDefaultSymbol, DefaultSymbolAddress as StaticDefaultSymbolAddress,
    RegisterLanes as StaticRegisterLanes, SegmentOp as StaticSegmentOp,
    SegmentedAddressSpace as StaticSegmentedAddressSpace, StorageLocation as StaticStorageLocation,
    TrackedSet as StaticTrackedSet, TrackedSetUpdate as StaticTrackedSetUpdate,
    VolatileRange as StaticVolatileRange,
};

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct ContextUpdate {
    name: Box<str>,
    value: u32,
    description: Option<Box<str>>,
}

impl From<&SleighContextUpdate> for ContextUpdate {
    fn from(update: &SleighContextUpdate) -> Self {
        Self {
            name: Box::<str>::from(update.name().as_str()),
            value: update.value(),
            description: update.description().map(Box::<str>::from),
        }
    }
}

impl Install for ContextUpdate {
    type Target = StaticContextUpdate;

    fn install(self) -> Self::Target {
        Self::Target::new(self.name.install(), self.value)
            .with_description(self.description.install())
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct ContextSet {
    space: u8,
    range: Option<RangeInclusive<u64>>,
    updates: Box<[ContextUpdate]>,
}

impl From<&SleighContextSet> for ContextSet {
    fn from(context_set: &SleighContextSet) -> Self {
        Self {
            space: u8::try_from(context_set.space().index())
                .expect("address-space identifier fits in u8"),
            range: context_set.range().cloned(),
            updates: context_set.updates().iter().map(Into::into).collect(),
        }
    }
}

impl Install for ContextSet {
    type Target = StaticContextSet;

    fn install(self) -> Self::Target {
        Self::Target::new(self.space, self.range, self.updates.install())
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct TrackedSetUpdate {
    register: Varnode,
    value: u64,
    description: Option<Box<str>>,
}

impl From<&SleighTrackedSetUpdate> for TrackedSetUpdate {
    fn from(update: &SleighTrackedSetUpdate) -> Self {
        Self {
            register: update.register().into(),
            value: update.value(),
            description: update.description().map(Box::<str>::from),
        }
    }
}

impl Install for TrackedSetUpdate {
    type Target = StaticTrackedSetUpdate;

    fn install(self) -> Self::Target {
        Self::Target::new(self.register, self.value).with_description(self.description.install())
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct TrackedSet {
    space: u8,
    range: Option<RangeInclusive<u64>>,
    updates: Box<[TrackedSetUpdate]>,
}

impl From<&SleighTrackedSet> for TrackedSet {
    fn from(tracked_set: &SleighTrackedSet) -> Self {
        Self {
            space: u8::try_from(tracked_set.space().index())
                .expect("address-space identifier fits in u8"),
            range: tracked_set.range().cloned(),
            updates: tracked_set.updates().iter().map(Into::into).collect(),
        }
    }
}

impl Install for TrackedSet {
    type Target = StaticTrackedSet;

    fn install(self) -> Self::Target {
        Self::Target::new(self.space, self.range, self.updates.install())
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct VolatileRange {
    location: StorageLocation,
    read_op: Box<str>,
    write_op: Box<str>,
    format: Option<Box<str>>,
}

impl From<&SleighVolatileRange> for VolatileRange {
    fn from(volatile: &SleighVolatileRange) -> Self {
        Self {
            location: volatile.location().into(),
            read_op: Box::<str>::from(volatile.read_op().as_str()),
            write_op: Box::<str>::from(volatile.write_op().as_str()),
            format: volatile.format().map(Box::<str>::from),
        }
    }
}

impl Install for VolatileRange {
    type Target = StaticVolatileRange;

    fn install(self) -> Self::Target {
        Self::Target::new(
            self.location.install(),
            self.read_op.install(),
            self.write_op.install(),
        )
        .with_format(self.format.install())
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct RegisterLanes {
    register: Varnode,
    sizes: Box<[u16]>,
}

impl From<&SleighRegisterLanes> for RegisterLanes {
    fn from(lanes: &SleighRegisterLanes) -> Self {
        Self {
            register: lanes.register().into(),
            sizes: lanes.sizes().into(),
        }
    }
}

impl Install for RegisterLanes {
    type Target = StaticRegisterLanes;

    fn install(self) -> Self::Target {
        Self::Target::new(self.register, self.sizes.install())
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct DefaultSymbol {
    name: Box<str>,
    address: DefaultSymbolAddress,
    entry: bool,
    kind: Option<DefaultSymbolKind>,
    size: Option<u16>,
    volatile: Option<bool>,
    description: Option<Box<str>>,
}

impl From<&SleighDefaultSymbol> for DefaultSymbol {
    fn from(symbol: &SleighDefaultSymbol) -> Self {
        Self {
            name: Box::<str>::from(symbol.name()),
            address: symbol.address().into(),
            entry: symbol.entry(),
            kind: symbol.kind(),
            size: symbol.size(),
            volatile: symbol.volatile(),
            description: symbol.description().map(Box::<str>::from),
        }
    }
}

impl Install for DefaultSymbol {
    type Target = StaticDefaultSymbol;

    fn install(self) -> Self::Target {
        Self::Target::new(self.name.install(), self.address.install())
            .with_entry(self.entry)
            .with_kind(self.kind)
            .with_size(self.size)
            .with_volatile(self.volatile)
            .with_description(self.description.install())
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) enum StorageLocation {
    Range {
        space: u8,
        range: Option<RangeInclusive<u64>>,
    },
    Register(Varnode),
    StackRelative {
        range: Option<RangeInclusive<u64>>,
    },
}

impl From<&SleighStorageLocation> for StorageLocation {
    fn from(location: &SleighStorageLocation) -> Self {
        match location {
            SleighStorageLocation::Range { space, range } => Self::Range {
                space: u8::try_from(space.index()).expect("address-space identifier fits in u8"),
                range: range.clone(),
            },
            SleighStorageLocation::Register(register) => Self::Register(register.into()),
            SleighStorageLocation::StackRelative { range } => Self::StackRelative {
                range: range.clone(),
            },
        }
    }
}

impl Install for StorageLocation {
    type Target = StaticStorageLocation;

    fn install(self) -> Self::Target {
        match self {
            Self::Range { space, range } => Self::Target::Range { space, range },
            Self::Register(register) => Self::Target::Register(register),
            Self::StackRelative { range } => Self::Target::StackRelative { range },
        }
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) enum DefaultSymbolAddress {
    Absolute { space: u8, offset: u64 },
    Next,
}

impl From<&SleighDefaultSymbolAddress> for DefaultSymbolAddress {
    fn from(address: &SleighDefaultSymbolAddress) -> Self {
        match address {
            SleighDefaultSymbolAddress::Absolute { space, offset } => Self::Absolute {
                space: u8::try_from(space.index()).expect("address-space identifier fits in u8"),
                offset: *offset,
            },
            SleighDefaultSymbolAddress::Next => Self::Next,
        }
    }
}

impl Install for DefaultSymbolAddress {
    type Target = StaticDefaultSymbolAddress;

    fn install(self) -> Self::Target {
        match self {
            Self::Absolute { space, offset } => Self::Target::Absolute { space, offset },
            Self::Next => Self::Target::Next,
        }
    }
}

impl From<&SleighSegmentedAddressSpace> for StaticSegmentedAddressSpace {
    fn from(address: &SleighSegmentedAddressSpace) -> Self {
        Self::new(
            u8::try_from(address.space().index()).expect("address-space identifier fits in u8"),
            address.kind(),
        )
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct SegmentOp {
    space: u8,
    user_op: Box<str>,
    payload: InjectPayload,
    far_pointer: bool,
    constant_resolver: Option<Varnode>,
}

impl From<&SleighSegmentOp> for SegmentOp {
    fn from(operation: &SleighSegmentOp) -> Self {
        Self {
            space: u8::try_from(operation.space().index())
                .expect("address-space identifier fits in u8"),
            user_op: Box::<str>::from(operation.user_op().as_str()),
            payload: operation.payload().into(),
            far_pointer: operation.far_pointer(),
            constant_resolver: operation.constant_resolver().map(Into::into),
        }
    }
}

impl Install for SegmentOp {
    type Target = StaticSegmentOp;

    fn install(self) -> Self::Target {
        Self::Target::new(self.space, self.user_op.install(), self.payload.install())
            .with_far_pointer(self.far_pointer)
            .with_constant_resolver(self.constant_resolver)
    }
}
