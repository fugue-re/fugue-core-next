use std::ops::RangeInclusive;

pub use fugue_sleigh_language::processor::DefaultSymbolKind;

use crate::pcode::Varnode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageLocation {
    Range {
        space: u8,
        range: Option<RangeInclusive<u64>>,
    },
    Register(Varnode),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ContextUpdate {
    name: &'static str,
    value: u32,
    description: Option<&'static str>,
}

impl ContextUpdate {
    pub const fn new(name: &'static str, value: u32) -> Self {
        Self {
            name,
            value,
            description: None,
        }
    }

    pub const fn set_description(&mut self, description: Option<&'static str>) {
        self.description = description;
    }

    pub const fn with_description(mut self, description: Option<&'static str>) -> Self {
        self.set_description(description);
        self
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn value(&self) -> u32 {
        self.value
    }

    pub const fn description(&self) -> Option<&'static str> {
        self.description
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSet {
    space: u8,
    range: Option<RangeInclusive<u64>>,
    updates: &'static [ContextUpdate],
}

impl ContextSet {
    pub const fn new(
        space: u8,
        range: Option<RangeInclusive<u64>>,
        updates: &'static [ContextUpdate],
    ) -> Self {
        Self {
            space,
            range,
            updates,
        }
    }

    pub const fn space(&self) -> u8 {
        self.space
    }

    pub const fn range(&self) -> Option<&RangeInclusive<u64>> {
        self.range.as_ref()
    }

    pub const fn updates(&self) -> &'static [ContextUpdate] {
        self.updates
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrackedSetUpdate {
    register: Varnode,
    value: u32,
    description: Option<&'static str>,
}

impl TrackedSetUpdate {
    pub const fn new(register: Varnode, value: u32) -> Self {
        Self {
            register,
            value,
            description: None,
        }
    }

    pub const fn set_description(&mut self, description: Option<&'static str>) {
        self.description = description;
    }

    pub const fn with_description(mut self, description: Option<&'static str>) -> Self {
        self.set_description(description);
        self
    }

    pub const fn register(&self) -> Varnode {
        self.register
    }

    pub const fn value(&self) -> u32 {
        self.value
    }

    pub const fn description(&self) -> Option<&'static str> {
        self.description
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedSet {
    space: u8,
    range: Option<RangeInclusive<u64>>,
    updates: &'static [TrackedSetUpdate],
}

impl TrackedSet {
    pub const fn new(
        space: u8,
        range: Option<RangeInclusive<u64>>,
        updates: &'static [TrackedSetUpdate],
    ) -> Self {
        Self {
            space,
            range,
            updates,
        }
    }

    pub const fn space(&self) -> u8 {
        self.space
    }

    pub const fn range(&self) -> Option<&RangeInclusive<u64>> {
        self.range.as_ref()
    }

    pub const fn updates(&self) -> &'static [TrackedSetUpdate] {
        self.updates
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolatileRange {
    location: StorageLocation,
    read_op: &'static str,
    write_op: &'static str,
    format: Option<&'static str>,
}

impl VolatileRange {
    pub const fn new(
        location: StorageLocation,
        read_op: &'static str,
        write_op: &'static str,
    ) -> Self {
        Self {
            location,
            read_op,
            write_op,
            format: None,
        }
    }

    pub const fn set_format(&mut self, format: Option<&'static str>) {
        self.format = format;
    }

    pub const fn with_format(mut self, format: Option<&'static str>) -> Self {
        self.set_format(format);
        self
    }

    pub const fn location(&self) -> &StorageLocation {
        &self.location
    }

    pub const fn read_op(&self) -> &'static str {
        self.read_op
    }

    pub const fn write_op(&self) -> &'static str {
        self.write_op
    }

    pub const fn format(&self) -> Option<&'static str> {
        self.format
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RegisterLanes {
    register: Varnode,
    sizes: &'static [u16],
}

impl RegisterLanes {
    pub const fn new(register: Varnode, sizes: &'static [u16]) -> Self {
        Self { register, sizes }
    }

    pub const fn register(&self) -> Varnode {
        self.register
    }

    pub const fn sizes(&self) -> &'static [u16] {
        self.sizes
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DefaultSymbol {
    name: &'static str,
    address: DefaultSymbolAddress,
    entry: bool,
    kind: Option<DefaultSymbolKind>,
    size: Option<u16>,
    volatile: Option<bool>,
    description: Option<&'static str>,
}

impl DefaultSymbol {
    pub const fn new(name: &'static str, address: DefaultSymbolAddress) -> Self {
        Self {
            name,
            address,
            entry: false,
            kind: None,
            size: None,
            volatile: None,
            description: None,
        }
    }

    pub const fn set_entry(&mut self, entry: bool) {
        self.entry = entry;
    }

    pub const fn with_entry(mut self, entry: bool) -> Self {
        self.set_entry(entry);
        self
    }

    pub const fn set_kind(&mut self, kind: Option<DefaultSymbolKind>) {
        self.kind = kind;
    }

    pub const fn with_kind(mut self, kind: Option<DefaultSymbolKind>) -> Self {
        self.set_kind(kind);
        self
    }

    pub const fn set_size(&mut self, size: Option<u16>) {
        self.size = size;
    }

    pub const fn with_size(mut self, size: Option<u16>) -> Self {
        self.set_size(size);
        self
    }

    pub const fn set_volatile(&mut self, volatile: Option<bool>) {
        self.volatile = volatile;
    }

    pub const fn with_volatile(mut self, volatile: Option<bool>) -> Self {
        self.set_volatile(volatile);
        self
    }

    pub const fn set_description(&mut self, description: Option<&'static str>) {
        self.description = description;
    }

    pub const fn with_description(mut self, description: Option<&'static str>) -> Self {
        self.set_description(description);
        self
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn address(&self) -> DefaultSymbolAddress {
        self.address
    }

    pub const fn entry(&self) -> bool {
        self.entry
    }

    pub const fn kind(&self) -> Option<DefaultSymbolKind> {
        self.kind
    }

    pub const fn size(&self) -> Option<u16> {
        self.size
    }

    pub const fn volatile(&self) -> Option<bool> {
        self.volatile
    }

    pub const fn description(&self) -> Option<&'static str> {
        self.description
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DefaultSymbolAddress {
    Absolute { space: u8, offset: u64 },
    Next,
}
