use std::str::FromStr;

use fugue_core::engine::EngineMetricsSnapshot;
use fugue_core::il::registry::IlFormRegistration;
use fugue_core::ir::{
    Address as CoreAddress, AddressRange as CoreAddressRange, Function, RawAddress, Reference,
    SymbolProperties,
};
use fugue_core::project::ChangeSet;
use fugue_core::queries::{MappingEntity, ProblemEntity, SwitchEntity, SymbolEntity};
use fugue_core::storage::{AddressSpaceId, DEFAULT_SPACE_ID};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::error::WorkbenchError;

pub const DEFAULT_SPACE: AddressSpaceId = DEFAULT_SPACE_ID;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Address(String);

impl Address {
    pub fn decode(input: &str) -> Result<CoreAddress, WorkbenchError> {
        let (space, offset) = match input.split_once(':') {
            Some((space, offset)) => (Self::decode_space(space, input)?, offset),
            None => (DEFAULT_SPACE_ID, input),
        };
        let offset = RawAddress::from_str(offset).map_err(|_| WorkbenchError::not_mapped(input))?;
        Ok(CoreAddress::new(space, offset))
    }

    fn decode_space(space: &str, input: &str) -> Result<AddressSpaceId, WorkbenchError> {
        let trimmed = space.strip_prefix("0x").unwrap_or(space);
        let index =
            usize::from_str_radix(trimmed, 16).map_err(|_| WorkbenchError::not_mapped(input))?;
        AddressSpaceId::try_new(index).map_err(|_| WorkbenchError::not_mapped(input))
    }
}

impl From<CoreAddress> for Address {
    fn from(address: CoreAddress) -> Self {
        Self(address.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AddressRange {
    pub(crate) start: Address,
    pub(crate) end: Address,
}

impl AddressRange {
    fn from_range(range: &CoreAddressRange) -> Self {
        Self {
            start: Address::from(range.start_address()),
            end: Address::from(range.end_address()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetaResponse {
    pub(crate) arch: String,
    pub(crate) language: String,
    pub(crate) entry_point: Option<Address>,
    pub(crate) revision: u64,
    pub(crate) default_space: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FunctionRow {
    pub(crate) entry: Address,
    pub(crate) name: Option<String>,
    pub(crate) non_returning: bool,
    pub(crate) thunk: bool,
    pub(crate) external: bool,
}

impl FunctionRow {
    pub fn from_function(function: &Function) -> Self {
        Self {
            entry: Address::from(function.entry()),
            name: function.name().map(|name| name.to_string()),
            non_returning: function.is_non_returning(),
            thunk: function.is_thunk(),
            external: function.is_external(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SymbolRow {
    pub(crate) address: Address,
    pub(crate) name: String,
    pub(crate) function: bool,
    pub(crate) data: bool,
    pub(crate) export: bool,
    pub(crate) import: bool,
}

impl SymbolRow {
    pub fn from_entity(entity: &SymbolEntity) -> Self {
        let properties = entity.properties();
        Self {
            address: Address::from(entity.address()),
            name: entity.symbol().to_string(),
            function: properties.contains(SymbolProperties::FUNCTION),
            data: properties.contains(SymbolProperties::DATA),
            export: properties.contains(SymbolProperties::EXPORT),
            import: properties.contains(SymbolProperties::EXTERN),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProblemRow {
    pub(crate) address: Option<Address>,
    pub(crate) kind: String,
    pub(crate) attempts: u8,
}

impl ProblemRow {
    pub fn from_entity(entity: &ProblemEntity) -> Self {
        Self {
            address: entity.address().map(Address::from),
            kind: format!("{:?}", entity.kind()),
            attempts: entity.attempts(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SwitchRow {
    pub(crate) branch: Address,
    pub(crate) cases: u32,
    pub(crate) has_default: bool,
}

impl SwitchRow {
    pub fn from_entity(entity: &SwitchEntity) -> Self {
        Self {
            branch: Address::from(entity.branch()),
            cases: entity.case_count() as u32,
            has_default: entity.has_default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SegmentRow {
    pub(crate) start: Address,
    pub(crate) size: u64,
    pub(crate) readable: bool,
    pub(crate) writable: bool,
    pub(crate) executable: bool,
}

impl SegmentRow {
    pub fn from_mapping(entity: &MappingEntity) -> Self {
        let properties = entity.properties();
        Self {
            start: Address::from(entity.start()),
            size: entity.size(),
            readable: properties.is_readable(),
            writable: properties.is_writable(),
            executable: properties.is_executable(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ListingLine {
    pub(crate) address: Address,
    pub(crate) bytes: String,
    pub(crate) mnemonic: String,
    pub(crate) operands: String,
    pub(crate) size: u32,
    pub(crate) decoded: bool,
}

impl ListingLine {
    pub fn decoded(address: CoreAddress, bytes: &[u8], mnemonic: String, operands: String) -> Self {
        Self {
            address: Address::from(address),
            bytes: hex_string(bytes),
            mnemonic,
            operands,
            size: bytes.len() as u32,
            decoded: true,
        }
    }

    pub fn undecoded(address: CoreAddress, byte: u8) -> Self {
        Self {
            address: Address::from(address),
            bytes: hex_string(&[byte]),
            mnemonic: "db".to_owned(),
            operands: format!("{byte:#04x}"),
            size: 1,
            decoded: false,
        }
    }
}

fn hex_string(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct XrefRow {
    pub(crate) from: Address,
    pub(crate) to: Address,
    pub(crate) call: bool,
    pub(crate) jump: bool,
    pub(crate) data: bool,
}

impl XrefRow {
    pub fn from_reference(reference: &Reference) -> Option<Self> {
        let to = reference.target().address()?;
        Some(Self {
            from: Address::from(reference.from()),
            to: Address::from(to),
            call: reference.is_call(),
            jump: reference.is_jump(),
            data: reference.is_data(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FormInfo {
    pub(crate) id: String,
    pub(crate) root: bool,
    pub(crate) persistable: bool,
    pub(crate) renderable: bool,
}

impl FormInfo {
    pub fn from_registration(registration: &IlFormRegistration, renderable: bool) -> Self {
        Self {
            id: registration.form().to_string(),
            root: registration.is_root(),
            persistable: registration.is_persistable(),
            renderable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "kebab-case")]
pub enum IlTokenKind {
    Address,
    Flag,
    Keyword,
    Meta,
    Number,
    Opcode,
    Punctuation,
    Register,
    Space,
    Text,
    Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct IlToken {
    pub(crate) kind: IlTokenKind,
    pub(crate) text: String,
    pub(crate) nav: Option<Address>,
    pub(crate) title: Option<String>,
}

impl IlToken {
    pub fn new(kind: IlTokenKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
            nav: None,
            title: None,
        }
    }

    pub fn with_nav(mut self, address: CoreAddress) -> Self {
        self.nav = Some(Address::from(address));
        self
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct IlLine {
    pub(crate) address: Address,
    pub(crate) tokens: Vec<IlToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct IlResponse {
    pub(crate) form: String,
    pub(crate) lines: Vec<IlLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CfgBlock {
    pub(crate) id: u32,
    pub(crate) entry: Address,
    pub(crate) entry_block: bool,
    pub(crate) lines: Vec<ListingLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CfgEdge {
    pub(crate) from: u32,
    pub(crate) to: u32,
    pub(crate) taken: bool,
    pub(crate) fall_through: bool,
    pub(crate) computed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CfgResponse {
    pub(crate) entry: Address,
    pub(crate) blocks: Vec<CfgBlock>,
    pub(crate) edges: Vec<CfgEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsResponse {
    pub(crate) dispatches: u64,
    pub(crate) items_dispatched: u64,
    pub(crate) retries: u64,
    pub(crate) retries_exhausted: u64,
}

impl MetricsResponse {
    pub fn from_snapshot(snapshot: &EngineMetricsSnapshot) -> Self {
        Self {
            dispatches: snapshot.dispatches(),
            items_dispatched: snapshot.items_dispatched(),
            retries: snapshot.retries(),
            retries_exhausted: snapshot.retries_exhausted(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
pub struct RenameRequest {
    pub(crate) address: String,
    pub(crate) name: String,
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
pub struct AddressRequest {
    pub(crate) address: String,
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
pub struct PatchRequest {
    pub(crate) address: String,
    pub(crate) bytes: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct MutationResponse {
    pub(crate) revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ChangeEvent {
    pub(crate) revision: u64,
    pub(crate) kinds: Vec<String>,
    pub(crate) ranges: Vec<AddressRange>,
}

impl ChangeEvent {
    pub fn from_change_set(changes: &ChangeSet) -> Self {
        let kinds = changes
            .kinds()
            .iter_names()
            .map(|(name, _)| name.to_owned())
            .collect();
        let mut ranges = Vec::new();
        for record in changes.records() {
            for range in record.ranges() {
                ranges.push(AddressRange::from_range(&range));
            }
        }
        Self {
            revision: changes.revision().value(),
            kinds,
            ranges,
        }
    }
}
