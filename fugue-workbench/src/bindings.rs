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
#[serde(transparent)]
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
        let index = usize::from_str_radix(trimmed, 16)
            .map_err(|_| WorkbenchError::not_mapped(input))?;
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
    pub start: Address,
    pub end: Address,
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
    pub arch: String,
    pub language: String,
    pub entry_point: Option<Address>,
    pub revision: u64,
    pub default_space: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FunctionRow {
    pub entry: Address,
    pub name: Option<String>,
    pub non_returning: bool,
    pub thunk: bool,
    pub external: bool,
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
    pub address: Address,
    pub name: String,
    pub function: bool,
    pub data: bool,
    pub export: bool,
    pub import: bool,
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
    pub address: Option<Address>,
    pub kind: String,
    pub attempts: u8,
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
    pub branch: Address,
    pub cases: u32,
    pub has_default: bool,
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
    pub start: Address,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
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
    pub address: Address,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub size: u32,
    pub decoded: bool,
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
    pub from: Address,
    pub to: Address,
    pub call: bool,
    pub jump: bool,
    pub data: bool,
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
    pub id: String,
    pub root: bool,
    pub persistable: bool,
    pub renderable: bool,
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
    Opcode,
    Keyword,
    Register,
    Flag,
    Number,
    Address,
    Space,
    Value,
    Punctuation,
    Meta,
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct IlToken {
    pub kind: IlTokenKind,
    pub text: String,
    pub nav: Option<Address>,
    pub title: Option<String>,
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
    pub address: Address,
    pub tokens: Vec<IlToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct IlResponse {
    pub form: String,
    pub lines: Vec<IlLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CfgBlock {
    pub id: u32,
    pub entry: Address,
    pub entry_block: bool,
    pub lines: Vec<ListingLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CfgEdge {
    pub from: u32,
    pub to: u32,
    pub taken: bool,
    pub fall_through: bool,
    pub computed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CfgResponse {
    pub entry: Address,
    pub blocks: Vec<CfgBlock>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsResponse {
    pub dispatches: u64,
    pub items_dispatched: u64,
    pub retries: u64,
    pub retries_exhausted: u64,
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
    pub address: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
pub struct AddressRequest {
    pub address: String,
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
pub struct PatchRequest {
    pub address: String,
    pub bytes: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct MutationResponse {
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ChangeEvent {
    pub revision: u64,
    pub kinds: Vec<String>,
    pub ranges: Vec<AddressRange>,
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
