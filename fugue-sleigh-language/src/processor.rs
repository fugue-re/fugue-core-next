use std::fs;
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::Arc;

use ahash::AHashMap as Map;
use roxmltree::{Document, Node};
use ustr::Ustr;

use crate::compiler::InjectPayload;
use crate::deserialise::{DeserialiseError, XmlExt, parse_int_radix, parse_int_radix_with};
use crate::language::{Language, LanguageError, UserOpStr};
use crate::spaces::AddressSpace;
use crate::varnode::VarnodeData;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ContextUpdate {
    name: Ustr,
    value: u32,
    description: Option<String>,
}

impl ContextUpdate {
    pub fn from_xml(input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "set" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }
        Ok(Self {
            name: input.attribute_str("name")?.into(),
            value: input.attribute_int("val")?,
            description: input.attribute("description").map(str::to_owned),
        })
    }

    pub fn name(&self) -> Ustr {
        self.name
    }

    pub fn value(&self) -> u32 {
        self.value
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ContextSet {
    space: Arc<AddressSpace>,
    range: Option<RangeInclusive<u64>>,
    updates: Vec<ContextUpdate>,
}

impl ContextSet {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        let (space, range) = parse_range(language, input)?;
        Ok(Self {
            space,
            range,
            updates: input
                .children()
                .filter(Node::is_element)
                .map(ContextUpdate::from_xml)
                .collect::<Result<_, _>>()?,
        })
    }

    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    pub fn range(&self) -> Option<&RangeInclusive<u64>> {
        self.range.as_ref()
    }

    pub fn updates(&self) -> &[ContextUpdate] {
        &self.updates
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct TrackedSetUpdate {
    register: VarnodeData,
    value: u64,
    description: Option<String>,
}

impl TrackedSetUpdate {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "set" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }
        let name = input.attribute_str("name")?;
        Ok(Self {
            register: language
                .register_by_name(name)
                .ok_or(DeserialiseError::invariant("tracked register is invalid"))?,
            value: input.attribute_int("val")?,
            description: input.attribute("description").map(str::to_owned),
        })
    }

    pub fn register(&self) -> &VarnodeData {
        &self.register
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct TrackedSet {
    space: Arc<AddressSpace>,
    range: Option<RangeInclusive<u64>>,
    updates: Vec<TrackedSetUpdate>,
}

impl TrackedSet {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        let (space, range) = parse_range(language, input)?;
        Ok(Self {
            space,
            range,
            updates: input
                .children()
                .filter(Node::is_element)
                .map(|node| TrackedSetUpdate::from_xml(language, node))
                .collect::<Result<_, _>>()?,
        })
    }

    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    pub fn range(&self) -> Option<&RangeInclusive<u64>> {
        self.range.as_ref()
    }

    pub fn updates(&self) -> &[TrackedSetUpdate] {
        &self.updates
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum StorageLocation {
    Range {
        space: Arc<AddressSpace>,
        range: Option<RangeInclusive<u64>>,
    },
    Register(VarnodeData),
    StackRelative {
        range: Option<RangeInclusive<u64>>,
    },
}

impl StorageLocation {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        match input.tag_name().name() {
            "range" if input.attribute("space") == Some("stack") => Ok(Self::StackRelative {
                range: parse_range_bounds(u64::MAX, input)?,
            }),
            "range" => {
                let (space, range) = parse_range(language, input)?;
                Ok(Self::Range { space, range })
            }
            "register" => Ok(Self::Register(VarnodeData::from_xml(language, input)?)),
            tag => Err(DeserialiseError::tag_unexpected(tag)),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Deserialize,
    serde::Serialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum SegmentedAddressSpaceKind {
    Protected,
    Real,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SegmentedAddressSpace {
    space: Arc<AddressSpace>,
    kind: SegmentedAddressSpaceKind,
}

impl SegmentedAddressSpace {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        Ok(Self {
            space: language
                .spaces()
                .space_by_name(input.attribute_str("space")?)
                .ok_or(DeserialiseError::invariant(
                    "segmented address space is invalid",
                ))?,
            kind: if input.attribute("type") == Some("protected") {
                SegmentedAddressSpaceKind::Protected
            } else {
                SegmentedAddressSpaceKind::Real
            },
        })
    }

    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    pub fn kind(&self) -> SegmentedAddressSpaceKind {
        self.kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SegmentOp {
    space: Arc<AddressSpace>,
    user_op: UserOpStr,
    far_pointer: bool,
    payload: InjectPayload,
    constant_resolver: Option<VarnodeData>,
}

impl SegmentOp {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        let mut payload = None;
        let mut constant_resolver = None;
        for child in input.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "pcode" => {
                    if payload.is_some() {
                        return Err(DeserialiseError::invariant(
                            "segment operation has multiple payloads",
                        ));
                    }
                    payload = Some(InjectPayload::from_xml(child)?);
                }
                "constresolve" => {
                    let mut nodes = child.children().filter(Node::is_element);
                    let node = nodes.next().ok_or(DeserialiseError::invariant(
                        "segment constant resolver requires storage",
                    ))?;
                    if constant_resolver.is_some() || nodes.next().is_some() {
                        return Err(DeserialiseError::invariant(
                            "segment operation has multiple constant resolvers",
                        ));
                    }
                    constant_resolver = Some(VarnodeData::from_xml(language, node)?);
                }
                tag => return Err(DeserialiseError::tag_unexpected(tag)),
            }
        }
        let payload = payload.ok_or(DeserialiseError::invariant(
            "segment operation requires a payload",
        ))?;
        if !(1..=2).contains(&payload.inputs().len()) || payload.outputs().len() != 1 {
            return Err(DeserialiseError::invariant(
                "segment operation requires one or two inputs and one output",
            ));
        }
        Ok(Self {
            space: language
                .spaces()
                .space_by_name(input.attribute_str("space")?)
                .ok_or(DeserialiseError::invariant(
                    "segment operation address space is invalid",
                ))?,
            user_op: input.attribute("userop").unwrap_or("segment").into(),
            far_pointer: input.attribute("farpointer").is_some(),
            payload,
            constant_resolver,
        })
    }

    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    pub fn user_op(&self) -> UserOpStr {
        self.user_op
    }

    pub fn far_pointer(&self) -> bool {
        self.far_pointer
    }

    pub fn payload(&self) -> &InjectPayload {
        &self.payload
    }

    pub fn constant_resolver(&self) -> Option<&VarnodeData> {
        self.constant_resolver.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct VolatileRange {
    location: StorageLocation,
    read_op: UserOpStr,
    write_op: UserOpStr,
    format: Option<String>,
}

impl VolatileRange {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        let parent = input
            .parent()
            .ok_or(DeserialiseError::invariant("volatile range has no parent"))?;
        if parent.tag_name().name() != "volatile" {
            return Err(DeserialiseError::tag_unexpected(parent.tag_name().name()));
        }
        Ok(Self {
            location: StorageLocation::from_xml(language, input)?,
            read_op: parent.attribute_str("inputop")?.into(),
            write_op: parent.attribute_str("outputop")?.into(),
            format: parent.attribute("format").map(str::to_owned),
        })
    }

    pub fn location(&self) -> &StorageLocation {
        &self.location
    }

    pub fn read_op(&self) -> UserOpStr {
        self.read_op
    }

    pub fn write_op(&self) -> UserOpStr {
        self.write_op
    }

    pub fn format(&self) -> Option<&str> {
        self.format.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RegisterLanes {
    register: VarnodeData,
    sizes: Vec<u16>,
}

impl RegisterLanes {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        let sizes = input
            .attribute_str("vector_lane_sizes")?
            .split(',')
            .map(|size| parse_int_radix(size.trim()))
            .collect::<Result<Vec<u16>, _>>()?;
        if sizes.contains(&0) {
            return Err(DeserialiseError::invariant("register lane size is zero"));
        }
        let name = input.attribute_str("name")?;
        Ok(Self {
            register: language
                .register_by_name(name)
                .ok_or(DeserialiseError::invariant("laned register is invalid"))?,
            sizes,
        })
    }

    pub fn register(&self) -> &VarnodeData {
        &self.register
    }

    pub fn sizes(&self) -> &[u16] {
        &self.sizes
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Deserialize,
    serde::Serialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum DefaultSymbolKind {
    Code,
    CodePointer,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum DefaultSymbolAddress {
    Absolute {
        space: Arc<AddressSpace>,
        offset: u64,
    },
    Next,
}

impl DefaultSymbolAddress {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        let value = input.attribute_str("address")?;
        if value == "next" {
            return Ok(Self::Next);
        }
        let (space, offset) = match value.rsplit_once(':') {
            Some((space, offset)) => (
                language
                    .spaces()
                    .space_by_name(space)
                    .ok_or(DeserialiseError::invariant(
                        "default symbol address space is invalid",
                    ))?,
                offset,
            ),
            None => (language.spaces().default_space(), value),
        };
        Ok(Self::Absolute {
            space,
            offset: parse_int_radix_with(offset, 16)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DefaultSymbol {
    name: String,
    address: DefaultSymbolAddress,
    entry: bool,
    kind: Option<DefaultSymbolKind>,
    size: Option<u16>,
    volatile: Option<bool>,
    description: Option<String>,
}

impl DefaultSymbol {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        let kind = match input.attribute("type") {
            Some("code") => Some(DefaultSymbolKind::Code),
            Some("code_ptr") => Some(DefaultSymbolKind::CodePointer),
            Some(_) => return Err(DeserialiseError::invariant("unknown default symbol type")),
            None => None,
        };
        Ok(Self {
            name: input.attribute_string("name")?,
            address: DefaultSymbolAddress::from_xml(language, input)?,
            entry: input.attribute_bool_opt("entry", false)?,
            kind,
            size: input.attribute("size").map(parse_int_radix).transpose()?,
            volatile: input
                .attribute("volatile")
                .map(|_| input.attribute_bool("volatile"))
                .transpose()?,
            description: input.attribute("description").map(str::to_owned),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> &DefaultSymbolAddress {
        &self.address
    }

    pub fn entry(&self) -> bool {
        self.entry
    }

    pub fn kind(&self) -> Option<DefaultSymbolKind> {
        self.kind
    }

    pub fn size(&self) -> Option<u16> {
        self.size
    }

    pub fn volatile(&self) -> Option<bool> {
        self.volatile
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Processor {
    context_sets: Vec<ContextSet>,
    tracked_sets: Vec<TrackedSet>,
    volatile_ranges: Vec<VolatileRange>,
    register_lanes: Vec<RegisterLanes>,
    default_symbols: Vec<DefaultSymbol>,
    properties: Map<String, String>,
    segment_ops: Vec<SegmentOp>,
    segmented_address_space: Option<SegmentedAddressSpace>,
}

impl Processor {
    pub fn context_defaults(&self) -> impl Iterator<Item = (&str, u32)> {
        self.context_sets
            .iter()
            .filter(|set| set.range().is_none())
            .flat_map(|set| set.updates().iter())
            .map(|update| (update.name().as_str(), update.value()))
    }

    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "processor_spec" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }
        let mut context_sets = Vec::new();
        let mut tracked_sets = Vec::new();
        let mut volatile_ranges = Vec::new();
        let mut register_lanes = Vec::new();
        let mut default_symbols = Vec::new();
        let mut properties = Map::default();
        let mut segment_ops = Vec::new();
        let mut segmented_address_space = None;
        for child in input.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "properties" => {
                    for node in child.children().filter(Node::is_element) {
                        if !node.has_tag_name("property") {
                            return Err(DeserialiseError::tag_unexpected(node.tag_name().name()));
                        }
                        properties.insert(
                            node.attribute_string("key")?,
                            node.attribute_string("value")?,
                        );
                    }
                }
                "segmentop" => segment_ops.push(SegmentOp::from_xml(language, child)?),
                "segmented_address" => {
                    segmented_address_space =
                        Some(SegmentedAddressSpace::from_xml(language, child)?)
                }
                "context_data" => {
                    for node in child.children().filter(Node::is_element) {
                        match node.tag_name().name() {
                            "context_set" => {
                                context_sets.push(ContextSet::from_xml(language, node)?)
                            }
                            "tracked_set" => {
                                tracked_sets.push(TrackedSet::from_xml(language, node)?)
                            }
                            tag => return Err(DeserialiseError::tag_unexpected(tag)),
                        }
                    }
                }
                "volatile" => {
                    for node in child.children().filter(Node::is_element) {
                        volatile_ranges.push(VolatileRange::from_xml(language, node)?);
                    }
                }
                "register_data" => {
                    for node in child
                        .children()
                        .filter(Node::is_element)
                        .filter(|node| node.attribute("vector_lane_sizes").is_some())
                    {
                        register_lanes.push(RegisterLanes::from_xml(language, node)?);
                    }
                }
                "default_symbols" => {
                    for node in child.children().filter(Node::is_element) {
                        default_symbols.push(DefaultSymbol::from_xml(language, node)?);
                    }
                }
                _ => (),
            }
        }
        Ok(Self {
            context_sets,
            tracked_sets,
            volatile_ranges,
            register_lanes,
            default_symbols,
            properties,
            segment_ops,
            segmented_address_space,
        })
    }

    pub fn from_file(language: &Language, path: impl AsRef<Path>) -> Result<Self, LanguageError> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|error| LanguageError::ParseFile {
            path: path.to_owned(),
            error,
        })?;
        Self::from_str(language, input).map_err(|error| LanguageError::DeserialiseFile {
            path: path.to_owned(),
            error,
        })
    }

    pub fn from_str(language: &Language, input: impl AsRef<str>) -> Result<Self, DeserialiseError> {
        let document = Document::parse(input.as_ref()).map_err(DeserialiseError::xml)?;
        Self::from_xml(language, document.root_element())
    }

    pub fn context_sets(&self) -> &[ContextSet] {
        &self.context_sets
    }

    pub fn tracked_sets(&self) -> &[TrackedSet] {
        &self.tracked_sets
    }

    pub fn volatile_ranges(&self) -> &[VolatileRange] {
        &self.volatile_ranges
    }

    pub fn register_lanes(&self) -> &[RegisterLanes] {
        &self.register_lanes
    }

    pub fn default_symbols(&self) -> &[DefaultSymbol] {
        &self.default_symbols
    }

    pub fn properties(&self) -> &Map<String, String> {
        &self.properties
    }

    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(String::as_str)
    }

    pub fn segment_ops(&self) -> &[SegmentOp] {
        &self.segment_ops
    }

    pub fn segmented_address_space(&self) -> Option<&SegmentedAddressSpace> {
        self.segmented_address_space.as_ref()
    }
}

fn parse_range(
    language: &Language,
    input: Node,
) -> Result<(Arc<AddressSpace>, Option<RangeInclusive<u64>>), DeserialiseError> {
    let space = input.attribute_str("space")?;
    let space = language
        .spaces()
        .space_by_name(space)
        .ok_or(DeserialiseError::invariant(
            "address range space is invalid",
        ))?;
    let range = parse_range_bounds(space.highest_offset(), input)?;
    Ok((space, range))
}

fn parse_range_bounds(
    highest_offset: u64,
    input: Node,
) -> Result<Option<RangeInclusive<u64>>, DeserialiseError> {
    let first = input.attribute("first").map(parse_int_radix).transpose()?;
    let last = input.attribute("last").map(parse_int_radix).transpose()?;
    let range = (first.is_some() || last.is_some())
        .then(|| first.unwrap_or(0)..=last.unwrap_or(highest_offset));
    if range.as_ref().is_some_and(RangeInclusive::is_empty) {
        return Err(DeserialiseError::invariant("address range is reversed"));
    }
    Ok(range)
}
