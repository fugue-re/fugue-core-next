use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use ahash::AHashMap as Map;
use itertools::Itertools;
use roxmltree::{Document, Node};
use ustr::Ustr;

use crate::compiler::{CallFixup, DataOrganisation, UserOpFixup};
use crate::deserialise::{DeserialiseError, XmlExt, parse_int_radix};
use crate::language::{Language, LanguageError};
use crate::processor::{SegmentOp, StorageLocation};
use crate::spaces::AddressSpace;
use crate::varnode::VarnodeData;

pub use crate::compiler::{
    DatatypeFilter, DatatypeKind, PrototypeRule, PrototypeRuleAction, PrototypeRuleCondition,
    RuleStorage,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum JoinPiece {
    Location(VarnodeData),
    StackRelative { offset: u64, size: u16 },
}

impl JoinPiece {
    pub fn from_str(language: &Language, input: &str) -> Result<Self, DeserialiseError> {
        let Some((space, rest)) = input.split_once(':') else {
            return language
                .register_by_name(input)
                .map(Self::Location)
                .ok_or(DeserialiseError::invariant("join register is invalid"));
        };
        let (offset, size) = rest.split_once(':').ok_or(DeserialiseError::invariant(
            "join piece requires offset and size",
        ))?;
        let offset = parse_int_radix(offset)?;
        let size = parse_int_radix::<u16>(size)?;
        if space == "stack" {
            return Ok(Self::StackRelative { offset, size });
        }
        let space = language
            .spaces()
            .space_by_name(space)
            .ok_or(DeserialiseError::invariant("join address space is invalid"))?;
        Ok(Self::Location(VarnodeData::new(
            &space,
            offset,
            usize::from(size),
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum PrototypeOperand {
    Address {
        space: Arc<AddressSpace>,
        offset: u64,
        size: Option<u16>,
    },
    Join {
        pieces: Vec<JoinPiece>,
        logical_size: Option<u16>,
    },
    Register {
        name: Ustr,
        varnode: VarnodeData,
    },
    RegisterJoin {
        first_name: Ustr,
        first_varnode: VarnodeData,
        second_name: Ustr,
        second_varnode: VarnodeData,
    },
    StackRelative {
        offset: u64,
        size: Option<u16>,
    },
}

impl PrototypeOperand {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        match input.tag_name().name() {
            "register" | "addr" | "varnode" if input.attribute("name").is_some() => {
                let name = input.attribute_str("name")?;
                let varnode =
                    language
                        .register_by_name(name)
                        .ok_or(DeserialiseError::invariant(
                            "register for prototype operand invalid",
                        ))?;
                Ok(Self::Register {
                    name: name.into(),
                    varnode,
                })
            }
            "addr" | "varnode" => match input.attribute_str("space")? {
                "join" => {
                    let indexed = input
                        .attributes()
                        .filter_map(|attr| {
                            attr.name()
                                .strip_prefix("piece")
                                .map(|index| (index, attr.value()))
                        })
                        .map(|(index, value)| {
                            parse_int_radix::<usize>(index).map(|index| (index, value))
                        })
                        .process_results(|pieces| {
                            pieces
                                .sorted_unstable_by_key(|(index, _)| *index)
                                .collect::<Vec<_>>()
                        })?;
                    if indexed.is_empty()
                        || indexed
                            .iter()
                            .enumerate()
                            .any(|(position, (index, _))| *index != position + 1)
                    {
                        return Err(DeserialiseError::invariant(
                            "join pieces must be consecutive starting at one",
                        ));
                    }
                    let logical_size = input
                        .attribute("logicalsize")
                        .map(parse_int_radix)
                        .transpose()?;
                    if logical_size.is_none()
                        && let [(_, first), (_, second)] = indexed.as_slice()
                        && !first.contains(':')
                        && !second.contains(':')
                    {
                        let first_varnode =
                            language
                                .register_by_name(first)
                                .ok_or(DeserialiseError::invariant(
                                    "register for prototype operand invalid",
                                ))?;
                        let second_varnode = language.register_by_name(second).ok_or(
                            DeserialiseError::invariant("register for prototype operand invalid"),
                        )?;
                        return Ok(Self::RegisterJoin {
                            first_name: (*first).into(),
                            first_varnode,
                            second_name: (*second).into(),
                            second_varnode,
                        });
                    }
                    let pieces = indexed
                        .into_iter()
                        .map(|(_, value)| JoinPiece::from_str(language, value))
                        .collect::<Result<_, _>>()?;
                    Ok(Self::Join {
                        pieces,
                        logical_size,
                    })
                }
                "stack" => Ok(Self::StackRelative {
                    offset: input.attribute_int_opt("offset", 0)?,
                    size: input.attribute("size").map(parse_int_radix).transpose()?,
                }),
                space => Ok(Self::Address {
                    space: language.spaces().space_by_name(space).ok_or(
                        DeserialiseError::invariant("prototype address space is invalid"),
                    )?,
                    offset: input.attribute_int_opt("offset", 0)?,
                    size: input.attribute("size").map(parse_int_radix).transpose()?,
                }),
            },
            tag => Err(DeserialiseError::tag_unexpected(tag)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PrototypeEntry {
    killed_by_call: bool,
    storage: Option<RuleStorage>,
    group: Option<u32>,
    min_size: u16,
    max_size: u16,
    alignment: u64,
    meta_type: Option<String>,
    extension: Option<String>,
    operand: PrototypeOperand,
}

impl PrototypeEntry {
    pub fn from_xml(
        language: &Language,
        killed_by_call: bool,
        input: Node,
    ) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "pentry" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }
        let node = input
            .children()
            .find(Node::is_element)
            .ok_or(DeserialiseError::invariant(
                "compiler specification prototype entry does not define an operand",
            ))?;
        Ok(Self {
            killed_by_call,
            min_size: input.attribute_int("minsize")?,
            max_size: input.attribute_int("maxsize")?,
            alignment: input
                .attribute("align")
                .or_else(|| input.attribute("size"))
                .map(parse_int_radix)
                .transpose()?
                .unwrap_or(0),
            meta_type: input.attribute("metatype").map(str::to_owned),
            extension: input.attribute("extension").map(str::to_owned),
            storage: RuleStorage::from_attr_opt(input, "storage")?,
            group: None,
            operand: PrototypeOperand::from_xml(language, node)?,
        })
    }

    pub fn killed_by_call(&self) -> bool {
        self.killed_by_call
    }

    pub fn storage(&self) -> Option<RuleStorage> {
        self.storage
    }

    pub fn group(&self) -> Option<u32> {
        self.group
    }

    pub fn min_size(&self) -> u16 {
        self.min_size
    }

    pub fn max_size(&self) -> u16 {
        self.max_size
    }

    pub fn alignment(&self) -> u64 {
        self.alignment
    }

    pub fn meta_type(&self) -> &Option<String> {
        &self.meta_type
    }

    pub fn extension(&self) -> &Option<String> {
        &self.extension
    }

    pub fn operand(&self) -> &PrototypeOperand {
        &self.operand
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Prototype {
    name: String,
    extra_pop: Option<u64>,
    stack_shift: u64,
    pointer_max: Option<u64>,
    this_before_ret_pointer: bool,
    inputs: Vec<PrototypeEntry>,
    outputs: Vec<PrototypeEntry>,
    input_rules: Vec<PrototypeRule>,
    output_rules: Vec<PrototypeRule>,
    unaffected: Vec<PrototypeOperand>,
    killed_by_call: Vec<PrototypeOperand>,
    likely_trashed: Vec<PrototypeOperand>,
    local_ranges: Vec<StorageLocation>,
    internal_storage: Vec<VarnodeData>,
}

impl Prototype {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "prototype" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }

        let name = input.attribute_string("name")?;
        let extra_pop = if matches!(input.attribute("extrapop"), Some("unknown")) {
            None
        } else {
            Some(input.attribute_int("extrapop")?)
        };
        let stack_shift = input.attribute_int("stackshift")?;

        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut input_rules = Vec::new();
        let mut output_rules = Vec::new();
        let mut unaffected = Vec::new();
        let mut killed_by_call = Vec::new();
        let mut likely_trashed = Vec::new();
        let mut local_ranges = Vec::new();
        let mut internal_storage = Vec::new();
        let mut next_group = 0u32;
        let mut pointer_max = None;
        let mut this_before_ret_pointer = false;

        for child in input.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "input" => {
                    let killed = child.attribute_bool_opt("killedbycall", false)?;
                    let max = child.attribute_int_opt::<u64>("pointermax", 0)?;
                    pointer_max = (max != 0).then_some(max);
                    this_before_ret_pointer =
                        child.attribute_bool_opt("thisbeforeretpointer", false)?;
                    for c in child.children().filter(Node::is_element) {
                        match c.tag_name().name() {
                            "pentry" => inputs.push(PrototypeEntry::from_xml(language, killed, c)?),
                            "group" => {
                                for node in c.children().filter(Node::is_element) {
                                    let mut entry =
                                        PrototypeEntry::from_xml(language, killed, node)?;
                                    entry.group = Some(next_group);
                                    inputs.push(entry);
                                }
                                next_group += 1;
                            }
                            "rule" => input_rules.push(PrototypeRule::from_xml_with(killed, c)?),
                            _ => (),
                        }
                    }
                }
                "output" => {
                    let killed = child.attribute_bool_opt("killedbycall", false)?;
                    for c in child.children().filter(Node::is_element) {
                        match c.tag_name().name() {
                            "pentry" => {
                                outputs.push(PrototypeEntry::from_xml(language, killed, c)?)
                            }
                            "rule" => output_rules.push(PrototypeRule::from_xml_with(killed, c)?),
                            _ => (),
                        }
                    }
                }
                "unaffected" => {
                    let mut values = child
                        .children()
                        .filter(Node::is_element)
                        .map(|node| PrototypeOperand::from_xml(language, node))
                        .collect::<Result<Vec<_>, _>>()?;
                    unaffected.append(&mut values);
                }
                "killedbycall" => {
                    let mut values = child
                        .children()
                        .filter(Node::is_element)
                        .map(|node| PrototypeOperand::from_xml(language, node))
                        .collect::<Result<Vec<_>, _>>()?;
                    killed_by_call.append(&mut values);
                }
                "likelytrash" => {
                    let mut values = child
                        .children()
                        .filter(Node::is_element)
                        .map(|node| PrototypeOperand::from_xml(language, node))
                        .collect::<Result<Vec<_>, _>>()?;
                    likely_trashed.append(&mut values);
                }
                "localrange" => {
                    for node in child.children().filter(Node::is_element) {
                        if node.tag_name().name() != "range" {
                            return Err(DeserialiseError::tag_unexpected(node.tag_name().name()));
                        }
                        local_ranges.push(StorageLocation::from_xml(language, node)?);
                    }
                }
                "internal_storage" => {
                    for node in child.children().filter(Node::is_element) {
                        internal_storage.push(VarnodeData::from_xml(language, node)?);
                    }
                }
                _ => (),
            }
        }

        Ok(Self {
            name,
            extra_pop,
            stack_shift,
            pointer_max,
            this_before_ret_pointer,
            inputs,
            outputs,
            input_rules,
            output_rules,
            unaffected,
            killed_by_call,
            likely_trashed,
            local_ranges,
            internal_storage,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn extra_pop(&self) -> Option<u64> {
        self.extra_pop
    }

    pub fn stack_shift(&self) -> u64 {
        self.stack_shift
    }

    pub fn pointer_max(&self) -> Option<u64> {
        self.pointer_max
    }

    pub fn this_before_ret_pointer(&self) -> bool {
        self.this_before_ret_pointer
    }

    pub fn inputs(&self) -> &[PrototypeEntry] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[PrototypeEntry] {
        &self.outputs
    }

    pub fn input_rules(&self) -> &[PrototypeRule] {
        &self.input_rules
    }

    pub fn output_rules(&self) -> &[PrototypeRule] {
        &self.output_rules
    }

    pub fn unaffected(&self) -> &[PrototypeOperand] {
        &self.unaffected
    }

    pub fn killed_by_call(&self) -> &[PrototypeOperand] {
        &self.killed_by_call
    }

    pub fn likely_trashed(&self) -> &[PrototypeOperand] {
        &self.likely_trashed
    }

    pub fn local_ranges(&self) -> &[StorageLocation] {
        &self.local_ranges
    }

    pub fn internal_storage(&self) -> &[VarnodeData] {
        &self.internal_storage
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    serde::Deserialize,
    serde::Serialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum PrototypeReference {
    Alias(u32),
    Prototype(u32),
    Resolution(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PrototypeAlias {
    name: String,
    parent: u32,
}

impl PrototypeAlias {
    pub fn from_xml(convention: &Convention, input: Node) -> Result<Self, DeserialiseError> {
        if !input.has_tag_name("modelalias") {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }
        let name = input.attribute_string("name")?;
        if convention.prototype_reference(&name).is_some() {
            return Err(DeserialiseError::invariant(
                "prototype alias name is already defined",
            ));
        }
        let parent = input.attribute_str("parent")?;
        let parent = convention
            .prototypes()
            .position(|prototype| prototype.name() == parent)
            .ok_or(DeserialiseError::invariant(
                "prototype alias parent is invalid",
            ))?;
        Ok(Self {
            name,
            parent: u32::try_from(parent).expect("prototype index fits in u32"),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn parent(&self) -> u32 {
        self.parent
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PrototypeResolution {
    name: String,
    prototypes: Vec<PrototypeReference>,
}

impl PrototypeResolution {
    pub fn from_xml(convention: &Convention, input: Node) -> Result<Self, DeserialiseError> {
        if !input.has_tag_name("resolveprototype") {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }
        let name = input.attribute_string("name")?;
        if convention.prototype_reference(&name).is_some() {
            return Err(DeserialiseError::invariant(
                "prototype resolution name is already defined",
            ));
        }
        let prototypes = input
            .children()
            .filter(Node::is_element)
            .map(|node| {
                if node.tag_name().name() != "model" {
                    return Err(DeserialiseError::tag_unexpected(node.tag_name().name()));
                }
                let reference = convention
                    .prototype_reference(node.attribute_str("name")?)
                    .ok_or(DeserialiseError::invariant(
                        "prototype resolution model is invalid",
                    ))?;
                if matches!(reference, PrototypeReference::Resolution(_)) {
                    return Err(DeserialiseError::invariant(
                        "prototype resolution model cannot be a resolution",
                    ));
                }
                Ok(reference)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if prototypes.is_empty() {
            return Err(DeserialiseError::invariant(
                "prototype resolution requires a model",
            ));
        }
        Ok(Self { name, prototypes })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn prototypes(&self) -> &[PrototypeReference] {
        &self.prototypes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PreferredVarnodeSplit {
    storage: VarnodeData,
    split_offset: u16,
}

impl PreferredVarnodeSplit {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        let parent = input
            .parent()
            .ok_or(DeserialiseError::invariant("preferred split has no parent"))?;
        if !parent.has_tag_name("prefersplit") {
            return Err(DeserialiseError::tag_unexpected(parent.tag_name().name()));
        }
        if parent.attribute_str("style")? != "inhalf" {
            return Err(DeserialiseError::invariant(
                "preferred split style is invalid",
            ));
        }
        let storage = VarnodeData::from_xml(language, input)?;
        let split_offset = u16::try_from(storage.size() / 2)
            .map_err(|_| DeserialiseError::invariant("preferred split offset exceeds u16"))?;
        Ok(Self {
            storage,
            split_offset,
        })
    }

    pub fn storage(&self) -> &VarnodeData {
        &self.storage
    }

    pub fn split_offset(&self) -> u16 {
        self.split_offset
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum ReturnAddress {
    Register { name: Ustr, varnode: VarnodeData },
    StackRelative { offset: u64, size: u16 },
}

impl ReturnAddress {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "returnaddress" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }
        let node = input
            .children()
            .find(Node::is_element)
            .ok_or(DeserialiseError::invariant("no children for returnaddress"))?;
        match node.tag_name().name() {
            "register" => {
                let name = node.attribute_str("name")?;
                let varnode =
                    language
                        .register_by_name(name)
                        .ok_or(DeserialiseError::invariant(
                            "register for return address invalid",
                        ))?;
                Ok(Self::Register {
                    name: name.into(),
                    varnode,
                })
            }
            "varnode" if node.attribute("space") == Some("stack") => Ok(Self::StackRelative {
                offset: node.attribute_int("offset")?,
                size: node.attribute_int("size")?,
            }),
            tag => Err(DeserialiseError::tag_unexpected(tag)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct StackPointer {
    name: Ustr,
    varnode: VarnodeData,
    space: Arc<AddressSpace>,
}

impl StackPointer {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "stackpointer" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }
        let name = input.attribute_str("register")?;
        let varnode = language
            .register_by_name(name)
            .ok_or(DeserialiseError::invariant("named stack pointer invalid"))?;
        let space = language
            .spaces()
            .space_by_name(input.attribute_str("space")?)
            .ok_or(DeserialiseError::invariant(
                "stack pointer space for convention invalid",
            ))?;
        Ok(Self {
            name: name.into(),
            varnode,
            space,
        })
    }

    pub fn varnode(&self) -> &VarnodeData {
        &self.varnode
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Convention {
    name: String,
    data_organisation: Option<DataOrganisation>,
    stack_pointer: StackPointer,
    return_address: Option<ReturnAddress>,
    default_prototype: Prototype,
    call_preserved_registers: Vec<VarnodeData>,
    additional_prototypes: Vec<Prototype>,
    call_fixups: Vec<CallFixup>,
    user_op_fixups: Vec<UserOpFixup>,
    function_pointer_alignment: Option<u64>,
    global_ranges: Vec<StorageLocation>,
    aggressive_trim: bool,
    preferred_varnode_splits: Vec<PreferredVarnodeSplit>,
    prototype_aliases: Vec<PrototypeAlias>,
    prototype_resolutions: Vec<PrototypeResolution>,
    eval_current_prototype: Option<PrototypeReference>,
    properties: Map<String, String>,
    segment_ops: Vec<SegmentOp>,
}

impl Convention {
    pub fn from_file(
        language: &Language,
        name: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<Self, LanguageError> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|error| LanguageError::ParseFile {
            path: path.to_owned(),
            error,
        })?;
        Self::from_str(language, name, input).map_err(|error| LanguageError::DeserialiseFile {
            path: path.to_owned(),
            error,
        })
    }

    pub fn from_xml(
        language: &Language,
        name: impl Into<String>,
        input: Node,
    ) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "compiler_spec" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }

        let mut data_organisation = None;
        let mut stack_pointer = None;
        let mut return_address = None;
        let mut default_prototype = None;
        let mut additional_prototypes = Vec::new();
        let mut call_fixups = Vec::new();
        let mut user_op_fixups = Vec::new();
        let mut function_pointer_alignment = None;
        let mut global_ranges = Vec::new();
        let mut aggressive_trim = false;
        let mut preferred_varnode_splits = Vec::new();
        let mut properties = Map::default();
        let mut segment_ops = Vec::new();

        for child in input.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "global" => {
                    for node in child.children().filter(Node::is_element) {
                        global_ranges.push(StorageLocation::from_xml(language, node)?);
                    }
                }
                "aggressivetrim" => aggressive_trim = child.attribute_bool_opt("signext", false)?,
                "prefersplit" => {
                    for node in child.children().filter(Node::is_element) {
                        preferred_varnode_splits
                            .push(PreferredVarnodeSplit::from_xml(language, node)?);
                    }
                }
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
                "data_organization" => {
                    data_organisation = Some(DataOrganisation::from_xml(child)?);
                }
                "stackpointer" => {
                    stack_pointer = Some(StackPointer::from_xml(language, child)?);
                }
                "returnaddress" => {
                    return_address = Some(ReturnAddress::from_xml(language, child)?);
                }
                "default_proto" => {
                    let proto = child.children().find(Node::is_element).ok_or(DeserialiseError::invariant(
                        "compiler specification does not define prototype for default prototype",
                    ))?;
                    default_prototype = Some(Prototype::from_xml(language, proto)?);
                }
                "prototype" => {
                    additional_prototypes.push(Prototype::from_xml(language, child)?);
                }
                "callfixup" => call_fixups.push(CallFixup::from_xml(child)?),
                "callotherfixup" => user_op_fixups.push(UserOpFixup::from_xml(child)?),
                "funcptr" => function_pointer_alignment = Some(child.attribute_int("align")?),
                _ => (),
            }
        }

        let default_prototype = default_prototype.ok_or(DeserialiseError::invariant(
            "compiler specification does not define a default prototype",
        ))?;

        let stack_pointer = stack_pointer.ok_or(DeserialiseError::invariant(
            "compiler specification does not define stack pointer configuration",
        ))?;
        let register_space = language.spaces().register_space_id();
        let mut call_preserved_registers = BTreeSet::new();
        for operand in default_prototype.unaffected() {
            match operand {
                PrototypeOperand::Register { varnode, .. } => {
                    call_preserved_registers.insert(*varnode);
                }
                PrototypeOperand::RegisterJoin {
                    first_varnode,
                    second_varnode,
                    ..
                } => {
                    call_preserved_registers.extend([*first_varnode, *second_varnode]);
                }
                PrototypeOperand::Join { pieces, .. } => {
                    call_preserved_registers.extend(pieces.iter().filter_map(
                        |piece| match piece {
                            JoinPiece::Location(varnode) if varnode.space() == register_space => {
                                Some(*varnode)
                            }
                            _ => None,
                        },
                    ));
                }
                PrototypeOperand::Address {
                    space,
                    offset,
                    size: Some(size),
                } if space.id() == register_space => {
                    call_preserved_registers.insert(VarnodeData::new(
                        space,
                        *offset,
                        usize::from(*size),
                    ));
                }
                PrototypeOperand::Address { .. } | PrototypeOperand::StackRelative { .. } => {}
            }
        }

        let mut convention = Self {
            name: name.into(),
            data_organisation,
            stack_pointer,
            return_address,
            default_prototype,
            call_preserved_registers: call_preserved_registers.into_iter().collect(),
            additional_prototypes,
            call_fixups,
            user_op_fixups,
            function_pointer_alignment,
            global_ranges,
            aggressive_trim,
            preferred_varnode_splits,
            prototype_aliases: Vec::new(),
            prototype_resolutions: Vec::new(),
            eval_current_prototype: None,
            properties,
            segment_ops,
        };
        let mut names = BTreeSet::new();
        if convention
            .prototypes()
            .any(|prototype| !names.insert(prototype.name()))
        {
            return Err(DeserialiseError::invariant(
                "prototype name is already defined",
            ));
        }
        for child in input
            .children()
            .filter(|node| node.has_tag_name("modelalias"))
        {
            convention
                .prototype_aliases
                .push(PrototypeAlias::from_xml(&convention, child)?);
        }
        for child in input
            .children()
            .filter(|node| node.has_tag_name("resolveprototype"))
        {
            convention
                .prototype_resolutions
                .push(PrototypeResolution::from_xml(&convention, child)?);
        }
        for child in input
            .children()
            .filter(|node| node.has_tag_name("eval_current_prototype"))
        {
            convention.eval_current_prototype = Some(
                convention
                    .prototype_reference(child.attribute_str("name")?)
                    .ok_or(DeserialiseError::invariant(
                        "current evaluation prototype is invalid",
                    ))?,
            );
        }
        Ok(convention)
    }

    pub fn from_str(
        language: &Language,
        name: impl Into<String>,
        input: impl AsRef<str>,
    ) -> Result<Self, DeserialiseError> {
        let document = Document::parse(input.as_ref()).map_err(DeserialiseError::xml)?;
        Self::from_xml(language, name, document.root_element())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn stack_pointer(&self) -> &StackPointer {
        &self.stack_pointer
    }

    pub fn return_address(&self) -> Option<&ReturnAddress> {
        self.return_address.as_ref()
    }

    pub fn default_prototype(&self) -> &Prototype {
        &self.default_prototype
    }

    pub fn call_preserved_registers(&self) -> &[VarnodeData] {
        &self.call_preserved_registers
    }

    pub fn additional_prototypes(&self) -> &[Prototype] {
        &self.additional_prototypes
    }

    pub fn prototypes(&self) -> impl Iterator<Item = &Prototype> {
        std::iter::once(&self.default_prototype).chain(self.additional_prototypes.iter())
    }

    pub fn data_organisation(&self) -> Option<&DataOrganisation> {
        self.data_organisation.as_ref()
    }

    pub fn user_op_fixups(&self) -> &[UserOpFixup] {
        &self.user_op_fixups
    }

    pub fn function_pointer_alignment(&self) -> Option<u64> {
        self.function_pointer_alignment
    }

    pub fn call_fixups(&self) -> &[CallFixup] {
        &self.call_fixups
    }

    pub fn global_ranges(&self) -> &[StorageLocation] {
        &self.global_ranges
    }

    pub fn aggressive_trim(&self) -> bool {
        self.aggressive_trim
    }

    pub fn preferred_varnode_splits(&self) -> &[PreferredVarnodeSplit] {
        &self.preferred_varnode_splits
    }

    pub fn prototype_aliases(&self) -> &[PrototypeAlias] {
        &self.prototype_aliases
    }

    pub fn prototype_resolutions(&self) -> &[PrototypeResolution] {
        &self.prototype_resolutions
    }

    pub fn eval_current_prototype(&self) -> Option<PrototypeReference> {
        self.eval_current_prototype
    }

    pub fn prototype_reference(&self, name: &str) -> Option<PrototypeReference> {
        if let Some(index) = self
            .prototypes()
            .position(|prototype| prototype.name() == name)
        {
            return Some(PrototypeReference::Prototype(
                u32::try_from(index).expect("prototype index fits in u32"),
            ));
        }
        if let Some(index) = self
            .prototype_aliases
            .iter()
            .position(|alias| alias.name() == name)
        {
            return Some(PrototypeReference::Alias(
                u32::try_from(index).expect("prototype alias index fits in u32"),
            ));
        }
        self.prototype_resolutions
            .iter()
            .position(|resolution| resolution.name() == name)
            .map(|index| {
                PrototypeReference::Resolution(
                    u32::try_from(index).expect("prototype resolution index fits in u32"),
                )
            })
    }

    pub fn prototype(&self, index: u32) -> Option<&Prototype> {
        self.prototypes().nth(index as _)
    }

    pub fn prototype_resolution(&self, index: u32) -> Option<&PrototypeResolution> {
        self.prototype_resolutions.get(index as usize)
    }

    pub fn prototype_alias(&self, index: u32) -> Option<&PrototypeAlias> {
        self.prototype_aliases.get(index as usize)
    }

    pub fn prototype_by_reference(&self, reference: PrototypeReference) -> Option<&Prototype> {
        match reference {
            PrototypeReference::Alias(index) => {
                self.prototype(self.prototype_alias(index)?.parent())
            }
            PrototypeReference::Prototype(index) => self.prototype(index),
            PrototypeReference::Resolution(_) => None,
        }
    }

    pub fn prototype_by_name(&self, name: &str) -> Option<&Prototype> {
        self.prototype_by_reference(self.prototype_reference(name)?)
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
}
