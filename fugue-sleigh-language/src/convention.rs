use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use roxmltree::{Document, Node};
use ustr::Ustr;

use crate::compiler::{CallFixup, DataOrganisation, UserOpFixup};
use crate::deserialise::{DeserialiseError, XmlExt, parse_int_radix};
use crate::language::{Language, LanguageError};
use crate::spaces::{AddressSpace, AddressSpaceId};
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
                    let mut indexed = input
                        .attributes()
                        .filter_map(|attr| {
                            attr.name()
                                .strip_prefix("piece")
                                .map(|index| (index, attr.value()))
                        })
                        .map(|(index, value)| Ok((parse_int_radix::<usize>(index)?, value)))
                        .collect::<Result<Vec<_>, DeserialiseError>>()?;
                    indexed.sort_unstable_by_key(|(index, _)| *index);
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
    extra_pop: u64,
    stack_shift: u64,
    inputs: Vec<PrototypeEntry>,
    outputs: Vec<PrototypeEntry>,
    input_rules: Vec<PrototypeRule>,
    output_rules: Vec<PrototypeRule>,
    unaffected: Vec<PrototypeOperand>,
    killed_by_call: Vec<PrototypeOperand>,
    likely_trashed: Vec<PrototypeOperand>,
}

impl Prototype {
    pub fn from_xml(language: &Language, input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "prototype" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }

        let name = input.attribute_string("name")?;
        let extra_pop = if matches!(input.attribute("extrapop"), Some("unknown")) {
            0
        } else {
            input.attribute_int("extrapop")?
        };
        let stack_shift = input.attribute_int("stackshift")?;

        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut input_rules = Vec::new();
        let mut output_rules = Vec::new();
        let mut unaffected = Vec::new();
        let mut killed_by_call = Vec::new();
        let mut likely_trashed = Vec::new();
        let mut next_group = 0u32;

        for child in input.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "input" => {
                    let killed = child.attribute_bool_opt("killedbycall", false)?;
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
                _ => (),
            }
        }

        Ok(Self {
            name,
            extra_pop,
            stack_shift,
            inputs,
            outputs,
            input_rules,
            output_rules,
            unaffected,
            killed_by_call,
            likely_trashed,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn extra_pop(&self) -> u64 {
        self.extra_pop
    }

    pub fn stack_shift(&self) -> u64 {
        self.stack_shift
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

        for child in input.children().filter(Node::is_element) {
            match child.tag_name().name() {
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
        let call_preserved_registers = collect_call_preserved_registers(
            &default_prototype,
            language.spaces().register_space_id(),
        );

        Ok(Self {
            name: name.into(),
            data_organisation,
            stack_pointer,
            return_address,
            default_prototype,
            call_preserved_registers,
            additional_prototypes,
            call_fixups,
            user_op_fixups,
            function_pointer_alignment,
        })
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
}

fn collect_call_preserved_registers(
    prototype: &Prototype,
    register_space: AddressSpaceId,
) -> Vec<VarnodeData> {
    let mut registers = BTreeSet::new();
    for operand in prototype.unaffected() {
        match operand {
            PrototypeOperand::Register { varnode, .. } => {
                registers.insert(*varnode);
            }
            PrototypeOperand::RegisterJoin {
                first_varnode,
                second_varnode,
                ..
            } => {
                registers.extend([*first_varnode, *second_varnode]);
            }
            PrototypeOperand::Join { pieces, .. } => {
                registers.extend(pieces.iter().filter_map(|piece| match piece {
                    JoinPiece::Location(varnode) if varnode.space() == register_space => {
                        Some(*varnode)
                    }
                    _ => None,
                }));
            }
            PrototypeOperand::Address {
                space,
                offset,
                size: Some(size),
            } if space.id() == register_space => {
                registers.insert(VarnodeData::new(space, *offset, usize::from(*size)));
            }
            PrototypeOperand::Address { .. } | PrototypeOperand::StackRelative { .. } => {}
        }
    }
    registers.into_iter().collect()
}
