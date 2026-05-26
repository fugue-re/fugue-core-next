use std::fs::File;
use std::io::Read;
use std::iter::FromIterator;
use std::path::Path;

use ahash::AHashMap as Map;
use ustr::UstrSet;

use crate::deserialise::{parse_int_radix, DeserialiseError, XmlExt};
use crate::language::LanguageError;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DataOrganisation {
    pub(crate) absolute_max_alignment: u64,
    pub(crate) machine_alignment: u64,
    pub(crate) default_alignment: u64,
    pub(crate) default_pointer_alignment: u64,
    pub(crate) pointer_size: usize,
    pub(crate) wchar_size: usize,
    pub(crate) short_size: usize,
    pub(crate) integer_size: usize,
    pub(crate) long_size: usize,
    pub(crate) long_long_size: usize,
    pub(crate) float_size: usize,
    pub(crate) double_size: usize,
    pub(crate) long_double_size: usize,
    pub(crate) size_alignment_map: Map<usize, u64>,
}

impl Default for DataOrganisation {
    fn default() -> Self {
        Self {
            absolute_max_alignment: 0,
            machine_alignment: 1,
            default_alignment: 1,
            default_pointer_alignment: 4,
            pointer_size: 4,
            wchar_size: 2,
            short_size: 2,
            integer_size: 4,
            long_size: 4,
            long_long_size: 8,
            float_size: 4,
            double_size: 8,
            long_double_size: 12,
            size_alignment_map: Map::from_iter(vec![(1, 1), (2, 2), (4, 4), (8, 8)]),
        }
    }
}

impl DataOrganisation {
    pub fn from_xml(input: xml::Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "data_organization" {
            return Err(DeserialiseError::TagUnexpected(
                input.tag_name().name().to_owned(),
            ));
        }

        let mut data = Self::default();

        for child in input.children().filter(xml::Node::is_element) {
            match child.tag_name().name() {
                "absolute_max_alignment" => {
                    data.absolute_max_alignment = child.attribute_int("value")?;
                }
                "machine_alignment" => {
                    data.machine_alignment = child.attribute_int("value")?;
                }
                "default_alignment" => {
                    data.default_alignment = child.attribute_int("value")?;
                }
                "default_pointer_alignment" => {
                    data.default_pointer_alignment = child.attribute_int("value")?;
                }
                "pointer_size" => {
                    data.pointer_size = child.attribute_int("value")?;
                }
                "wchar_size" => {
                    data.wchar_size = child.attribute_int("value")?;
                }
                "short_size" => {
                    data.short_size = child.attribute_int("value")?;
                }
                "integer_size" => {
                    data.integer_size = child.attribute_int("value")?;
                }
                "long_size" => {
                    data.long_size = child.attribute_int("value")?;
                }
                "long_long_size" => {
                    data.long_long_size = child.attribute_int("value")?;
                }
                "float_size" => {
                    data.float_size = child.attribute_int("value")?;
                }
                "double_size" => {
                    data.double_size = child.attribute_int("value")?;
                }
                "long_double_size" => {
                    data.long_double_size = child.attribute_int("value")?;
                }
                "size_alignment_map" => {
                    for entry in child
                        .children()
                        .filter(|e| e.is_element() && e.tag_name().name() == "entry")
                    {
                        data.size_alignment_map.insert(
                            entry.attribute_int("size")?,
                            entry.attribute_int("alignment")?,
                        );
                    }
                }
                _ => (),
            }
        }

        Ok(data)
    }

    pub fn absolute_max_alignment(&self) -> u64 {
        self.absolute_max_alignment
    }

    pub fn machine_alignment(&self) -> u64 {
        self.machine_alignment
    }

    pub fn default_alignment(&self) -> u64 {
        self.default_alignment
    }

    pub fn default_pointer_alignment(&self) -> u64 {
        self.default_pointer_alignment
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    pub fn wchar_size(&self) -> usize {
        self.wchar_size
    }

    pub fn short_size(&self) -> usize {
        self.short_size
    }

    pub fn integer_size(&self) -> usize {
        self.integer_size
    }

    pub fn long_size(&self) -> usize {
        self.long_size
    }

    pub fn long_long_size(&self) -> usize {
        self.long_long_size
    }

    pub fn float_size(&self) -> usize {
        self.float_size
    }

    pub fn double_size(&self) -> usize {
        self.double_size
    }

    pub fn long_double_size(&self) -> usize {
        self.long_double_size
    }

    pub fn size_alignment(&self, size: usize) -> u64 {
        self.size_alignment_map
            .get(&size)
            .cloned()
            .unwrap_or(self.default_alignment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct StackPointer {
    pub(crate) register: String,
    pub(crate) space: String,
}

impl StackPointer {
    pub fn from_xml(input: xml::Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "stackpointer" {
            return Err(DeserialiseError::TagUnexpected(
                input.tag_name().name().to_owned(),
            ));
        }

        Ok(Self {
            register: input.attribute_string("register")?,
            space: input.attribute_string("space")?,
        })
    }

    pub fn register(&self) -> &str {
        &self.register
    }

    pub fn space(&self) -> &str {
        &self.space
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum ReturnAddress {
    Register(String),
    StackRelative { offset: u64, size: usize },
}

impl ReturnAddress {
    pub fn from_xml(input: xml::Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "returnaddress" {
            return Err(DeserialiseError::TagUnexpected(
                input.tag_name().name().to_owned(),
            ));
        }

        let mut children = input.children().filter(xml::Node::is_element);

        let node = children
            .next()
            .ok_or(DeserialiseError::Invariant("no children for returnaddress"))?;

        match node.tag_name().name() {
            "register" => Ok(Self::Register(node.attribute_string("name")?)),
            "varnode"
                if node
                    .attribute_string("space")
                    .map(|space| space == "stack")
                    .unwrap_or(false) =>
            {
                Ok(Self::StackRelative {
                    offset: node.attribute_int("offset")?,
                    size: node.attribute_int("size")?,
                })
            }
            tag => Err(DeserialiseError::TagUnexpected(tag.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum PrototypeOperand {
    Register(String),
    RegisterJoin(String, String),
    StackRelative(u64),
}

impl PrototypeOperand {
    pub fn from_xml(input: xml::Node) -> Result<Self, DeserialiseError> {
        match input.tag_name().name() {
            "addr" => match input.attribute_string("space")?.as_ref() {
                "join" => Ok(Self::RegisterJoin(
                    input.attribute_string("piece1")?,
                    input.attribute_string("piece2")?,
                )),
                "stack" => Ok(Self::StackRelative(input.attribute_int("offset")?)),
                tag => Err(DeserialiseError::TagUnexpected(tag.to_owned())),
            },
            "register" => Ok(Self::Register(input.attribute_string("name")?)),
            tag => Err(DeserialiseError::TagUnexpected(tag.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PrototypeEntry {
    pub(crate) killed_by_call: bool,
    pub(crate) min_size: usize,
    pub(crate) max_size: usize,
    pub(crate) alignment: u64,
    pub(crate) meta_type: Option<String>,
    pub(crate) extension: Option<String>,
    pub(crate) operand: PrototypeOperand,
}

impl PrototypeEntry {
    pub fn from_xml(input: xml::Node, killed_by_call: bool) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "pentry" {
            return Err(DeserialiseError::TagUnexpected(
                input.tag_name().name().to_owned(),
            ));
        }

        let min_size = input.attribute_int("minsize")?;
        let max_size = input.attribute_int("maxsize")?;
        let alignment = input.attribute_int_opt("alignment", 1)?;

        let meta_type = input
            .attribute_string("metatype")
            .map(Some)
            .unwrap_or_default();
        let extension = input
            .attribute_string("extension")
            .map(Some)
            .unwrap_or_default();

        let node = input.children().find(xml::Node::is_element);
        if node.is_none() {
            return Err(DeserialiseError::Invariant(
                "compiler specification prototype entry does not define an operand",
            ));
        }

        let operand = PrototypeOperand::from_xml(node.unwrap())?;

        Ok(Self {
            killed_by_call,
            min_size,
            max_size,
            alignment,
            meta_type,
            extension,
            operand,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum DatatypeKind {
    Struct,
    Union,
    Float,
    Any,
    HomogeneousFloatAggregate,
}

impl DatatypeKind {
    pub fn from_name(name: &str) -> Result<Self, DeserialiseError> {
        match name {
            "struct" => Ok(Self::Struct),
            "union" => Ok(Self::Union),
            "float" => Ok(Self::Float),
            "any" => Ok(Self::Any),
            "homogeneous-float-aggregate" => Ok(Self::HomogeneousFloatAggregate),
            _ => Err(DeserialiseError::Invariant(
                "unknown datatype name in prototype rule",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum RuleStorage {
    General,
    Float,
}

impl RuleStorage {
    pub fn from_attr_opt(
        node: xml::Node,
        name: &'static str,
    ) -> Result<Option<Self>, DeserialiseError> {
        match node.attribute(name) {
            Some("general") => Ok(Some(Self::General)),
            Some("float") => Ok(Some(Self::Float)),
            Some(_) => Err(DeserialiseError::Invariant(
                "unknown storage class in prototype rule",
            )),
            None => Ok(None),
        }
    }

    pub fn from_attr(node: xml::Node, name: &'static str) -> Result<Self, DeserialiseError> {
        Self::from_attr_opt(node, name)?.ok_or(DeserialiseError::AttributeExpected(name))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DatatypeFilter {
    pub(crate) kind: DatatypeKind,
    pub(crate) min_size: Option<usize>,
    pub(crate) max_size: Option<usize>,
    pub(crate) sizes: Vec<usize>,
    pub(crate) max_primitives: Option<usize>,
}

impl DatatypeFilter {
    pub fn from_xml(input: xml::Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "datatype" {
            return Err(DeserialiseError::TagUnexpected(
                input.tag_name().name().to_owned(),
            ));
        }

        let kind = DatatypeKind::from_name(&input.attribute_string("name")?)?;

        let min_size = input.attribute("minsize").map(parse_int_radix).transpose()?;
        let max_size = input.attribute("maxsize").map(parse_int_radix).transpose()?;
        let max_primitives = input
            .attribute("maxprimitives")
            .map(parse_int_radix)
            .transpose()?;

        let sizes = match input.attribute("sizes") {
            Some(s) => s
                .split(',')
                .map(|part| parse_int_radix(part.trim()))
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };

        Ok(Self {
            kind,
            min_size,
            max_size,
            sizes,
            max_primitives,
        })
    }

    pub fn kind(&self) -> DatatypeKind {
        self.kind
    }

    pub fn min_size(&self) -> Option<usize> {
        self.min_size
    }

    pub fn max_size(&self) -> Option<usize> {
        self.max_size
    }

    pub fn sizes(&self) -> &[usize] {
        &self.sizes
    }

    pub fn max_primitives(&self) -> Option<usize> {
        self.max_primitives
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum PrototypeRuleCondition {
    Datatype(DatatypeFilter),
    Varargs { first: usize },
    Position { index: usize },
    DatatypeAt { index: usize, datatype: DatatypeFilter },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum PrototypeRuleAction {
    Consume {
        storage: RuleStorage,
    },
    ConsumeExtra {
        storage: RuleStorage,
    },
    Join {
        align: bool,
        backfill: bool,
        stack_spill: bool,
        reverse_justify: bool,
        storage: Option<RuleStorage>,
    },
    JoinPerPrimitive {
        storage: Option<RuleStorage>,
    },
    JoinDualClass {
        stack_spill: bool,
        fill_alternate: bool,
        reverse_justify: bool,
    },
    GotoStack,
    ConvertToPtr,
    HiddenReturn {
        void_lock: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PrototypeRule {
    pub(crate) killed_by_call: bool,
    pub(crate) conditions: Vec<PrototypeRuleCondition>,
    pub(crate) actions: Vec<PrototypeRuleAction>,
}

impl PrototypeRule {
    pub fn from_xml(input: xml::Node) -> Result<Self, DeserialiseError> {
        Self::from_xml_with(input, false)
    }

    pub fn from_xml_with(
        input: xml::Node,
        killed_by_call: bool,
    ) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "rule" {
            return Err(DeserialiseError::TagUnexpected(
                input.tag_name().name().to_owned(),
            ));
        }

        let mut conditions = Vec::new();
        let mut actions = Vec::new();

        for child in input.children().filter(xml::Node::is_element) {
            match child.tag_name().name() {
                "datatype" => {
                    conditions
                        .push(PrototypeRuleCondition::Datatype(DatatypeFilter::from_xml(child)?));
                }
                "varargs" => {
                    let first = child.attribute_int_opt("first", 0usize)?;
                    conditions.push(PrototypeRuleCondition::Varargs { first });
                }
                "position" => {
                    let index = child.attribute_int("index")?;
                    conditions.push(PrototypeRuleCondition::Position { index });
                }
                "datatype_at" => {
                    let index = child.attribute_int("index")?;
                    let inner = child
                        .children()
                        .filter(xml::Node::is_element)
                        .find(|n| n.tag_name().name() == "datatype")
                        .ok_or(DeserialiseError::Invariant(
                            "datatype_at missing nested datatype",
                        ))?;
                    let datatype = DatatypeFilter::from_xml(inner)?;
                    conditions.push(PrototypeRuleCondition::DatatypeAt { index, datatype });
                }
                "consume" => {
                    let storage = RuleStorage::from_attr(child, "storage")?;
                    actions.push(PrototypeRuleAction::Consume { storage });
                }
                "consume_extra" => {
                    let storage = RuleStorage::from_attr(child, "storage")?;
                    actions.push(PrototypeRuleAction::ConsumeExtra { storage });
                }
                "join" => {
                    actions.push(PrototypeRuleAction::Join {
                        align: child.attribute_bool_opt("align", false)?,
                        backfill: child.attribute_bool_opt("backfill", false)?,
                        stack_spill: child.attribute_bool_opt("stackspill", false)?,
                        reverse_justify: child.attribute_bool_opt("reversejustify", false)?,
                        storage: RuleStorage::from_attr_opt(child, "storage")?,
                    });
                }
                "join_per_primitive" => {
                    actions.push(PrototypeRuleAction::JoinPerPrimitive {
                        storage: RuleStorage::from_attr_opt(child, "storage")?,
                    });
                }
                "join_dual_class" => {
                    actions.push(PrototypeRuleAction::JoinDualClass {
                        stack_spill: child.attribute_bool_opt("stackspill", false)?,
                        fill_alternate: child.attribute_bool_opt("fillalternate", false)?,
                        reverse_justify: child.attribute_bool_opt("reversejustify", false)?,
                    });
                }
                "goto_stack" => {
                    actions.push(PrototypeRuleAction::GotoStack);
                }
                "convert_to_ptr" => {
                    actions.push(PrototypeRuleAction::ConvertToPtr);
                }
                "hidden_return" => {
                    actions.push(PrototypeRuleAction::HiddenReturn {
                        void_lock: child.attribute_bool_opt("voidlock", false)?,
                    });
                }
                tag => {
                    return Err(DeserialiseError::TagUnexpected(tag.to_owned()));
                }
            }
        }

        Ok(Self {
            killed_by_call,
            conditions,
            actions,
        })
    }

    pub fn killed_by_call(&self) -> bool {
        self.killed_by_call
    }

    pub fn conditions(&self) -> &[PrototypeRuleCondition] {
        &self.conditions
    }

    pub fn actions(&self) -> &[PrototypeRuleAction] {
        &self.actions
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Prototype {
    pub(crate) name: String,
    pub(crate) extra_pop: u64,
    pub(crate) stack_shift: u64,
    pub(crate) inputs: Vec<PrototypeEntry>,
    pub(crate) outputs: Vec<PrototypeEntry>,
    pub(crate) input_rules: Vec<PrototypeRule>,
    pub(crate) output_rules: Vec<PrototypeRule>,
    pub(crate) unaffected: Vec<PrototypeOperand>,
    pub(crate) killed_by_call: Vec<PrototypeOperand>,
    pub(crate) likely_trashed: Vec<PrototypeOperand>,
}

impl Prototype {
    pub fn from_xml(input: xml::Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "prototype" {
            return Err(DeserialiseError::TagUnexpected(
                input.tag_name().name().to_owned(),
            ));
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

        for child in input.children().filter(xml::Node::is_element) {
            match child.tag_name().name() {
                "input" => {
                    for c in child.children().filter(xml::Node::is_element) {
                        match c.tag_name().name() {
                            "pentry" => inputs.push(PrototypeEntry::from_xml(c, false)?),
                            "rule" => input_rules.push(PrototypeRule::from_xml(c)?),
                            _ => (),
                        }
                    }
                }
                "output" => {
                    let killed = child.attribute_bool("killedbycall").unwrap_or_default();
                    for c in child.children().filter(xml::Node::is_element) {
                        match c.tag_name().name() {
                            "pentry" => outputs.push(PrototypeEntry::from_xml(c, killed)?),
                            "rule" => {
                                output_rules.push(PrototypeRule::from_xml_with(c, killed)?)
                            }
                            _ => (),
                        }
                    }
                }
                "unaffected" => {
                    let mut values = child
                        .children()
                        .filter(xml::Node::is_element)
                        .filter_map(|op| PrototypeOperand::from_xml(op).ok())
                        .collect::<Vec<_>>();
                    unaffected.append(&mut values);
                }
                "killedbycall" => {
                    let mut values = child
                        .children()
                        .filter(xml::Node::is_element)
                        .filter_map(|op| PrototypeOperand::from_xml(op).ok())
                        .collect::<Vec<_>>();
                    killed_by_call.append(&mut values);
                }
                "likelytrash" => {
                    let mut values = child
                        .children()
                        .filter(xml::Node::is_element)
                        .filter_map(|op| PrototypeOperand::from_xml(op).ok())
                        .collect::<Vec<_>>();
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
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CompilerSpec {
    pub(crate) name: String,
    pub(crate) data_organisation: Option<DataOrganisation>,
    pub(crate) stack_pointer: StackPointer,
    pub(crate) return_address: Option<ReturnAddress>,
    pub(crate) default_prototype: Prototype,
    pub(crate) additional_prototypes: Vec<Prototype>,
    pub(crate) call_fixups: Vec<CallFixup>,
}

impl CompilerSpec {
    pub fn named_from_xml<N: Into<String>>(
        name: N,
        input: xml::Node,
    ) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "compiler_spec" {
            return Err(DeserialiseError::TagUnexpected(
                input.tag_name().name().to_owned(),
            ));
        }

        let mut data_organisation = None;
        let mut stack_pointer = None;
        let mut return_address = None;
        let mut default_prototype = None;
        let mut additional_prototypes = Vec::new();
        let mut call_fixups = Vec::new();

        for child in input.children().filter(xml::Node::is_element) {
            match child.tag_name().name() {
                "data_organization" => {
                    data_organisation = Some(DataOrganisation::from_xml(child)?);
                }
                "stackpointer" => {
                    stack_pointer = Some(StackPointer::from_xml(child)?);
                }
                "returnaddress" => {
                    return_address = Some(ReturnAddress::from_xml(child)?);
                }
                "default_proto" => {
                    let proto = child.children().find(xml::Node::is_element);
                    if proto.is_none() {
                        return Err(DeserialiseError::Invariant(
                                "compiler specification does not define prototype for default prototype"
                        ));
                    }
                    default_prototype = Some(Prototype::from_xml(proto.unwrap())?);
                }
                "prototype" => {
                    additional_prototypes.push(Prototype::from_xml(child)?);
                }
                "callfixup" => {
                    call_fixups.push(CallFixup::from_xml(child)?);
                }
                _ => (),
            }
        }

        if stack_pointer.is_none() {
            return Err(DeserialiseError::Invariant(
                "compiler specification does not define stack pointer configuration",
            ));
        }

        Ok(Self {
            name: name.into(),
            data_organisation,
            stack_pointer: stack_pointer.unwrap(),
            return_address,
            default_prototype: default_prototype.unwrap(),
            additional_prototypes,
            call_fixups,
        })
    }

    pub fn named_from_file<N: Into<String>, P: AsRef<Path>>(
        name: N,
        path: P,
    ) -> Result<Self, LanguageError> {
        let path = path.as_ref();
        let mut file = File::open(path).map_err(|error| LanguageError::ParseFile {
            path: path.to_owned(),
            error,
        })?;

        let mut input = String::new();
        file.read_to_string(&mut input)
            .map_err(|error| LanguageError::ParseFile {
                path: path.to_owned(),
                error,
            })?;

        Self::named_from_str(name, &input).map_err(|error| LanguageError::DeserialiseFile {
            path: path.to_owned(),
            error,
        })
    }

    pub fn named_from_str<N: Into<String>, S: AsRef<str>>(
        name: N,
        input: S,
    ) -> Result<Self, DeserialiseError> {
        let document = xml::Document::parse(input.as_ref()).map_err(DeserialiseError::Xml)?;

        let res = Self::named_from_xml(name, document.root_element());

        #[cfg(feature = "tracing")]
        if let Err(ref e) = res {
            tracing::debug!("load failed: {:?}", e);
        }

        res
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CallFixup {
    name: String,
    shift: i64,
    targets: UstrSet,
    pcode: String,
}

impl CallFixup {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn targets(&self) -> &UstrSet {
        &self.targets
    }

    pub fn pcode(&self) -> &str {
        &self.pcode
    }

    pub fn shift(&self) -> i64 {
        self.shift
    }
}

impl CallFixup {
    pub fn from_xml(input: xml::Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "callfixup" {
            return Err(DeserialiseError::TagUnexpected(
                input.tag_name().name().to_owned(),
            ));
        }

        let name = input.attribute_string("name")?;

        let mut targets = UstrSet::default();
        let mut pcode = None;
        let mut shift = 0;

        for child in input.children().filter(xml::Node::is_element) {
            match child.tag_name().name() {
                "target" => {
                    let name = child.attribute_string("name")?;
                    targets.insert(name.into());
                }
                "pcode" => {
                    if pcode.is_some() {
                        return Err(DeserialiseError::Invariant(
                            "call fixup has multiple bodies",
                        ));
                    }

                    // first child should be pcode
                    let Some(elt) = child.first_element_child() else {
                        return Err(DeserialiseError::Invariant(
                            "call fixup body does not contain any injectable pcode",
                        ));
                    };

                    if elt.tag_name().name() != "body" {
                        return Err(DeserialiseError::TagUnexpected(
                            elt.tag_name().name().to_owned(),
                        ));
                    }

                    if let Some(text) = elt.text().map(ToOwned::to_owned) {
                        shift = child.attribute_int_opt("paramshift", 0i64)?;
                        pcode = Some(text);
                    }
                }
                _ => (),
            }
        }

        if pcode.is_none() {
            return Err(DeserialiseError::Invariant(
                "call fixup does not define any injectable pcode",
            ));
        }

        Ok(Self {
            name,
            targets,
            shift,
            pcode: pcode.unwrap(),
        })
    }
}
