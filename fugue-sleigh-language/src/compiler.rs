use ahash::AHashMap as Map;
use roxmltree::Node;
use ustr::UstrSet;

use crate::deserialise::{DeserialiseError, XmlExt, parse_int_radix};
use crate::language::UserOpStr;

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
pub struct BitfieldPacking {
    use_ms_convention: bool,
    type_alignment_enabled: bool,
    zero_length_boundary: u16,
}

impl Default for BitfieldPacking {
    fn default() -> Self {
        Self::new(false, true, 0)
    }
}

impl BitfieldPacking {
    pub const fn new(
        use_ms_convention: bool,
        type_alignment_enabled: bool,
        zero_length_boundary: u16,
    ) -> Self {
        Self {
            use_ms_convention,
            type_alignment_enabled,
            zero_length_boundary,
        }
    }

    pub const fn use_ms_convention(&self) -> bool {
        self.use_ms_convention
    }

    pub const fn type_alignment_enabled(&self) -> bool {
        self.type_alignment_enabled
    }

    pub const fn zero_length_boundary(&self) -> u16 {
        self.zero_length_boundary
    }

    pub fn from_xml(input: Node) -> Result<Self, DeserialiseError> {
        let mut packing = Self::default();
        for child in input.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "use_MS_convention" => packing.use_ms_convention = child.attribute_bool("value")?,
                "type_alignment_enabled" => {
                    packing.type_alignment_enabled = child.attribute_bool("value")?
                }
                "zero_length_boundary" => {
                    packing.zero_length_boundary = child.attribute_int("value")?
                }
                tag => return Err(DeserialiseError::tag_unexpected(tag)),
            }
        }
        Ok(packing)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DataOrganisation {
    absolute_max_alignment: u64,
    machine_alignment: u64,
    default_alignment: u64,
    default_pointer_alignment: u64,
    pointer_size: u16,
    pointer_shift: u32,
    char_size: u16,
    char_signed: bool,
    wchar_size: u16,
    short_size: u16,
    integer_size: u16,
    long_size: u16,
    long_long_size: u16,
    float_size: u16,
    double_size: u16,
    long_double_size: u16,
    bitfield_packing: BitfieldPacking,
    alignments: Map<u16, u64>,
}

impl Default for DataOrganisation {
    fn default() -> Self {
        Self {
            absolute_max_alignment: 0,
            machine_alignment: 1,
            default_alignment: 1,
            default_pointer_alignment: 4,
            pointer_size: 4,
            pointer_shift: 0,
            char_size: 1,
            char_signed: true,
            wchar_size: 2,
            short_size: 2,
            integer_size: 4,
            long_size: 4,
            long_long_size: 8,
            float_size: 4,
            double_size: 8,
            long_double_size: 12,
            bitfield_packing: BitfieldPacking::new(false, true, 0),
            alignments: Map::from_iter([(1, 1), (2, 2), (4, 4), (8, 8)]),
        }
    }
}

impl DataOrganisation {
    pub fn from_xml(input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "data_organization" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }

        let mut data = Self::default();

        for child in input.children().filter(Node::is_element) {
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
                "pointer_shift" => data.pointer_shift = child.attribute_int("value")?,
                "char_size" => data.char_size = child.attribute_int("value")?,
                "char_type" => data.char_signed = child.attribute_bool("signed")?,
                "bitfield_packing" => data.bitfield_packing = BitfieldPacking::from_xml(child)?,
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
                        let size = entry.attribute_int("size")?;
                        let alignment = entry.attribute_int("alignment")?;
                        data.alignments.insert(size, alignment);
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

    pub fn pointer_size(&self) -> u16 {
        self.pointer_size
    }

    pub fn wchar_size(&self) -> u16 {
        self.wchar_size
    }

    pub fn short_size(&self) -> u16 {
        self.short_size
    }

    pub fn integer_size(&self) -> u16 {
        self.integer_size
    }

    pub fn long_size(&self) -> u16 {
        self.long_size
    }

    pub fn long_long_size(&self) -> u16 {
        self.long_long_size
    }

    pub fn float_size(&self) -> u16 {
        self.float_size
    }

    pub fn double_size(&self) -> u16 {
        self.double_size
    }

    pub fn long_double_size(&self) -> u16 {
        self.long_double_size
    }

    pub fn pointer_shift(&self) -> u32 {
        self.pointer_shift
    }

    pub fn char_size(&self) -> u16 {
        self.char_size
    }

    pub fn char_signed(&self) -> bool {
        self.char_signed
    }

    pub fn bitfield_packing(&self) -> BitfieldPacking {
        self.bitfield_packing
    }

    pub fn alignments(&self) -> impl Iterator<Item = (u16, u64)> {
        self.alignments
            .iter()
            .map(|(size, alignment)| (*size, *alignment))
    }

    pub fn alignment(&self, size: u16) -> u64 {
        self.alignments
            .get(&size)
            .copied()
            .unwrap_or_else(|| self.default_alignment())
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
pub enum DatatypeKind {
    Any,
    Array,
    Boolean,
    Code,
    Float,
    HomogeneousFloatAggregate,
    Integer,
    PartialStruct,
    PartialUnion,
    Pointer,
    RelativePointer,
    SignedEnumeration,
    SpaceBase,
    Struct,
    Union,
    Unknown,
    UnsignedEnumeration,
    UnsignedInteger,
    Void,
}

impl DatatypeKind {
    pub fn from_name(name: &str) -> Result<Self, DeserialiseError> {
        match name {
            "any" => Ok(Self::Any),
            "array" => Ok(Self::Array),
            "bool" => Ok(Self::Boolean),
            "code" => Ok(Self::Code),
            "float" => Ok(Self::Float),
            "homogeneous-float-aggregate" => Ok(Self::HomogeneousFloatAggregate),
            "int" => Ok(Self::Integer),
            "partstruct" => Ok(Self::PartialStruct),
            "partunion" => Ok(Self::PartialUnion),
            "ptr" | "pointer" => Ok(Self::Pointer),
            "ptrrel" => Ok(Self::RelativePointer),
            "enum_int" => Ok(Self::SignedEnumeration),
            "spacebase" => Ok(Self::SpaceBase),
            "struct" => Ok(Self::Struct),
            "union" => Ok(Self::Union),
            "unknown" => Ok(Self::Unknown),
            "enum_uint" => Ok(Self::UnsignedEnumeration),
            "uint" => Ok(Self::UnsignedInteger),
            "void" => Ok(Self::Void),
            _ => Err(DeserialiseError::invariant(
                "unknown datatype name in prototype rule",
            )),
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
pub enum RuleStorage {
    Class1,
    Class2,
    Class3,
    Class4,
    Float,
    General,
    HiddenReturn,
    Pointer,
    Vector,
}

impl RuleStorage {
    pub fn from_attr_opt(node: Node, name: &'static str) -> Result<Option<Self>, DeserialiseError> {
        match node.attribute(name) {
            Some("class1") => Ok(Some(Self::Class1)),
            Some("class2") => Ok(Some(Self::Class2)),
            Some("class3") => Ok(Some(Self::Class3)),
            Some("class4") => Ok(Some(Self::Class4)),
            Some("float") => Ok(Some(Self::Float)),
            Some("general") | Some("unknown") => Ok(Some(Self::General)),
            Some("hiddenret") => Ok(Some(Self::HiddenReturn)),
            Some("ptr") | Some("pointer") => Ok(Some(Self::Pointer)),
            Some("vector") => Ok(Some(Self::Vector)),
            Some(_) => Err(DeserialiseError::invariant(
                "unknown prototype storage class",
            )),
            None => Ok(None),
        }
    }

    pub fn from_attr(node: Node, name: &'static str) -> Result<Self, DeserialiseError> {
        Self::from_attr_opt(node, name)?.ok_or(DeserialiseError::attribute_expected(name))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DatatypeFilter {
    kind: DatatypeKind,
    min_size: Option<u16>,
    max_size: Option<u16>,
    sizes: Vec<u16>,
    min_elements: Option<u32>,
    max_elements: Option<u32>,
    max_primitives: Option<u32>,
}

impl DatatypeFilter {
    pub fn from_xml(input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "datatype" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }

        let kind = DatatypeKind::from_name(&input.attribute_string("name")?)?;

        let min_size = input
            .attribute("minsize")
            .map(parse_int_radix)
            .transpose()?;
        let max_size = input
            .attribute("maxsize")
            .map(parse_int_radix)
            .transpose()?;
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
            min_elements: input
                .attribute("minelements")
                .map(parse_int_radix)
                .transpose()?,
            max_elements: input
                .attribute("maxelements")
                .map(parse_int_radix)
                .transpose()?,
        })
    }

    pub fn kind(&self) -> DatatypeKind {
        self.kind
    }

    pub fn min_size(&self) -> Option<u16> {
        self.min_size
    }

    pub fn max_size(&self) -> Option<u16> {
        self.max_size
    }

    pub fn sizes(&self) -> &[u16] {
        &self.sizes
    }

    pub fn min_elements(&self) -> Option<u32> {
        self.min_elements
    }

    pub fn max_elements(&self) -> Option<u32> {
        self.max_elements
    }

    pub fn max_primitives(&self) -> Option<u32> {
        self.max_primitives
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
pub enum HiddenReturnStrategy {
    NormalParameter,
    Special,
}

impl HiddenReturnStrategy {
    fn from_name(name: &str) -> Result<Self, DeserialiseError> {
        match name {
            "normalparam" => Ok(Self::NormalParameter),
            "special" => Ok(Self::Special),
            _ => Err(DeserialiseError::invariant(
                "unknown hidden return strategy",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum PrototypeRuleCondition {
    Datatype(DatatypeFilter),
    DatatypeAt {
        index: i32,
        datatype: DatatypeFilter,
    },
    Position {
        index: i32,
    },
    Varargs {
        first: Option<i32>,
        last: Option<i32>,
    },
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
pub enum PrototypeRuleAction {
    Consume {
        storage: RuleStorage,
    },
    ConsumeExtra {
        storage: Option<RuleStorage>,
        match_size: Option<bool>,
    },
    ConsumeRemaining {
        storage: RuleStorage,
    },
    ConvertToPtr,
    ExtraStack {
        after_bytes: Option<u16>,
        after_storage: Option<RuleStorage>,
    },
    GotoStack,
    HiddenReturn {
        void_lock: bool,
        strategy: Option<HiddenReturnStrategy>,
    },
    Join {
        align: bool,
        backfill: bool,
        stack_spill: Option<bool>,
        reverse_justify: bool,
        reverse_significance: bool,
        storage: Option<RuleStorage>,
    },
    JoinDualClass {
        storage: Option<RuleStorage>,
        first_storage: Option<RuleStorage>,
        second_storage: Option<RuleStorage>,
        stack_spill: Option<bool>,
        fill_alternate: bool,
        reverse_justify: bool,
        reverse_significance: bool,
    },
    JoinPerPrimitive {
        storage: Option<RuleStorage>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PrototypeRule {
    killed_by_call: bool,
    conditions: Vec<PrototypeRuleCondition>,
    actions: Vec<PrototypeRuleAction>,
}

impl PrototypeRule {
    pub fn from_xml(input: Node) -> Result<Self, DeserialiseError> {
        Self::from_xml_with(false, input)
    }

    pub fn from_xml_with(killed_by_call: bool, input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "rule" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }

        let mut conditions = Vec::new();
        let mut actions = Vec::new();

        for child in input.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "datatype" => {
                    conditions.push(PrototypeRuleCondition::Datatype(DatatypeFilter::from_xml(
                        child,
                    )?));
                }
                "varargs" => {
                    let first = child.attribute("first").map(parse_int_radix).transpose()?;
                    conditions.push(PrototypeRuleCondition::Varargs {
                        first,
                        last: child.attribute("last").map(parse_int_radix).transpose()?,
                    });
                }
                "position" => {
                    let index = child.attribute_int("index")?;
                    conditions.push(PrototypeRuleCondition::Position { index });
                }
                "datatype_at" => {
                    let index = child.attribute_int("index")?;
                    let inner = child
                        .children()
                        .filter(Node::is_element)
                        .find(|n| n.tag_name().name() == "datatype")
                        .ok_or(DeserialiseError::invariant(
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
                    let storage = RuleStorage::from_attr_opt(child, "storage")?;
                    actions.push(PrototypeRuleAction::ConsumeExtra {
                        storage,
                        match_size: child
                            .attribute("matchsize")
                            .map(|_| child.attribute_bool("matchsize"))
                            .transpose()?,
                    });
                }
                "consume_remaining" => actions.push(PrototypeRuleAction::ConsumeRemaining {
                    storage: RuleStorage::from_attr(child, "storage")?,
                }),
                "extra_stack" => actions.push(PrototypeRuleAction::ExtraStack {
                    after_bytes: child
                        .attribute("afterbytes")
                        .map(parse_int_radix)
                        .transpose()?,
                    after_storage: RuleStorage::from_attr_opt(child, "afterstorage")?,
                }),
                "join" => {
                    actions.push(PrototypeRuleAction::Join {
                        align: child.attribute_bool_opt("align", false)?,
                        backfill: child.attribute_bool_opt("backfill", false)?,
                        stack_spill: child
                            .attribute("stackspill")
                            .map(|_| child.attribute_bool("stackspill"))
                            .transpose()?,
                        reverse_justify: child.attribute_bool_opt("reversejustify", false)?,
                        reverse_significance: child.attribute_bool_opt("reversesignif", false)?,
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
                        storage: RuleStorage::from_attr_opt(child, "storage")?,
                        first_storage: RuleStorage::from_attr_opt(child, "a")?,
                        second_storage: RuleStorage::from_attr_opt(child, "b")?,
                        stack_spill: child
                            .attribute("stackspill")
                            .map(|_| child.attribute_bool("stackspill"))
                            .transpose()?,
                        fill_alternate: child.attribute_bool_opt("fillalternate", false)?,
                        reverse_justify: child.attribute_bool_opt("reversejustify", false)?,
                        reverse_significance: child.attribute_bool_opt("reversesignif", false)?,
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
                        strategy: child
                            .attribute("strategy")
                            .map(HiddenReturnStrategy::from_name)
                            .transpose()?,
                    });
                }
                tag => {
                    return Err(DeserialiseError::tag_unexpected(tag));
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
pub struct InjectParameter {
    name: String,
    size: Option<u16>,
}

impl InjectParameter {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn size(&self) -> Option<u16> {
        self.size
    }

    pub fn from_xml(input: Node) -> Result<Self, DeserialiseError> {
        Ok(Self {
            name: input.attribute_string("name")?,
            size: input.attribute("size").map(parse_int_radix).transpose()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct InjectPayload {
    body: Option<String>,
    inputs: Vec<InjectParameter>,
    outputs: Vec<InjectParameter>,
    param_shift: i64,
    dynamic: bool,
    incidental_copy: bool,
}

impl InjectPayload {
    pub fn body(&self) -> Option<&str> {
        self.body.as_deref()
    }

    pub fn inputs(&self) -> &[InjectParameter] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[InjectParameter] {
        &self.outputs
    }

    pub fn param_shift(&self) -> i64 {
        self.param_shift
    }

    pub fn dynamic(&self) -> bool {
        self.dynamic
    }

    pub fn incidental_copy(&self) -> bool {
        self.incidental_copy
    }

    pub fn from_xml(input: Node) -> Result<Self, DeserialiseError> {
        let mut body = None;
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let dynamic = input.attribute_bool_opt("dynamic", false)?;
        for child in input.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "input" => inputs.push(InjectParameter::from_xml(child)?),
                "output" => outputs.push(InjectParameter::from_xml(child)?),
                "body" => {
                    if body.is_some() {
                        return Err(DeserialiseError::invariant(
                            "injection payload has multiple bodies",
                        ));
                    }
                    body = Some(child.text().unwrap_or_default().to_owned());
                }
                tag => return Err(DeserialiseError::tag_unexpected(tag)),
            }
        }
        if body.is_none() && !dynamic {
            return Err(DeserialiseError::invariant(
                "injection payload requires a body or dynamic provider",
            ));
        }
        Ok(Self {
            body,
            inputs,
            outputs,
            param_shift: input.attribute_int_opt("paramshift", 0)?,
            dynamic,
            incidental_copy: input.attribute_bool_opt("incidentalcopy", false)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CallFixup {
    name: String,
    targets: UstrSet,
    payload: InjectPayload,
}

impl CallFixup {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn targets(&self) -> &UstrSet {
        &self.targets
    }

    pub fn payload(&self) -> &InjectPayload {
        &self.payload
    }

    pub fn pcode(&self) -> &str {
        self.payload.body().unwrap_or_default()
    }

    pub fn shift(&self) -> i64 {
        self.payload.param_shift()
    }

    pub fn from_xml(input: Node) -> Result<Self, DeserialiseError> {
        if input.tag_name().name() != "callfixup" {
            return Err(DeserialiseError::tag_unexpected(input.tag_name().name()));
        }
        let mut targets = UstrSet::default();
        let mut payload = None;
        for child in input.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "target" => {
                    targets.insert(child.attribute_string("name")?.into());
                }
                "pcode" => {
                    if payload.is_some() {
                        return Err(DeserialiseError::invariant(
                            "call fixup has multiple payloads",
                        ));
                    }
                    payload = Some(InjectPayload::from_xml(child)?);
                }
                tag => return Err(DeserialiseError::tag_unexpected(tag)),
            }
        }
        Ok(Self {
            name: input.attribute_string("name")?,
            targets,
            payload: payload.ok_or(DeserialiseError::invariant(
                "call fixup requires an injection payload",
            ))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct UserOpFixup {
    target_op: UserOpStr,
    payload: InjectPayload,
}

impl UserOpFixup {
    pub fn target_op(&self) -> UserOpStr {
        self.target_op
    }

    pub fn payload(&self) -> &InjectPayload {
        &self.payload
    }

    pub fn from_xml(input: Node) -> Result<Self, DeserialiseError> {
        let mut payload = None;
        for child in input.children().filter(Node::is_element) {
            if child.tag_name().name() != "pcode" {
                return Err(DeserialiseError::tag_unexpected(child.tag_name().name()));
            }
            if payload.is_some() {
                return Err(DeserialiseError::invariant(
                    "callother fixup has multiple payloads",
                ));
            }
            payload = Some(InjectPayload::from_xml(child)?);
        }
        Ok(Self {
            target_op: input.attribute_str("targetop")?.into(),
            payload: payload.ok_or(DeserialiseError::invariant(
                "callother fixup requires an injection payload",
            ))?,
        })
    }
}
