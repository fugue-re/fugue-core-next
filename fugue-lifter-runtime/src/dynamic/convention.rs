use fugue_sleigh_language::compiler::{
    BitfieldPacking, CallFixup as SleighCallFixup, DataOrganisation as SleighDataOrganisation,
    DatatypeFilter as SleighDatatypeFilter, DatatypeKind, InjectParameter as SleighInjectParameter,
    InjectPayload as SleighInjectPayload, PrototypeRule as SleighPrototypeRule,
    PrototypeRuleAction, PrototypeRuleCondition as SleighPrototypeRuleCondition, RuleStorage,
    UserOpFixup as SleighUserOpFixup,
};
use fugue_sleigh_language::convention::{
    Convention as SleighConvention, JoinPiece as SleighJoinPiece,
    PreferredVarnodeSplit as SleighPreferredVarnodeSplit, Prototype as SleighPrototype,
    PrototypeAlias as SleighPrototypeAlias, PrototypeEntry as SleighPrototypeEntry,
    PrototypeOperand as SleighPrototypeOperand, PrototypeReference,
    PrototypeResolution as SleighPrototypeResolution, ReturnAddress as SleighReturnAddress,
};
use itertools::Itertools;

use crate::convention::{
    CallFixup as StaticCallFixup, Convention as StaticConvention,
    DataOrganisation as StaticDataOrganisation, DatatypeFilter as StaticDatatypeFilter,
    InjectParameter as StaticInjectParameter, InjectPayload as StaticInjectPayload,
    JoinPiece as StaticJoinPiece, PreferredVarnodeSplit as StaticPreferredVarnodeSplit,
    Prototype as StaticPrototype, PrototypeAlias as StaticPrototypeAlias,
    PrototypeEntry as StaticPrototypeEntry, PrototypeOperand as StaticPrototypeOperand,
    PrototypeResolution as StaticPrototypeResolution, PrototypeRule as StaticPrototypeRule,
    PrototypeRuleCondition as StaticPrototypeRuleCondition, ReturnAddress as StaticReturnAddress,
    UserOpFixup as StaticUserOpFixup,
};
use crate::dynamic::install::Install;
use crate::dynamic::processor::{SegmentOp, StorageLocation};
use crate::pcode::Varnode;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) enum ReturnAddress {
    Register(Varnode),
    StackRelative { offset: u64, size: u16 },
}

impl From<&SleighReturnAddress> for ReturnAddress {
    fn from(return_address: &SleighReturnAddress) -> Self {
        match return_address {
            SleighReturnAddress::Register { varnode, .. } => Self::Register(varnode.into()),
            SleighReturnAddress::StackRelative { offset, size } => Self::StackRelative {
                offset: *offset,
                size: *size,
            },
        }
    }
}

impl Install for ReturnAddress {
    type Target = StaticReturnAddress;

    fn install(self) -> Self::Target {
        match self {
            Self::Register(varnode) => Self::Target::Register(varnode),
            Self::StackRelative { offset, size } => Self::Target::StackRelative { offset, size },
        }
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct Convention {
    name: Box<str>,
    stack_pointer: Varnode,
    return_address: Option<ReturnAddress>,
    prototypes: Box<[Prototype]>,
    data_organisation: Option<DataOrganisation>,
    call_fixups: Box<[CallFixup]>,
    user_op_fixups: Box<[UserOpFixup]>,
    function_pointer_alignment: Option<u64>,
    global_ranges: Box<[StorageLocation]>,
    aggressive_trim: bool,
    preferred_varnode_splits: Box<[StaticPreferredVarnodeSplit]>,
    prototype_aliases: Box<[PrototypeAlias]>,
    prototype_resolutions: Box<[PrototypeResolution]>,
    eval_current_prototype: Option<PrototypeReference>,
    properties: Box<[(Box<str>, Box<str>)]>,
    segment_ops: Box<[SegmentOp]>,
}

impl From<&SleighConvention> for Convention {
    fn from(convention: &SleighConvention) -> Self {
        Self {
            name: Box::<str>::from(convention.name()),
            stack_pointer: convention.stack_pointer().varnode().into(),
            return_address: convention.return_address().map(Into::into),
            prototypes: convention.prototypes().map(Into::into).collect(),
            data_organisation: convention.data_organisation().map(Into::into),
            call_fixups: convention.call_fixups().iter().map(Into::into).collect(),
            user_op_fixups: convention.user_op_fixups().iter().map(Into::into).collect(),
            function_pointer_alignment: convention.function_pointer_alignment(),
            global_ranges: convention.global_ranges().iter().map(Into::into).collect(),
            aggressive_trim: convention.aggressive_trim(),
            preferred_varnode_splits: convention
                .preferred_varnode_splits()
                .iter()
                .map(Into::into)
                .collect(),
            prototype_aliases: convention
                .prototype_aliases()
                .iter()
                .map(Into::into)
                .collect(),
            prototype_resolutions: convention
                .prototype_resolutions()
                .iter()
                .map(Into::into)
                .collect(),
            eval_current_prototype: convention.eval_current_prototype(),
            properties: convention
                .properties()
                .iter()
                .map(|(key, value)| {
                    (
                        Box::<str>::from(key.as_str()),
                        Box::<str>::from(value.as_str()),
                    )
                })
                .sorted_unstable_by(|(a, _), (b, _)| a.cmp(b))
                .collect(),
            segment_ops: convention.segment_ops().iter().map(Into::into).collect(),
        }
    }
}

impl Install for Convention {
    type Target = StaticConvention;

    fn install(self) -> Self::Target {
        let mut convention = Self::Target::new(self.name.install(), self.stack_pointer)
            .with_prototypes(self.prototypes.install())
            .with_data_organisation(self.data_organisation.install())
            .with_call_fixups(self.call_fixups.install())
            .with_user_op_fixups(self.user_op_fixups.install())
            .with_function_pointer_alignment(self.function_pointer_alignment)
            .with_global_ranges(self.global_ranges.install())
            .with_aggressive_trim(self.aggressive_trim)
            .with_preferred_varnode_splits(self.preferred_varnode_splits.install())
            .with_prototype_aliases(self.prototype_aliases.install())
            .with_prototype_resolutions(self.prototype_resolutions.install())
            .with_eval_current_prototype(self.eval_current_prototype)
            .with_properties(self.properties.install())
            .with_segment_ops(self.segment_ops.install());
        if let Some(return_address) = self.return_address {
            convention = convention.with_return_address(return_address.install());
        }
        convention
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) enum PrototypeOperand {
    Address {
        space: u8,
        offset: u64,
        size: Option<u16>,
    },
    Join {
        pieces: Box<[StaticJoinPiece]>,
        logical_size: Option<u16>,
    },
    Register(Varnode),
    RegisterJoin(Varnode, Varnode),
    StackRelative {
        offset: u64,
        size: Option<u16>,
    },
}

impl From<&SleighPrototypeOperand> for PrototypeOperand {
    fn from(operand: &SleighPrototypeOperand) -> Self {
        match operand {
            SleighPrototypeOperand::Address {
                space,
                offset,
                size,
            } => Self::Address {
                space: u8::try_from(space.index()).expect("address-space identifier fits in u8"),
                offset: *offset,
                size: *size,
            },
            SleighPrototypeOperand::Join {
                pieces,
                logical_size,
            } => Self::Join {
                pieces: pieces
                    .iter()
                    .map(|piece| match piece {
                        SleighJoinPiece::StackRelative { offset, size } => {
                            StaticJoinPiece::StackRelative {
                                offset: *offset,
                                size: *size,
                            }
                        }
                        SleighJoinPiece::Location(varnode) => StaticJoinPiece::Location {
                            space: u8::try_from(varnode.space().index())
                                .expect("address-space identifier fits in u8"),
                            offset: varnode.offset(),
                            size: u16::try_from(varnode.size()).expect("varnode size fits in u16"),
                        },
                    })
                    .collect(),
                logical_size: *logical_size,
            },
            SleighPrototypeOperand::Register { varnode, .. } => Self::Register(varnode.into()),
            SleighPrototypeOperand::RegisterJoin {
                first_varnode,
                second_varnode,
                ..
            } => Self::RegisterJoin(first_varnode.into(), second_varnode.into()),
            SleighPrototypeOperand::StackRelative { offset, size } => Self::StackRelative {
                offset: *offset,
                size: *size,
            },
        }
    }
}

impl Install for PrototypeOperand {
    type Target = StaticPrototypeOperand;

    fn install(self) -> Self::Target {
        match self {
            Self::Address {
                space,
                offset,
                size,
            } => Self::Target::Address {
                space,
                offset,
                size,
            },
            Self::Join {
                pieces,
                logical_size,
            } => Self::Target::Join {
                pieces: pieces.install(),
                logical_size,
            },
            Self::Register(varnode) => Self::Target::Register(varnode),
            Self::RegisterJoin(first, second) => Self::Target::RegisterJoin(first, second),
            Self::StackRelative { offset, size } => Self::Target::StackRelative { offset, size },
        }
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct PrototypeEntry {
    min_size: u16,
    max_size: u16,
    alignment: u64,
    meta_type: Option<Box<str>>,
    extension: Option<Box<str>>,
    operand: PrototypeOperand,
    killed_by_call: bool,
    storage: Option<RuleStorage>,
    group: Option<u32>,
}

impl From<&SleighPrototypeEntry> for PrototypeEntry {
    fn from(entry: &SleighPrototypeEntry) -> Self {
        Self {
            min_size: entry.min_size(),
            max_size: entry.max_size(),
            alignment: entry.alignment(),
            meta_type: entry.meta_type().as_deref().map(Box::<str>::from),
            extension: entry.extension().as_deref().map(Box::<str>::from),
            operand: entry.operand().into(),
            killed_by_call: entry.killed_by_call(),
            storage: entry.storage(),
            group: entry.group(),
        }
    }
}

impl Install for PrototypeEntry {
    type Target = StaticPrototypeEntry;

    fn install(self) -> Self::Target {
        let mut entry = Self::Target::new(
            self.min_size,
            self.max_size,
            self.alignment,
            self.operand.install(),
        )
        .with_killed_by_call(self.killed_by_call)
        .with_storage(self.storage)
        .with_group(self.group);
        if let Some(meta_type) = self.meta_type {
            entry = entry.with_meta_type(meta_type.install());
        }
        if let Some(extension) = self.extension {
            entry = entry.with_extension(extension.install());
        }
        entry
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct Prototype {
    name: Box<str>,
    extra_pop: u64,
    stack_shift: u64,
    inputs: Box<[PrototypeEntry]>,
    outputs: Box<[PrototypeEntry]>,
    input_rules: Box<[PrototypeRule]>,
    output_rules: Box<[PrototypeRule]>,
    unaffected: Box<[PrototypeOperand]>,
    killed_by_call: Box<[PrototypeOperand]>,
    likely_trashed: Box<[PrototypeOperand]>,
    local_ranges: Box<[StorageLocation]>,
    internal_storage: Box<[Varnode]>,
}

impl From<&SleighPrototype> for Prototype {
    fn from(prototype: &SleighPrototype) -> Self {
        Self {
            name: Box::<str>::from(prototype.name()),
            extra_pop: prototype.extra_pop(),
            stack_shift: prototype.stack_shift(),
            inputs: prototype.inputs().iter().map(Into::into).collect(),
            outputs: prototype.outputs().iter().map(Into::into).collect(),
            input_rules: prototype.input_rules().iter().map(Into::into).collect(),
            output_rules: prototype.output_rules().iter().map(Into::into).collect(),
            unaffected: prototype.unaffected().iter().map(Into::into).collect(),
            killed_by_call: prototype.killed_by_call().iter().map(Into::into).collect(),
            likely_trashed: prototype.likely_trashed().iter().map(Into::into).collect(),
            local_ranges: prototype.local_ranges().iter().map(Into::into).collect(),
            internal_storage: prototype
                .internal_storage()
                .iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl Install for Prototype {
    type Target = StaticPrototype;

    fn install(self) -> Self::Target {
        Self::Target::new(self.name.install(), self.extra_pop, self.stack_shift)
            .with_inputs(self.inputs.install())
            .with_outputs(self.outputs.install())
            .with_input_rules(self.input_rules.install())
            .with_output_rules(self.output_rules.install())
            .with_unaffected(self.unaffected.install())
            .with_killed_by_call(self.killed_by_call.install())
            .with_likely_trashed(self.likely_trashed.install())
            .with_local_ranges(self.local_ranges.install())
            .with_internal_storage(self.internal_storage.install())
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct DataOrganisation {
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
    alignments: Box<[(u16, u64)]>,
}

impl From<&SleighDataOrganisation> for DataOrganisation {
    fn from(organisation: &SleighDataOrganisation) -> Self {
        Self {
            absolute_max_alignment: organisation.absolute_max_alignment(),
            machine_alignment: organisation.machine_alignment(),
            default_alignment: organisation.default_alignment(),
            default_pointer_alignment: organisation.default_pointer_alignment(),
            pointer_size: organisation.pointer_size(),
            pointer_shift: organisation.pointer_shift(),
            char_size: organisation.char_size(),
            char_signed: organisation.char_signed(),
            wchar_size: organisation.wchar_size(),
            short_size: organisation.short_size(),
            integer_size: organisation.integer_size(),
            long_size: organisation.long_size(),
            long_long_size: organisation.long_long_size(),
            float_size: organisation.float_size(),
            double_size: organisation.double_size(),
            long_double_size: organisation.long_double_size(),
            bitfield_packing: organisation.bitfield_packing(),
            alignments: organisation
                .alignments()
                .sorted_unstable_by_key(|(size, _)| *size)
                .collect(),
        }
    }
}

impl Install for DataOrganisation {
    type Target = StaticDataOrganisation;

    fn install(self) -> Self::Target {
        Self::Target::new(self.alignments.install())
            .with_absolute_max_alignment(self.absolute_max_alignment)
            .with_machine_alignment(self.machine_alignment)
            .with_default_alignment(self.default_alignment)
            .with_default_pointer_alignment(self.default_pointer_alignment)
            .with_pointer_size(self.pointer_size)
            .with_pointer_shift(self.pointer_shift)
            .with_char_size(self.char_size)
            .with_char_signed(self.char_signed)
            .with_wchar_size(self.wchar_size)
            .with_short_size(self.short_size)
            .with_integer_size(self.integer_size)
            .with_long_size(self.long_size)
            .with_long_long_size(self.long_long_size)
            .with_float_size(self.float_size)
            .with_double_size(self.double_size)
            .with_long_double_size(self.long_double_size)
            .with_bitfield_packing(self.bitfield_packing)
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct DatatypeFilter {
    kind: DatatypeKind,
    sizes: Box<[u16]>,
    min_size: Option<u16>,
    max_size: Option<u16>,
    max_primitives: Option<u32>,
    min_elements: Option<u32>,
    max_elements: Option<u32>,
}

impl From<&SleighDatatypeFilter> for DatatypeFilter {
    fn from(filter: &SleighDatatypeFilter) -> Self {
        Self {
            kind: filter.kind(),
            sizes: filter.sizes().into(),
            min_size: filter.min_size(),
            max_size: filter.max_size(),
            max_primitives: filter.max_primitives(),
            min_elements: filter.min_elements(),
            max_elements: filter.max_elements(),
        }
    }
}

impl Install for DatatypeFilter {
    type Target = StaticDatatypeFilter;

    fn install(self) -> Self::Target {
        Self::Target::new(self.kind, self.sizes.install())
            .with_min_size(self.min_size)
            .with_max_size(self.max_size)
            .with_max_primitives(self.max_primitives)
            .with_min_elements(self.min_elements)
            .with_max_elements(self.max_elements)
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct PrototypeRule {
    killed_by_call: bool,
    conditions: Box<[PrototypeRuleCondition]>,
    actions: Box<[PrototypeRuleAction]>,
}

impl From<&SleighPrototypeRule> for PrototypeRule {
    fn from(rule: &SleighPrototypeRule) -> Self {
        Self {
            killed_by_call: rule.killed_by_call(),
            conditions: rule.conditions().iter().map(Into::into).collect(),
            actions: rule.actions().into(),
        }
    }
}

impl Install for PrototypeRule {
    type Target = StaticPrototypeRule;

    fn install(self) -> Self::Target {
        Self::Target::new(
            self.killed_by_call,
            self.conditions.install(),
            self.actions.install(),
        )
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct InjectParameter {
    name: Box<str>,
    size: Option<u16>,
}

impl From<&SleighInjectParameter> for InjectParameter {
    fn from(parameter: &SleighInjectParameter) -> Self {
        Self {
            name: Box::<str>::from(parameter.name()),
            size: parameter.size(),
        }
    }
}

impl Install for InjectParameter {
    type Target = StaticInjectParameter;

    fn install(self) -> Self::Target {
        Self::Target::new(self.name.install(), self.size)
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct InjectPayload {
    body: Option<Box<str>>,
    inputs: Box<[InjectParameter]>,
    outputs: Box<[InjectParameter]>,
    param_shift: i64,
    dynamic: bool,
    incidental_copy: bool,
}

impl From<&SleighInjectPayload> for InjectPayload {
    fn from(payload: &SleighInjectPayload) -> Self {
        Self {
            body: payload.body().map(Box::<str>::from),
            inputs: payload.inputs().iter().map(Into::into).collect(),
            outputs: payload.outputs().iter().map(Into::into).collect(),
            param_shift: payload.param_shift(),
            dynamic: payload.dynamic(),
            incidental_copy: payload.incidental_copy(),
        }
    }
}

impl Install for InjectPayload {
    type Target = StaticInjectPayload;

    fn install(self) -> Self::Target {
        Self::Target::new(
            self.body.install(),
            self.inputs.install(),
            self.outputs.install(),
        )
        .with_param_shift(self.param_shift)
        .with_dynamic(self.dynamic)
        .with_incidental_copy(self.incidental_copy)
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct CallFixup {
    name: Box<str>,
    targets: Box<[Box<str>]>,
    payload: InjectPayload,
}

impl From<&SleighCallFixup> for CallFixup {
    fn from(fixup: &SleighCallFixup) -> Self {
        Self {
            name: Box::<str>::from(fixup.name()),
            targets: fixup
                .targets()
                .iter()
                .map(|name| Box::<str>::from(name.as_str()))
                .sorted_unstable()
                .collect(),
            payload: fixup.payload().into(),
        }
    }
}

impl Install for CallFixup {
    type Target = StaticCallFixup;

    fn install(self) -> Self::Target {
        Self::Target::new(
            self.name.install(),
            self.targets.install(),
            self.payload.install(),
        )
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct UserOpFixup {
    target_op: Box<str>,
    payload: InjectPayload,
}

impl From<&SleighUserOpFixup> for UserOpFixup {
    fn from(fixup: &SleighUserOpFixup) -> Self {
        Self {
            target_op: Box::<str>::from(fixup.target_op().as_str()),
            payload: fixup.payload().into(),
        }
    }
}

impl Install for UserOpFixup {
    type Target = StaticUserOpFixup;

    fn install(self) -> Self::Target {
        Self::Target::new(self.target_op.install(), self.payload.install())
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) enum PrototypeRuleCondition {
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

impl From<&SleighPrototypeRuleCondition> for PrototypeRuleCondition {
    fn from(condition: &SleighPrototypeRuleCondition) -> Self {
        match condition {
            SleighPrototypeRuleCondition::Datatype(filter) => Self::Datatype(filter.into()),
            SleighPrototypeRuleCondition::DatatypeAt { index, datatype } => Self::DatatypeAt {
                index: *index,
                datatype: datatype.into(),
            },
            SleighPrototypeRuleCondition::Position { index } => Self::Position { index: *index },
            SleighPrototypeRuleCondition::Varargs { first, last } => Self::Varargs {
                first: *first,
                last: *last,
            },
        }
    }
}

impl Install for PrototypeRuleCondition {
    type Target = StaticPrototypeRuleCondition;

    fn install(self) -> Self::Target {
        match self {
            Self::Datatype(filter) => Self::Target::Datatype(filter.install()),
            Self::DatatypeAt { index, datatype } => Self::Target::DatatypeAt {
                index,
                datatype: datatype.install(),
            },
            Self::Position { index } => Self::Target::Position { index },
            Self::Varargs { first, last } => Self::Target::Varargs { first, last },
        }
    }
}

impl From<&SleighPreferredVarnodeSplit> for StaticPreferredVarnodeSplit {
    fn from(split: &SleighPreferredVarnodeSplit) -> Self {
        Self::new(split.storage().into(), split.split_offset())
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct PrototypeAlias {
    name: Box<str>,
    parent: u32,
}

impl From<&SleighPrototypeAlias> for PrototypeAlias {
    fn from(alias: &SleighPrototypeAlias) -> Self {
        Self {
            name: Box::<str>::from(alias.name()),
            parent: alias.parent(),
        }
    }
}

impl Install for PrototypeAlias {
    type Target = StaticPrototypeAlias;

    fn install(self) -> Self::Target {
        Self::Target::new(self.name.install(), self.parent)
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct PrototypeResolution {
    name: Box<str>,
    prototypes: Box<[PrototypeReference]>,
}

impl From<&SleighPrototypeResolution> for PrototypeResolution {
    fn from(resolution: &SleighPrototypeResolution) -> Self {
        Self {
            name: Box::<str>::from(resolution.name()),
            prototypes: resolution.prototypes().into(),
        }
    }
}

impl Install for PrototypeResolution {
    type Target = StaticPrototypeResolution;

    fn install(self) -> Self::Target {
        Self::Target::new(self.name.install(), self.prototypes.install())
    }
}
