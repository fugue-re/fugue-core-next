pub use fugue_sleigh_language::compiler::{
    BitfieldPacking, DatatypeKind, HiddenReturnStrategy, PrototypeRuleAction, RuleStorage,
};
pub use fugue_sleigh_language::convention::PrototypeReference;
use itertools::Itertools;

use crate::pcode::Varnode;
use crate::processor::{SegmentOp, StorageLocation};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReturnAddress {
    Register(Varnode),
    StackRelative { offset: u64, size: u16 },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Convention {
    name: &'static str,
    stack_pointer: Varnode,
    return_address: Option<ReturnAddress>,
    prototypes: &'static [Prototype],
    data_organisation: Option<DataOrganisation>,
    call_fixups: &'static [CallFixup],
    user_op_fixups: &'static [UserOpFixup],
    function_pointer_alignment: Option<u64>,
    global_ranges: &'static [StorageLocation],
    aggressive_trim: bool,
    preferred_varnode_splits: &'static [PreferredVarnodeSplit],
    prototype_aliases: &'static [PrototypeAlias],
    prototype_resolutions: &'static [PrototypeResolution],
    eval_current_prototype: Option<PrototypeReference>,
    properties: &'static [(&'static str, &'static str)],
    segment_ops: &'static [SegmentOp],
}

impl Convention {
    pub const fn new(name: &'static str, stack_pointer: Varnode) -> Self {
        Self::new_with(name, stack_pointer, &[])
    }

    pub const fn new_with(
        name: &'static str,
        stack_pointer: Varnode,
        properties: &'static [(&'static str, &'static str)],
    ) -> Self {
        Self {
            name,
            stack_pointer,
            return_address: None,
            prototypes: &[],
            data_organisation: None,
            call_fixups: &[],
            user_op_fixups: &[],
            function_pointer_alignment: None,
            global_ranges: &[],
            aggressive_trim: false,
            preferred_varnode_splits: &[],
            prototype_aliases: &[],
            prototype_resolutions: &[],
            eval_current_prototype: None,
            properties,
            segment_ops: &[],
        }
    }

    pub const fn set_return_address(&mut self, return_address: Option<ReturnAddress>) {
        self.return_address = return_address;
    }

    pub const fn with_return_address(mut self, return_address: ReturnAddress) -> Self {
        self.set_return_address(Some(return_address));
        self
    }

    pub const fn set_prototypes(&mut self, prototypes: &'static [Prototype]) {
        self.prototypes = prototypes;
    }

    pub const fn with_prototypes(mut self, prototypes: &'static [Prototype]) -> Self {
        self.set_prototypes(prototypes);
        self
    }

    pub const fn set_data_organisation(&mut self, data_organisation: Option<DataOrganisation>) {
        self.data_organisation = data_organisation;
    }

    pub const fn with_data_organisation(
        mut self,
        data_organisation: Option<DataOrganisation>,
    ) -> Self {
        self.set_data_organisation(data_organisation);
        self
    }

    pub const fn set_call_fixups(&mut self, call_fixups: &'static [CallFixup]) {
        self.call_fixups = call_fixups;
    }

    pub const fn with_call_fixups(mut self, call_fixups: &'static [CallFixup]) -> Self {
        self.set_call_fixups(call_fixups);
        self
    }

    pub const fn set_user_op_fixups(&mut self, user_op_fixups: &'static [UserOpFixup]) {
        self.user_op_fixups = user_op_fixups;
    }

    pub const fn with_user_op_fixups(mut self, user_op_fixups: &'static [UserOpFixup]) -> Self {
        self.set_user_op_fixups(user_op_fixups);
        self
    }

    pub const fn set_function_pointer_alignment(
        &mut self,
        function_pointer_alignment: Option<u64>,
    ) {
        self.function_pointer_alignment = function_pointer_alignment;
    }

    pub const fn with_function_pointer_alignment(
        mut self,
        function_pointer_alignment: Option<u64>,
    ) -> Self {
        self.set_function_pointer_alignment(function_pointer_alignment);
        self
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn stack_pointer(&self) -> Varnode {
        self.stack_pointer
    }

    pub const fn return_address(&self) -> Option<ReturnAddress> {
        self.return_address
    }

    pub const fn prototypes(&self) -> &'static [Prototype] {
        self.prototypes
    }

    pub const fn data_organisation(&self) -> Option<DataOrganisation> {
        self.data_organisation
    }

    pub const fn call_fixups(&self) -> &'static [CallFixup] {
        self.call_fixups
    }

    pub const fn user_op_fixups(&self) -> &'static [UserOpFixup] {
        self.user_op_fixups
    }

    pub const fn function_pointer_alignment(&self) -> Option<u64> {
        self.function_pointer_alignment
    }

    pub const fn global_ranges(&self) -> &'static [StorageLocation] {
        self.global_ranges
    }

    pub const fn set_global_ranges(&mut self, global_ranges: &'static [StorageLocation]) {
        self.global_ranges = global_ranges;
    }

    pub const fn with_global_ranges(mut self, global_ranges: &'static [StorageLocation]) -> Self {
        self.set_global_ranges(global_ranges);
        self
    }

    pub const fn aggressive_trim(&self) -> bool {
        self.aggressive_trim
    }

    pub const fn set_aggressive_trim(&mut self, aggressive_trim: bool) {
        self.aggressive_trim = aggressive_trim;
    }

    pub const fn with_aggressive_trim(mut self, aggressive_trim: bool) -> Self {
        self.set_aggressive_trim(aggressive_trim);
        self
    }

    pub const fn preferred_varnode_splits(&self) -> &'static [PreferredVarnodeSplit] {
        self.preferred_varnode_splits
    }

    pub const fn set_preferred_varnode_splits(
        &mut self,
        preferred_varnode_splits: &'static [PreferredVarnodeSplit],
    ) {
        self.preferred_varnode_splits = preferred_varnode_splits;
    }

    pub const fn with_preferred_varnode_splits(
        mut self,
        preferred_varnode_splits: &'static [PreferredVarnodeSplit],
    ) -> Self {
        self.set_preferred_varnode_splits(preferred_varnode_splits);
        self
    }

    pub const fn prototype_aliases(&self) -> &'static [PrototypeAlias] {
        self.prototype_aliases
    }

    pub const fn set_prototype_aliases(&mut self, prototype_aliases: &'static [PrototypeAlias]) {
        self.prototype_aliases = prototype_aliases;
    }

    pub const fn with_prototype_aliases(
        mut self,
        prototype_aliases: &'static [PrototypeAlias],
    ) -> Self {
        self.set_prototype_aliases(prototype_aliases);
        self
    }

    pub const fn prototype_resolutions(&self) -> &'static [PrototypeResolution] {
        self.prototype_resolutions
    }

    pub const fn set_prototype_resolutions(
        &mut self,
        prototype_resolutions: &'static [PrototypeResolution],
    ) {
        self.prototype_resolutions = prototype_resolutions;
    }

    pub const fn with_prototype_resolutions(
        mut self,
        prototype_resolutions: &'static [PrototypeResolution],
    ) -> Self {
        self.set_prototype_resolutions(prototype_resolutions);
        self
    }

    pub const fn eval_current_prototype(&self) -> Option<PrototypeReference> {
        self.eval_current_prototype
    }

    pub const fn set_eval_current_prototype(
        &mut self,
        eval_current_prototype: Option<PrototypeReference>,
    ) {
        self.eval_current_prototype = eval_current_prototype;
    }

    pub const fn with_eval_current_prototype(
        mut self,
        eval_current_prototype: Option<PrototypeReference>,
    ) -> Self {
        self.set_eval_current_prototype(eval_current_prototype);
        self
    }

    pub const fn properties(&self) -> &'static [(&'static str, &'static str)] {
        self.properties
    }

    pub fn property(&self, key: &str) -> Option<&'static str> {
        self.properties
            .binary_search_by_key(&key, |(name, _)| *name)
            .ok()
            .map(|index| self.properties[index].1)
    }

    pub fn set_properties(&mut self, properties: &'static [(&'static str, &'static str)]) {
        self.properties = if properties.is_sorted_by_key(|(key, _)| *key) {
            properties
        } else {
            Box::leak(
                properties
                    .iter()
                    .copied()
                    .sorted_unstable_by_key(|(key, _)| *key)
                    .collect::<Box<[_]>>(),
            )
        };
    }

    pub fn with_properties(mut self, properties: &'static [(&'static str, &'static str)]) -> Self {
        self.set_properties(properties);
        self
    }

    pub const fn segment_ops(&self) -> &'static [SegmentOp] {
        self.segment_ops
    }

    pub const fn set_segment_ops(&mut self, segment_ops: &'static [SegmentOp]) {
        self.segment_ops = segment_ops;
    }

    pub const fn with_segment_ops(mut self, segment_ops: &'static [SegmentOp]) -> Self {
        self.set_segment_ops(segment_ops);
        self
    }

    pub fn prototype_reference(&self, name: &str) -> Option<PrototypeReference> {
        if let Some(index) = self
            .prototypes
            .iter()
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

    pub fn prototype(&self, index: u32) -> Option<&'static Prototype> {
        self.prototypes.get(index as usize)
    }

    pub fn prototype_resolution(&self, index: u32) -> Option<&'static PrototypeResolution> {
        self.prototype_resolutions.get(index as usize)
    }

    pub fn prototype_alias(&self, index: u32) -> Option<&'static PrototypeAlias> {
        self.prototype_aliases.get(index as usize)
    }

    pub fn prototype_by_reference(
        &self,
        reference: PrototypeReference,
    ) -> Option<&'static Prototype> {
        match reference {
            PrototypeReference::Alias(index) => {
                self.prototype(self.prototype_alias(index)?.parent())
            }
            PrototypeReference::Prototype(index) => self.prototype(index),
            PrototypeReference::Resolution(_) => None,
        }
    }

    pub fn prototype_by_name(&self, name: &str) -> Option<&'static Prototype> {
        self.prototype_by_reference(self.prototype_reference(name)?)
    }

    pub const fn default_prototype(&self) -> Option<&'static Prototype> {
        self.prototypes.first()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PrototypeOperand {
    Address {
        space: u8,
        offset: u64,
        size: Option<u16>,
    },
    Join {
        pieces: &'static [JoinPiece],
        logical_size: Option<u16>,
    },
    Register(Varnode),
    RegisterJoin(Varnode, Varnode),
    StackRelative {
        offset: u64,
        size: Option<u16>,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum JoinPiece {
    Location { space: u8, offset: u64, size: u16 },
    StackRelative { offset: u64, size: u16 },
}

impl JoinPiece {
    pub const fn size(&self) -> u16 {
        match self {
            Self::Location { size, .. } | Self::StackRelative { size, .. } => *size,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrototypeEntry {
    min_size: u16,
    max_size: u16,
    alignment: u64,
    meta_type: Option<&'static str>,
    extension: Option<&'static str>,
    operand: PrototypeOperand,
    killed_by_call: bool,
    storage: Option<RuleStorage>,
    group: Option<u32>,
}

impl PrototypeEntry {
    pub const fn new(
        min_size: u16,
        max_size: u16,
        alignment: u64,
        operand: PrototypeOperand,
    ) -> Self {
        Self {
            min_size,
            max_size,
            alignment,
            meta_type: None,
            extension: None,
            operand,
            killed_by_call: false,
            storage: None,
            group: None,
        }
    }

    pub const fn set_meta_type(&mut self, meta_type: Option<&'static str>) {
        self.meta_type = meta_type;
    }

    pub const fn with_meta_type(mut self, meta_type: &'static str) -> Self {
        self.set_meta_type(Some(meta_type));
        self
    }

    pub const fn set_extension(&mut self, extension: Option<&'static str>) {
        self.extension = extension;
    }

    pub const fn with_extension(mut self, extension: &'static str) -> Self {
        self.set_extension(Some(extension));
        self
    }

    pub const fn set_killed_by_call(&mut self, killed_by_call: bool) {
        self.killed_by_call = killed_by_call;
    }

    pub const fn with_killed_by_call(mut self, killed_by_call: bool) -> Self {
        self.set_killed_by_call(killed_by_call);
        self
    }

    pub const fn set_storage(&mut self, storage: Option<RuleStorage>) {
        self.storage = storage;
    }

    pub const fn with_storage(mut self, storage: Option<RuleStorage>) -> Self {
        self.set_storage(storage);
        self
    }

    pub const fn set_group(&mut self, group: Option<u32>) {
        self.group = group;
    }

    pub const fn with_group(mut self, group: Option<u32>) -> Self {
        self.set_group(group);
        self
    }

    pub const fn min_size(&self) -> u16 {
        self.min_size
    }

    pub const fn max_size(&self) -> u16 {
        self.max_size
    }

    pub const fn alignment(&self) -> u64 {
        self.alignment
    }

    pub const fn meta_type(&self) -> Option<&'static str> {
        self.meta_type
    }

    pub const fn extension(&self) -> Option<&'static str> {
        self.extension
    }

    pub const fn operand(&self) -> &PrototypeOperand {
        &self.operand
    }

    pub const fn killed_by_call(&self) -> bool {
        self.killed_by_call
    }

    pub const fn storage(&self) -> Option<RuleStorage> {
        self.storage
    }

    pub const fn group(&self) -> Option<u32> {
        self.group
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Prototype {
    name: &'static str,
    extra_pop: u64,
    stack_shift: u64,
    inputs: &'static [PrototypeEntry],
    outputs: &'static [PrototypeEntry],
    input_rules: &'static [PrototypeRule],
    output_rules: &'static [PrototypeRule],
    unaffected: &'static [PrototypeOperand],
    killed_by_call: &'static [PrototypeOperand],
    likely_trashed: &'static [PrototypeOperand],
    local_ranges: &'static [StorageLocation],
    internal_storage: &'static [Varnode],
}

impl Prototype {
    pub const fn new(name: &'static str, extra_pop: u64, stack_shift: u64) -> Self {
        Self {
            name,
            extra_pop,
            stack_shift,
            inputs: &[],
            outputs: &[],
            input_rules: &[],
            output_rules: &[],
            unaffected: &[],
            killed_by_call: &[],
            likely_trashed: &[],
            local_ranges: &[],
            internal_storage: &[],
        }
    }

    pub const fn local_ranges(&self) -> &'static [StorageLocation] {
        self.local_ranges
    }

    pub const fn set_local_ranges(&mut self, local_ranges: &'static [StorageLocation]) {
        self.local_ranges = local_ranges;
    }

    pub const fn with_local_ranges(mut self, local_ranges: &'static [StorageLocation]) -> Self {
        self.set_local_ranges(local_ranges);
        self
    }

    pub const fn internal_storage(&self) -> &'static [Varnode] {
        self.internal_storage
    }

    pub const fn set_internal_storage(&mut self, internal_storage: &'static [Varnode]) {
        self.internal_storage = internal_storage;
    }

    pub const fn with_internal_storage(mut self, internal_storage: &'static [Varnode]) -> Self {
        self.set_internal_storage(internal_storage);
        self
    }

    pub const fn set_inputs(&mut self, inputs: &'static [PrototypeEntry]) {
        self.inputs = inputs;
    }

    pub const fn with_inputs(mut self, inputs: &'static [PrototypeEntry]) -> Self {
        self.set_inputs(inputs);
        self
    }

    pub const fn set_outputs(&mut self, outputs: &'static [PrototypeEntry]) {
        self.outputs = outputs;
    }

    pub const fn with_outputs(mut self, outputs: &'static [PrototypeEntry]) -> Self {
        self.set_outputs(outputs);
        self
    }

    pub const fn set_input_rules(&mut self, input_rules: &'static [PrototypeRule]) {
        self.input_rules = input_rules;
    }

    pub const fn with_input_rules(mut self, input_rules: &'static [PrototypeRule]) -> Self {
        self.set_input_rules(input_rules);
        self
    }

    pub const fn set_output_rules(&mut self, output_rules: &'static [PrototypeRule]) {
        self.output_rules = output_rules;
    }

    pub const fn with_output_rules(mut self, output_rules: &'static [PrototypeRule]) -> Self {
        self.set_output_rules(output_rules);
        self
    }

    pub const fn set_unaffected(&mut self, unaffected: &'static [PrototypeOperand]) {
        self.unaffected = unaffected;
    }

    pub const fn with_unaffected(mut self, unaffected: &'static [PrototypeOperand]) -> Self {
        self.set_unaffected(unaffected);
        self
    }

    pub const fn set_killed_by_call(&mut self, killed_by_call: &'static [PrototypeOperand]) {
        self.killed_by_call = killed_by_call;
    }

    pub const fn with_killed_by_call(
        mut self,
        killed_by_call: &'static [PrototypeOperand],
    ) -> Self {
        self.set_killed_by_call(killed_by_call);
        self
    }

    pub const fn set_likely_trashed(&mut self, likely_trashed: &'static [PrototypeOperand]) {
        self.likely_trashed = likely_trashed;
    }

    pub const fn with_likely_trashed(
        mut self,
        likely_trashed: &'static [PrototypeOperand],
    ) -> Self {
        self.set_likely_trashed(likely_trashed);
        self
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn extra_pop(&self) -> u64 {
        self.extra_pop
    }

    pub const fn stack_shift(&self) -> u64 {
        self.stack_shift
    }

    pub const fn inputs(&self) -> &'static [PrototypeEntry] {
        self.inputs
    }

    pub const fn outputs(&self) -> &'static [PrototypeEntry] {
        self.outputs
    }

    pub const fn input_rules(&self) -> &'static [PrototypeRule] {
        self.input_rules
    }

    pub const fn output_rules(&self) -> &'static [PrototypeRule] {
        self.output_rules
    }

    pub const fn unaffected(&self) -> &'static [PrototypeOperand] {
        self.unaffected
    }

    pub const fn killed_by_call(&self) -> &'static [PrototypeOperand] {
        self.killed_by_call
    }

    pub const fn likely_trashed(&self) -> &'static [PrototypeOperand] {
        self.likely_trashed
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
    alignments: &'static [(u16, u64)],
}

impl DataOrganisation {
    pub const fn new(alignments: &'static [(u16, u64)]) -> Self {
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
            alignments,
        }
    }

    pub const fn absolute_max_alignment(&self) -> u64 {
        self.absolute_max_alignment
    }

    pub const fn set_absolute_max_alignment(&mut self, absolute_max_alignment: u64) {
        self.absolute_max_alignment = absolute_max_alignment;
    }

    pub const fn with_absolute_max_alignment(mut self, absolute_max_alignment: u64) -> Self {
        self.set_absolute_max_alignment(absolute_max_alignment);
        self
    }

    pub const fn machine_alignment(&self) -> u64 {
        self.machine_alignment
    }

    pub const fn set_machine_alignment(&mut self, machine_alignment: u64) {
        self.machine_alignment = machine_alignment;
    }

    pub const fn with_machine_alignment(mut self, machine_alignment: u64) -> Self {
        self.set_machine_alignment(machine_alignment);
        self
    }

    pub const fn default_alignment(&self) -> u64 {
        self.default_alignment
    }

    pub const fn set_default_alignment(&mut self, default_alignment: u64) {
        self.default_alignment = default_alignment;
    }

    pub const fn with_default_alignment(mut self, default_alignment: u64) -> Self {
        self.set_default_alignment(default_alignment);
        self
    }

    pub const fn default_pointer_alignment(&self) -> u64 {
        self.default_pointer_alignment
    }

    pub const fn set_default_pointer_alignment(&mut self, default_pointer_alignment: u64) {
        self.default_pointer_alignment = default_pointer_alignment;
    }

    pub const fn with_default_pointer_alignment(mut self, default_pointer_alignment: u64) -> Self {
        self.set_default_pointer_alignment(default_pointer_alignment);
        self
    }

    pub const fn pointer_size(&self) -> u16 {
        self.pointer_size
    }

    pub const fn set_pointer_size(&mut self, pointer_size: u16) {
        self.pointer_size = pointer_size;
    }

    pub const fn with_pointer_size(mut self, pointer_size: u16) -> Self {
        self.set_pointer_size(pointer_size);
        self
    }

    pub const fn pointer_shift(&self) -> u32 {
        self.pointer_shift
    }

    pub const fn set_pointer_shift(&mut self, pointer_shift: u32) {
        self.pointer_shift = pointer_shift;
    }

    pub const fn with_pointer_shift(mut self, pointer_shift: u32) -> Self {
        self.set_pointer_shift(pointer_shift);
        self
    }

    pub const fn char_size(&self) -> u16 {
        self.char_size
    }

    pub const fn set_char_size(&mut self, char_size: u16) {
        self.char_size = char_size;
    }

    pub const fn with_char_size(mut self, char_size: u16) -> Self {
        self.set_char_size(char_size);
        self
    }

    pub const fn char_signed(&self) -> bool {
        self.char_signed
    }

    pub const fn set_char_signed(&mut self, char_signed: bool) {
        self.char_signed = char_signed;
    }

    pub const fn with_char_signed(mut self, char_signed: bool) -> Self {
        self.set_char_signed(char_signed);
        self
    }

    pub const fn wchar_size(&self) -> u16 {
        self.wchar_size
    }

    pub const fn set_wchar_size(&mut self, wchar_size: u16) {
        self.wchar_size = wchar_size;
    }

    pub const fn with_wchar_size(mut self, wchar_size: u16) -> Self {
        self.set_wchar_size(wchar_size);
        self
    }

    pub const fn short_size(&self) -> u16 {
        self.short_size
    }

    pub const fn set_short_size(&mut self, short_size: u16) {
        self.short_size = short_size;
    }

    pub const fn with_short_size(mut self, short_size: u16) -> Self {
        self.set_short_size(short_size);
        self
    }

    pub const fn integer_size(&self) -> u16 {
        self.integer_size
    }

    pub const fn set_integer_size(&mut self, integer_size: u16) {
        self.integer_size = integer_size;
    }

    pub const fn with_integer_size(mut self, integer_size: u16) -> Self {
        self.set_integer_size(integer_size);
        self
    }

    pub const fn long_size(&self) -> u16 {
        self.long_size
    }

    pub const fn set_long_size(&mut self, long_size: u16) {
        self.long_size = long_size;
    }

    pub const fn with_long_size(mut self, long_size: u16) -> Self {
        self.set_long_size(long_size);
        self
    }

    pub const fn long_long_size(&self) -> u16 {
        self.long_long_size
    }

    pub const fn set_long_long_size(&mut self, long_long_size: u16) {
        self.long_long_size = long_long_size;
    }

    pub const fn with_long_long_size(mut self, long_long_size: u16) -> Self {
        self.set_long_long_size(long_long_size);
        self
    }

    pub const fn float_size(&self) -> u16 {
        self.float_size
    }

    pub const fn set_float_size(&mut self, float_size: u16) {
        self.float_size = float_size;
    }

    pub const fn with_float_size(mut self, float_size: u16) -> Self {
        self.set_float_size(float_size);
        self
    }

    pub const fn double_size(&self) -> u16 {
        self.double_size
    }

    pub const fn set_double_size(&mut self, double_size: u16) {
        self.double_size = double_size;
    }

    pub const fn with_double_size(mut self, double_size: u16) -> Self {
        self.set_double_size(double_size);
        self
    }

    pub const fn long_double_size(&self) -> u16 {
        self.long_double_size
    }

    pub const fn set_long_double_size(&mut self, long_double_size: u16) {
        self.long_double_size = long_double_size;
    }

    pub const fn with_long_double_size(mut self, long_double_size: u16) -> Self {
        self.set_long_double_size(long_double_size);
        self
    }

    pub const fn bitfield_packing(&self) -> BitfieldPacking {
        self.bitfield_packing
    }

    pub const fn set_bitfield_packing(&mut self, bitfield_packing: BitfieldPacking) {
        self.bitfield_packing = bitfield_packing;
    }

    pub const fn with_bitfield_packing(mut self, bitfield_packing: BitfieldPacking) -> Self {
        self.set_bitfield_packing(bitfield_packing);
        self
    }

    pub const fn set_alignments(&mut self, alignments: &'static [(u16, u64)]) {
        self.alignments = alignments;
    }

    pub const fn with_alignments(mut self, alignments: &'static [(u16, u64)]) -> Self {
        self.set_alignments(alignments);
        self
    }

    pub const fn alignments(&self) -> &'static [(u16, u64)] {
        self.alignments
    }

    pub fn alignment(&self, size: u16) -> u64 {
        self.alignments
            .iter()
            .find(|(entry_size, _)| *entry_size == size)
            .map_or(self.default_alignment(), |(_, alignment)| *alignment)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DatatypeFilter {
    kind: DatatypeKind,
    sizes: &'static [u16],
    min_size: Option<u16>,
    max_size: Option<u16>,
    max_primitives: Option<u32>,
    min_elements: Option<u32>,
    max_elements: Option<u32>,
}

impl DatatypeFilter {
    pub const fn new(kind: DatatypeKind, sizes: &'static [u16]) -> Self {
        Self {
            kind,
            sizes,
            min_size: None,
            max_size: None,
            max_primitives: None,
            min_elements: None,
            max_elements: None,
        }
    }

    pub const fn set_min_size(&mut self, min_size: Option<u16>) {
        self.min_size = min_size;
    }

    pub const fn with_min_size(mut self, min_size: Option<u16>) -> Self {
        self.set_min_size(min_size);
        self
    }

    pub const fn set_max_size(&mut self, max_size: Option<u16>) {
        self.max_size = max_size;
    }

    pub const fn with_max_size(mut self, max_size: Option<u16>) -> Self {
        self.set_max_size(max_size);
        self
    }

    pub const fn set_max_primitives(&mut self, max_primitives: Option<u32>) {
        self.max_primitives = max_primitives;
    }

    pub const fn with_max_primitives(mut self, max_primitives: Option<u32>) -> Self {
        self.set_max_primitives(max_primitives);
        self
    }

    pub const fn set_min_elements(&mut self, min_elements: Option<u32>) {
        self.min_elements = min_elements;
    }

    pub const fn with_min_elements(mut self, min_elements: Option<u32>) -> Self {
        self.set_min_elements(min_elements);
        self
    }

    pub const fn set_max_elements(&mut self, max_elements: Option<u32>) {
        self.max_elements = max_elements;
    }

    pub const fn with_max_elements(mut self, max_elements: Option<u32>) -> Self {
        self.set_max_elements(max_elements);
        self
    }

    pub const fn kind(&self) -> DatatypeKind {
        self.kind
    }

    pub const fn sizes(&self) -> &'static [u16] {
        self.sizes
    }

    pub const fn min_size(&self) -> Option<u16> {
        self.min_size
    }

    pub const fn max_size(&self) -> Option<u16> {
        self.max_size
    }

    pub const fn max_primitives(&self) -> Option<u32> {
        self.max_primitives
    }

    pub const fn min_elements(&self) -> Option<u32> {
        self.min_elements
    }

    pub const fn max_elements(&self) -> Option<u32> {
        self.max_elements
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrototypeRule {
    killed_by_call: bool,
    conditions: &'static [PrototypeRuleCondition],
    actions: &'static [PrototypeRuleAction],
}

impl PrototypeRule {
    pub const fn new(
        killed_by_call: bool,
        conditions: &'static [PrototypeRuleCondition],
        actions: &'static [PrototypeRuleAction],
    ) -> Self {
        Self {
            killed_by_call,
            conditions,
            actions,
        }
    }

    pub const fn killed_by_call(&self) -> bool {
        self.killed_by_call
    }

    pub const fn conditions(&self) -> &'static [PrototypeRuleCondition] {
        self.conditions
    }

    pub const fn actions(&self) -> &'static [PrototypeRuleAction] {
        self.actions
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InjectParameter {
    name: &'static str,
    size: Option<u16>,
}

impl InjectParameter {
    pub const fn new(name: &'static str, size: Option<u16>) -> Self {
        Self { name, size }
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn size(&self) -> Option<u16> {
        self.size
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InjectPayload {
    body: Option<&'static str>,
    inputs: &'static [InjectParameter],
    outputs: &'static [InjectParameter],
    param_shift: i64,
    dynamic: bool,
    incidental_copy: bool,
}

impl InjectPayload {
    pub const fn new(
        body: Option<&'static str>,
        inputs: &'static [InjectParameter],
        outputs: &'static [InjectParameter],
    ) -> Self {
        Self {
            body,
            inputs,
            outputs,
            param_shift: 0,
            dynamic: false,
            incidental_copy: false,
        }
    }

    pub const fn set_param_shift(&mut self, param_shift: i64) {
        self.param_shift = param_shift;
    }

    pub const fn with_param_shift(mut self, param_shift: i64) -> Self {
        self.set_param_shift(param_shift);
        self
    }

    pub const fn set_dynamic(&mut self, dynamic: bool) {
        self.dynamic = dynamic;
    }

    pub const fn with_dynamic(mut self, dynamic: bool) -> Self {
        self.set_dynamic(dynamic);
        self
    }

    pub const fn set_incidental_copy(&mut self, incidental_copy: bool) {
        self.incidental_copy = incidental_copy;
    }

    pub const fn with_incidental_copy(mut self, incidental_copy: bool) -> Self {
        self.set_incidental_copy(incidental_copy);
        self
    }

    pub const fn body(&self) -> Option<&'static str> {
        self.body
    }

    pub const fn inputs(&self) -> &'static [InjectParameter] {
        self.inputs
    }

    pub const fn outputs(&self) -> &'static [InjectParameter] {
        self.outputs
    }

    pub const fn param_shift(&self) -> i64 {
        self.param_shift
    }

    pub const fn dynamic(&self) -> bool {
        self.dynamic
    }

    pub const fn incidental_copy(&self) -> bool {
        self.incidental_copy
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CallFixup {
    name: &'static str,
    targets: &'static [&'static str],
    payload: InjectPayload,
}

impl CallFixup {
    pub const fn new(
        name: &'static str,
        targets: &'static [&'static str],
        payload: InjectPayload,
    ) -> Self {
        Self {
            name,
            targets,
            payload,
        }
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn targets(&self) -> &'static [&'static str] {
        self.targets
    }

    pub const fn payload(&self) -> InjectPayload {
        self.payload
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UserOpFixup {
    target_op: &'static str,
    payload: InjectPayload,
}

impl UserOpFixup {
    pub const fn new(target_op: &'static str, payload: InjectPayload) -> Self {
        Self { target_op, payload }
    }

    pub const fn target_op(&self) -> &'static str {
        self.target_op
    }

    pub const fn payload(&self) -> InjectPayload {
        self.payload
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrototypeAlias {
    name: &'static str,
    parent: u32,
}

impl PrototypeAlias {
    pub const fn new(name: &'static str, parent: u32) -> Self {
        Self { name, parent }
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn parent(&self) -> u32 {
        self.parent
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrototypeResolution {
    name: &'static str,
    prototypes: &'static [PrototypeReference],
}

impl PrototypeResolution {
    pub const fn new(name: &'static str, prototypes: &'static [PrototypeReference]) -> Self {
        Self { name, prototypes }
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn prototypes(&self) -> &'static [PrototypeReference] {
        self.prototypes
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PreferredVarnodeSplit {
    storage: Varnode,
    split_offset: u16,
}

impl PreferredVarnodeSplit {
    pub const fn new(storage: Varnode, split_offset: u16) -> Self {
        Self {
            storage,
            split_offset,
        }
    }

    pub const fn storage(&self) -> Varnode {
        self.storage
    }

    pub const fn split_offset(&self) -> u16 {
        self.split_offset
    }
}
