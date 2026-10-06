use fugue_sleigh_language::compiler::{
    CallFixup, DataOrganisation, DatatypeFilter, DatatypeKind, HiddenReturnStrategy,
    InjectParameter, InjectPayload, PrototypeRule, PrototypeRuleAction, PrototypeRuleCondition,
    RuleStorage, UserOpFixup,
};
use fugue_sleigh_language::convention::{
    Convention, JoinPiece, Prototype, PrototypeEntry, PrototypeOperand, ReturnAddress,
};
use fugue_sleigh_language::varnode::VarnodeData;
use proc_macro2::TokenStream;
use quote::quote;

pub(crate) struct ConventionAdaptor<'a, T> {
    source: &'a T,
}

impl<'a, T> ConventionAdaptor<'a, T> {
    pub(crate) fn new(source: &'a T) -> Self {
        Self { source }
    }
}

impl<'a> ConventionAdaptor<'a, VarnodeData> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let varnode = self.source;
        let space =
            u8::try_from(varnode.space().index()).expect("address-space identifier fits in u8");
        let offset = varnode.offset();
        let size = u16::try_from(varnode.size()).expect("varnode size fits in u16");
        quote! { fugue_lifter_runtime::pcode::Varnode::new(#space, #offset, #size) }
    }
}

impl<'a> ConventionAdaptor<'a, PrototypeOperand> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let operand = self.source;
        match operand {
            PrototypeOperand::Address {
                space,
                offset,
                size,
            } => {
                let space =
                    u8::try_from(space.index()).expect("address-space identifier fits in u8");
                let size = size.map_or_else(|| quote! { None }, |size| quote! { Some(#size) });
                quote! {
                    fugue_lifter_runtime::convention::PrototypeOperand::Address {
                        space: #space,
                        offset: #offset,
                        size: #size,
                    }
                }
            }
            PrototypeOperand::Join {
                pieces,
                logical_size,
            } => {
                let pieces = pieces.iter().map(|piece| match piece {
                    JoinPiece::StackRelative { offset, size } => quote! {
                        fugue_lifter_runtime::convention::JoinPiece::StackRelative {
                            offset: #offset,
                            size: #size,
                        }
                    },
                    JoinPiece::Location(varnode) => {
                        let space = u8::try_from(varnode.space().index())
                            .expect("address-space identifier fits in u8");
                        let offset = varnode.offset();
                        let size = u16::try_from(varnode.size()).expect("varnode size fits in u16");
                        quote! {
                            fugue_lifter_runtime::convention::JoinPiece::Location {
                                space: #space,
                                offset: #offset,
                                size: #size,
                            }
                        }
                    }
                });
                let logical_size = logical_size.map_or_else(
                    || quote! { None },
                    |logical_size| quote! { Some(#logical_size) },
                );
                quote! {
                    fugue_lifter_runtime::convention::PrototypeOperand::Join {
                        pieces: &[#(#pieces),*],
                        logical_size: #logical_size,
                    }
                }
            }
            PrototypeOperand::Register { varnode, .. } => {
                let varnode = ConventionAdaptor::new(varnode).tokens();
                quote! { fugue_lifter_runtime::convention::PrototypeOperand::Register(#varnode) }
            }
            PrototypeOperand::RegisterJoin {
                first_varnode,
                second_varnode,
                ..
            } => {
                let first = ConventionAdaptor::new(first_varnode).tokens();
                let second = ConventionAdaptor::new(second_varnode).tokens();
                quote! { fugue_lifter_runtime::convention::PrototypeOperand::RegisterJoin(#first, #second) }
            }
            PrototypeOperand::StackRelative { offset, size } => {
                let size = size.map_or_else(|| quote! { None }, |size| quote! { Some(#size) });
                quote! {
                    fugue_lifter_runtime::convention::PrototypeOperand::StackRelative {
                        offset: #offset,
                        size: #size,
                    }
                }
            }
        }
    }
}

impl<'a> ConventionAdaptor<'a, PrototypeEntry> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let entry = self.source;
        let min_size = entry.min_size();
        let max_size = entry.max_size();
        let alignment = entry.alignment();
        let operand = ConventionAdaptor::new(entry.operand()).tokens();
        let killed = entry.killed_by_call();
        let storage = entry.storage().map_or_else(
            || quote! { None },
            |storage| {
                let storage = ConventionAdaptor::new(&storage).tokens();
                quote! { Some(#storage) }
            },
        );
        let group = entry
            .group()
            .map_or_else(|| quote! { None }, |group| quote! { Some(#group) });
        let mut tokens = quote! {
            fugue_lifter_runtime::convention::PrototypeEntry::new(
                #min_size,
                #max_size,
                #alignment,
                #operand,
            )
            .with_killed_by_call(#killed)
            .with_storage(#storage)
            .with_group(#group)
        };
        if let Some(meta_type) = entry.meta_type() {
            tokens = quote! { #tokens.with_meta_type(#meta_type) };
        }
        if let Some(extension) = entry.extension() {
            tokens = quote! { #tokens.with_extension(#extension) };
        }
        tokens
    }
}

impl<'a> ConventionAdaptor<'a, DatatypeFilter> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let datatype = self.source;
        let kind = match datatype.kind() {
            DatatypeKind::Any => quote! { fugue_lifter_runtime::convention::DatatypeKind::Any },
            DatatypeKind::Array => quote! { fugue_lifter_runtime::convention::DatatypeKind::Array },
            DatatypeKind::Boolean => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::Boolean }
            }
            DatatypeKind::Code => quote! { fugue_lifter_runtime::convention::DatatypeKind::Code },
            DatatypeKind::Float => quote! { fugue_lifter_runtime::convention::DatatypeKind::Float },
            DatatypeKind::HomogeneousFloatAggregate => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::HomogeneousFloatAggregate }
            }
            DatatypeKind::Integer => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::Integer }
            }
            DatatypeKind::PartialStruct => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::PartialStruct }
            }
            DatatypeKind::PartialUnion => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::PartialUnion }
            }
            DatatypeKind::Pointer => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::Pointer }
            }
            DatatypeKind::RelativePointer => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::RelativePointer }
            }
            DatatypeKind::SignedEnumeration => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::SignedEnumeration }
            }
            DatatypeKind::SpaceBase => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::SpaceBase }
            }
            DatatypeKind::Struct => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::Struct }
            }
            DatatypeKind::Union => quote! { fugue_lifter_runtime::convention::DatatypeKind::Union },
            DatatypeKind::Unknown => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::Unknown }
            }
            DatatypeKind::UnsignedEnumeration => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::UnsignedEnumeration }
            }
            DatatypeKind::UnsignedInteger => {
                quote! { fugue_lifter_runtime::convention::DatatypeKind::UnsignedInteger }
            }
            DatatypeKind::Void => quote! { fugue_lifter_runtime::convention::DatatypeKind::Void },
        };
        let sizes = datatype.sizes();
        let min = datatype
            .min_size()
            .map_or_else(|| quote! { None }, |min| quote! { Some(#min) });
        let max = datatype
            .max_size()
            .map_or_else(|| quote! { None }, |max| quote! { Some(#max) });
        let primitives = datatype.max_primitives().map_or_else(
            || quote! { None },
            |primitives| quote! { Some(#primitives) },
        );
        let min_elements = datatype.min_elements().map_or_else(
            || quote! { None },
            |min_elements| quote! { Some(#min_elements) },
        );
        let max_elements = datatype.max_elements().map_or_else(
            || quote! { None },
            |max_elements| quote! { Some(#max_elements) },
        );
        quote! {
            fugue_lifter_runtime::convention::DatatypeFilter::new(#kind, &[#(#sizes),*])
                .with_min_size(#min)
                .with_max_size(#max)
                .with_max_primitives(#primitives)
                .with_min_elements(#min_elements)
                .with_max_elements(#max_elements)
        }
    }
}

impl<'a> ConventionAdaptor<'a, PrototypeRuleCondition> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let condition = self.source;
        match condition {
            PrototypeRuleCondition::Datatype(datatype) => {
                let datatype = ConventionAdaptor::new(datatype).tokens();
                quote! { fugue_lifter_runtime::convention::PrototypeRuleCondition::Datatype(#datatype) }
            }
            PrototypeRuleCondition::DatatypeAt { index, datatype } => {
                let datatype = ConventionAdaptor::new(datatype).tokens();
                quote! {
                    fugue_lifter_runtime::convention::PrototypeRuleCondition::DatatypeAt {
                        index: #index,
                        datatype: #datatype,
                    }
                }
            }
            PrototypeRuleCondition::Position { index } => {
                quote! { fugue_lifter_runtime::convention::PrototypeRuleCondition::Position { index: #index } }
            }
            PrototypeRuleCondition::Varargs { first, last } => {
                let first = first.map_or_else(|| quote! { None }, |first| quote! { Some(#first) });
                let last = last.map_or_else(|| quote! { None }, |last| quote! { Some(#last) });
                quote! {
                    fugue_lifter_runtime::convention::PrototypeRuleCondition::Varargs {
                        first: #first,
                        last: #last,
                    }
                }
            }
        }
    }
}

impl<'a> ConventionAdaptor<'a, RuleStorage> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let storage = *self.source;
        match storage {
            RuleStorage::Class1 => quote! { fugue_lifter_runtime::convention::RuleStorage::Class1 },
            RuleStorage::Class2 => quote! { fugue_lifter_runtime::convention::RuleStorage::Class2 },
            RuleStorage::Class3 => quote! { fugue_lifter_runtime::convention::RuleStorage::Class3 },
            RuleStorage::Class4 => quote! { fugue_lifter_runtime::convention::RuleStorage::Class4 },
            RuleStorage::Float => quote! { fugue_lifter_runtime::convention::RuleStorage::Float },
            RuleStorage::General => {
                quote! { fugue_lifter_runtime::convention::RuleStorage::General }
            }
            RuleStorage::HiddenReturn => {
                quote! { fugue_lifter_runtime::convention::RuleStorage::HiddenReturn }
            }
            RuleStorage::Pointer => {
                quote! { fugue_lifter_runtime::convention::RuleStorage::Pointer }
            }
            RuleStorage::Vector => quote! { fugue_lifter_runtime::convention::RuleStorage::Vector },
        }
    }
}

impl<'a> ConventionAdaptor<'a, PrototypeRuleAction> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let action = self.source;
        match action {
            PrototypeRuleAction::Consume { storage } => {
                let storage = ConventionAdaptor::new(storage).tokens();
                quote! { fugue_lifter_runtime::convention::PrototypeRuleAction::Consume { storage: #storage } }
            }
            PrototypeRuleAction::ConsumeExtra {
                storage,
                match_size,
            } => {
                let match_size = match_size.map_or_else(
                    || quote! { None },
                    |match_size| quote! { Some(#match_size) },
                );
                let storage = storage.map_or_else(
                    || quote! { None },
                    |storage| {
                        let storage = ConventionAdaptor::new(&storage).tokens();
                        quote! { Some(#storage) }
                    },
                );
                quote! {
                    fugue_lifter_runtime::convention::PrototypeRuleAction::ConsumeExtra {
                        storage: #storage,
                        match_size: #match_size,
                    }
                }
            }
            PrototypeRuleAction::ConsumeRemaining { storage } => {
                let storage = ConventionAdaptor::new(storage).tokens();
                quote! {
                    fugue_lifter_runtime::convention::PrototypeRuleAction::ConsumeRemaining {
                        storage: #storage,
                    }
                }
            }
            PrototypeRuleAction::ExtraStack {
                after_bytes,
                after_storage,
            } => {
                let after_bytes = after_bytes.map_or_else(
                    || quote! { None },
                    |after_bytes| quote! { Some(#after_bytes) },
                );
                let after_storage = after_storage.map_or_else(
                    || quote! { None },
                    |storage| {
                        let storage = ConventionAdaptor::new(&storage).tokens();
                        quote! { Some(#storage) }
                    },
                );
                quote! {
                    fugue_lifter_runtime::convention::PrototypeRuleAction::ExtraStack {
                        after_bytes: #after_bytes,
                        after_storage: #after_storage,
                    }
                }
            }
            PrototypeRuleAction::ConvertToPtr => {
                quote! { fugue_lifter_runtime::convention::PrototypeRuleAction::ConvertToPtr }
            }
            PrototypeRuleAction::GotoStack => {
                quote! { fugue_lifter_runtime::convention::PrototypeRuleAction::GotoStack }
            }
            PrototypeRuleAction::HiddenReturn {
                void_lock,
                strategy,
            } => {
                let strategy = strategy.map_or_else(|| quote! { None }, |strategy| {
                    let strategy = match strategy {
                        HiddenReturnStrategy::NormalParameter => quote! { fugue_lifter_runtime::convention::HiddenReturnStrategy::NormalParameter },
                        HiddenReturnStrategy::Special => quote! { fugue_lifter_runtime::convention::HiddenReturnStrategy::Special },
                    };
                    quote! { Some(#strategy) }
                });
                quote! {
                    fugue_lifter_runtime::convention::PrototypeRuleAction::HiddenReturn {
                        void_lock: #void_lock,
                        strategy: #strategy,
                    }
                }
            }
            PrototypeRuleAction::Join {
                align,
                backfill,
                stack_spill,
                reverse_justify,
                reverse_significance,
                storage,
            } => {
                let storage = storage.map_or_else(
                    || quote! { None },
                    |storage| {
                        let storage = ConventionAdaptor::new(&storage).tokens();
                        quote! { Some(#storage) }
                    },
                );
                let stack_spill = stack_spill.map_or_else(
                    || quote! { None },
                    |stack_spill| quote! { Some(#stack_spill) },
                );
                quote! {
                    fugue_lifter_runtime::convention::PrototypeRuleAction::Join {
                        align: #align,
                        backfill: #backfill,
                        stack_spill: #stack_spill,
                        reverse_justify: #reverse_justify,
                        reverse_significance: #reverse_significance,
                        storage: #storage,
                    }
                }
            }
            PrototypeRuleAction::JoinDualClass {
                storage,
                first_storage,
                second_storage,
                stack_spill,
                fill_alternate,
                reverse_justify,
                reverse_significance,
            } => {
                let stack_spill = stack_spill.map_or_else(
                    || quote! { None },
                    |stack_spill| quote! { Some(#stack_spill) },
                );
                let storage = storage.map_or_else(
                    || quote! { None },
                    |storage| {
                        let storage = ConventionAdaptor::new(&storage).tokens();
                        quote! { Some(#storage) }
                    },
                );
                let first = first_storage.map_or_else(
                    || quote! { None },
                    |storage| {
                        let storage = ConventionAdaptor::new(&storage).tokens();
                        quote! { Some(#storage) }
                    },
                );
                let second = second_storage.map_or_else(
                    || quote! { None },
                    |storage| {
                        let storage = ConventionAdaptor::new(&storage).tokens();
                        quote! { Some(#storage) }
                    },
                );
                quote! {
                    fugue_lifter_runtime::convention::PrototypeRuleAction::JoinDualClass {
                        storage: #storage,
                        first_storage: #first,
                        second_storage: #second,
                        stack_spill: #stack_spill,
                        fill_alternate: #fill_alternate,
                        reverse_justify: #reverse_justify,
                        reverse_significance: #reverse_significance,
                    }
                }
            }
            PrototypeRuleAction::JoinPerPrimitive { storage } => {
                let storage = storage.map_or_else(
                    || quote! { None },
                    |storage| {
                        let storage = ConventionAdaptor::new(&storage).tokens();
                        quote! { Some(#storage) }
                    },
                );
                quote! {
                    fugue_lifter_runtime::convention::PrototypeRuleAction::JoinPerPrimitive {
                        storage: #storage,
                    }
                }
            }
        }
    }
}

impl<'a> ConventionAdaptor<'a, PrototypeRule> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let rule = self.source;
        let killed = rule.killed_by_call();
        let conditions = rule
            .conditions()
            .iter()
            .map(|condition| ConventionAdaptor::new(condition).tokens());
        let actions = rule
            .actions()
            .iter()
            .map(|action| ConventionAdaptor::new(action).tokens());
        quote! {
            fugue_lifter_runtime::convention::PrototypeRule::new(
                #killed,
                &[#(#conditions),*],
                &[#(#actions),*],
            )
        }
    }
}

impl<'a> ConventionAdaptor<'a, Prototype> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let prototype = self.source;
        let name = prototype.name();
        let extra_pop = prototype.extra_pop();
        let stack_shift = prototype.stack_shift();
        let inputs = prototype
            .inputs()
            .iter()
            .map(|entry| ConventionAdaptor::new(entry).tokens());
        let outputs = prototype
            .outputs()
            .iter()
            .map(|entry| ConventionAdaptor::new(entry).tokens());
        let input_rules = prototype
            .input_rules()
            .iter()
            .map(|rule| ConventionAdaptor::new(rule).tokens());
        let output_rules = prototype
            .output_rules()
            .iter()
            .map(|rule| ConventionAdaptor::new(rule).tokens());
        let unaffected = prototype
            .unaffected()
            .iter()
            .map(|operand| ConventionAdaptor::new(operand).tokens());
        let killed = prototype
            .killed_by_call()
            .iter()
            .map(|operand| ConventionAdaptor::new(operand).tokens());
        let trashed = prototype
            .likely_trashed()
            .iter()
            .map(|operand| ConventionAdaptor::new(operand).tokens());
        quote! {
            fugue_lifter_runtime::convention::Prototype::new(#name, #extra_pop, #stack_shift)
                .with_inputs(&[#(#inputs),*])
                .with_outputs(&[#(#outputs),*])
                .with_input_rules(&[#(#input_rules),*])
                .with_output_rules(&[#(#output_rules),*])
                .with_unaffected(&[#(#unaffected),*])
                .with_killed_by_call(&[#(#killed),*])
                .with_likely_trashed(&[#(#trashed),*])
        }
    }
}

impl<'a> ConventionAdaptor<'a, DataOrganisation> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let data = self.source;
        let absolute_max_alignment = data.absolute_max_alignment();
        let machine_alignment = data.machine_alignment();
        let default_alignment = data.default_alignment();
        let default_pointer_alignment = data.default_pointer_alignment();
        let pointer_size = data.pointer_size();
        let pointer_shift = data.pointer_shift();
        let char_size = data.char_size();
        let char_signed = data.char_signed();
        let wchar_size = data.wchar_size();
        let short_size = data.short_size();
        let integer_size = data.integer_size();
        let long_size = data.long_size();
        let long_long_size = data.long_long_size();
        let float_size = data.float_size();
        let double_size = data.double_size();
        let long_double_size = data.long_double_size();
        let packing = data.bitfield_packing();
        let use_ms_convention = packing.use_ms_convention();
        let type_alignment_enabled = packing.type_alignment_enabled();
        let zero_length_boundary = packing.zero_length_boundary();
        let mut entries = data.alignments().collect::<Vec<_>>();
        entries.sort_unstable_by_key(|(size, _)| *size);
        let entries = entries.iter().map(|(size, alignment)| {
            quote! { (#size, #alignment) }
        });
        quote! {
            fugue_lifter_runtime::convention::DataOrganisation::new(&[#(#entries),*])
                .with_absolute_max_alignment(#absolute_max_alignment)
                .with_machine_alignment(#machine_alignment)
                .with_default_alignment(#default_alignment)
                .with_default_pointer_alignment(#default_pointer_alignment)
                .with_pointer_size(#pointer_size)
                .with_pointer_shift(#pointer_shift)
                .with_char_size(#char_size)
                .with_char_signed(#char_signed)
                .with_wchar_size(#wchar_size)
                .with_short_size(#short_size)
                .with_integer_size(#integer_size)
                .with_long_size(#long_size)
                .with_long_long_size(#long_long_size)
                .with_float_size(#float_size)
                .with_double_size(#double_size)
                .with_long_double_size(#long_double_size)
                .with_bitfield_packing(
                    fugue_lifter_runtime::convention::BitfieldPacking::new(
                        #use_ms_convention,
                        #type_alignment_enabled,
                        #zero_length_boundary,
                    ),
                )
        }
    }
}

impl<'a> ConventionAdaptor<'a, InjectPayload> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let payload = self.source;
        let body = payload
            .body()
            .map_or_else(|| quote! { None }, |body| quote! { Some(#body) });
        let parameter = |parameter: &InjectParameter| {
            let name = parameter.name();
            let size = parameter
                .size()
                .map_or_else(|| quote! { None }, |size| quote! { Some(#size) });
            quote! { fugue_lifter_runtime::convention::InjectParameter::new(#name, #size) }
        };
        let inputs = payload.inputs().iter().map(parameter);
        let outputs = payload.outputs().iter().map(parameter);
        let shift = payload.param_shift();
        let dynamic = payload.dynamic();
        let incidental = payload.incidental_copy();
        quote! {
            fugue_lifter_runtime::convention::InjectPayload::new(#body, &[#(#inputs),*], &[#(#outputs),*])
                .with_param_shift(#shift)
                .with_dynamic(#dynamic)
                .with_incidental_copy(#incidental)
        }
    }
}

impl<'a> ConventionAdaptor<'a, CallFixup> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let fixup = self.source;
        let name = fixup.name();
        let mut targets = fixup
            .targets()
            .iter()
            .map(|target| target.as_str())
            .collect::<Vec<_>>();
        targets.sort_unstable();
        let payload = ConventionAdaptor::new(fixup.payload()).tokens();
        quote! { fugue_lifter_runtime::convention::CallFixup::new(#name, &[#(#targets),*], #payload) }
    }
}

impl<'a> ConventionAdaptor<'a, UserOpFixup> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let fixup = self.source;
        let target = fixup.target_op();
        let target = target.as_str();
        let payload = ConventionAdaptor::new(fixup.payload()).tokens();
        quote! { fugue_lifter_runtime::convention::UserOpFixup::new(#target, #payload) }
    }
}

impl<'a> ConventionAdaptor<'a, Convention> {
    pub(crate) fn convention_tokens(&self) -> TokenStream {
        let convention = self.source;
        let name = convention.name();
        let stack_pointer = ConventionAdaptor::new(convention.stack_pointer().varnode()).tokens();
        let prototypes = convention
            .prototypes()
            .map(|prototype| ConventionAdaptor::new(prototype).tokens());
        let data = convention.data_organisation().map_or_else(
            || quote! { None },
            |data| {
                let data = ConventionAdaptor::new(data).tokens();
                quote! { Some(#data) }
            },
        );
        let alignment = convention
            .function_pointer_alignment()
            .map_or_else(|| quote! { None }, |alignment| quote! { Some(#alignment) });
        let fixups = convention
            .call_fixups()
            .iter()
            .map(|fixup| ConventionAdaptor::new(fixup).tokens());
        let user_ops = convention
            .user_op_fixups()
            .iter()
            .map(|fixup| ConventionAdaptor::new(fixup).tokens());
        let mut convention_tokens = quote! {
            fugue_lifter_runtime::convention::Convention::new(#name, #stack_pointer)
                .with_prototypes(&[#(#prototypes),*])
                .with_data_organisation(#data)
                .with_function_pointer_alignment(#alignment)
                .with_call_fixups(&[#(#fixups),*])
                .with_user_op_fixups(&[#(#user_ops),*])
        };
        if let Some(address) = convention.return_address() {
            let address = match address {
                ReturnAddress::Register { varnode, .. } => {
                    let varnode = ConventionAdaptor::new(varnode).tokens();
                    quote! { fugue_lifter_runtime::convention::ReturnAddress::Register(#varnode) }
                }
                ReturnAddress::StackRelative { offset, size } => {
                    quote! {
                        fugue_lifter_runtime::convention::ReturnAddress::StackRelative {
                            offset: #offset,
                            size: #size,
                        }
                    }
                }
            };
            convention_tokens = quote! { #convention_tokens.with_return_address(#address) };
        }
        convention_tokens
    }
}
