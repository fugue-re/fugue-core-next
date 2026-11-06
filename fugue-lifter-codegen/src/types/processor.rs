use std::ops::RangeInclusive;

use fugue_sleigh_language::float_format::FloatFormat;
use fugue_sleigh_language::processor::{
    ContextSet, DefaultSymbol, DefaultSymbolAddress, DefaultSymbolKind, Processor, RegisterLanes,
    SegmentOp, SegmentedAddressSpace, SegmentedAddressSpaceKind, StorageLocation, TrackedSet,
    VolatileRange,
};
use itertools::Itertools;
use proc_macro2::TokenStream;
use quote::quote;

use crate::types::convention::ConventionAdaptor;

pub(crate) struct ProcessorAdaptor<'a, T> {
    source: &'a T,
}

impl<'a, T> ProcessorAdaptor<'a, T> {
    pub(crate) fn new(source: &'a T) -> Self {
        Self { source }
    }
}

impl<'a> ProcessorAdaptor<'a, RangeInclusive<u64>> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let range = self.source;
        let first = range.start();
        let last = range.end();
        quote! { #first..=#last }
    }
}

impl<'a> ProcessorAdaptor<'a, ContextSet> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let set = self.source;
        let space = u8::try_from(set.space().index()).expect("address-space identifier fits in u8");
        let range = set.range().map_or_else(
            || quote! { None },
            |range| {
                let range = ProcessorAdaptor::new(range).tokens();
                quote! { Some(#range) }
            },
        );
        let updates = set.updates().iter().map(|update| {
            let name = update.name();
            let name = name.as_str();
            let value = update.value();
            let description = update.description().map_or_else(
                || quote! { None },
                |description| quote! { Some(#description) },
            );
            quote! {
                fugue_lifter_runtime::processor::ContextUpdate::new(#name, #value)
                    .with_description(#description)
            }
        });
        quote! { fugue_lifter_runtime::processor::ContextSet::new(#space, #range, &[#(#updates),*]) }
    }
}

impl<'a> ProcessorAdaptor<'a, TrackedSet> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let set = self.source;
        let space = u8::try_from(set.space().index()).expect("address-space identifier fits in u8");
        let range = set.range().map_or_else(
            || quote! { None },
            |range| {
                let range = ProcessorAdaptor::new(range).tokens();
                quote! { Some(#range) }
            },
        );
        let updates = set.updates().iter().map(|update| {
            let register = ConventionAdaptor::new(update.register()).tokens();
            let value = update.value();
            let description = update.description().map_or_else(
                || quote! { None },
                |description| quote! { Some(#description) },
            );
            quote! {
                fugue_lifter_runtime::processor::TrackedSetUpdate::new(#register, #value)
                    .with_description(#description)
            }
        });
        quote! { fugue_lifter_runtime::processor::TrackedSet::new(#space, #range, &[#(#updates),*]) }
    }
}

impl<'a> ProcessorAdaptor<'a, VolatileRange> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let volatile = self.source;
        let location = ProcessorAdaptor::new(volatile.location()).tokens();
        let read_op = volatile.read_op();
        let write_op = volatile.write_op();
        let read_op = read_op.as_str();
        let write_op = write_op.as_str();
        let format = volatile
            .format()
            .map_or_else(|| quote! { None }, |format| quote! { Some(#format) });
        quote! {
            fugue_lifter_runtime::processor::VolatileRange::new(#location, #read_op, #write_op)
                .with_format(#format)
        }
    }
}

impl<'a> ProcessorAdaptor<'a, RegisterLanes> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let lanes = self.source;
        let register = ConventionAdaptor::new(lanes.register()).tokens();
        let sizes = lanes.sizes();
        quote! { fugue_lifter_runtime::processor::RegisterLanes::new(#register, &[#(#sizes),*]) }
    }
}

impl<'a> ProcessorAdaptor<'a, DefaultSymbol> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let symbol = self.source;
        let name = symbol.name();
        let address = match symbol.address() {
            DefaultSymbolAddress::Absolute { space, offset } => {
                let space =
                    u8::try_from(space.index()).expect("address-space identifier fits in u8");
                quote! {
                    fugue_lifter_runtime::processor::DefaultSymbolAddress::Absolute {
                        space: #space,
                        offset: #offset,
                    }
                }
            }
            DefaultSymbolAddress::Next => {
                quote! { fugue_lifter_runtime::processor::DefaultSymbolAddress::Next }
            }
        };
        let entry = symbol.entry();
        let size = symbol
            .size()
            .map_or_else(|| quote! { None }, |size| quote! { Some(#size) });
        let volatile = symbol
            .volatile()
            .map_or_else(|| quote! { None }, |volatile| quote! { Some(#volatile) });
        let description = symbol.description().map_or_else(
            || quote! { None },
            |description| quote! { Some(#description) },
        );
        let kind = symbol.kind().map_or_else(
            || quote! { None },
            |kind| {
                let kind = match kind {
                    DefaultSymbolKind::Code => {
                        quote! { fugue_lifter_runtime::processor::DefaultSymbolKind::Code }
                    }
                    DefaultSymbolKind::CodePointer => {
                        quote! { fugue_lifter_runtime::processor::DefaultSymbolKind::CodePointer }
                    }
                };
                quote! { Some(#kind) }
            },
        );
        quote! {
            fugue_lifter_runtime::processor::DefaultSymbol::new(#name, #address)
                .with_entry(#entry)
                .with_kind(#kind)
                .with_size(#size)
                .with_volatile(#volatile)
                .with_description(#description)
        }
    }
}

impl<'a> ProcessorAdaptor<'a, Processor> {
    pub(crate) fn processor_tokens(&self) -> TokenStream {
        let processor = self.source;
        let contexts = processor
            .context_sets()
            .iter()
            .map(|set| ProcessorAdaptor::new(set).tokens());
        let tracked = processor
            .tracked_sets()
            .iter()
            .map(|set| ProcessorAdaptor::new(set).tokens());
        let volatile = processor
            .volatile_ranges()
            .iter()
            .map(|volatile| ProcessorAdaptor::new(volatile).tokens());
        let lanes = processor
            .register_lanes()
            .iter()
            .map(|lanes| ProcessorAdaptor::new(lanes).tokens());
        let symbols = processor
            .default_symbols()
            .iter()
            .map(|symbol| ProcessorAdaptor::new(symbol).tokens());
        let properties = processor
            .properties()
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .sorted_unstable_by_key(|(key, _)| *key)
            .map(|(key, value)| quote! { (#key, #value) });
        let segment_ops = processor
            .segment_ops()
            .iter()
            .map(|operation| ProcessorAdaptor::new(operation).tokens());
        let segmented_address_space = processor.segmented_address_space().map_or_else(
            || quote! { None },
            |address| {
                let address = ProcessorAdaptor::new(address).tokens();
                quote! { Some(#address) }
            },
        );
        quote! {
            const CONTEXT_SETS: &'static [fugue_lifter_runtime::processor::ContextSet] =
                &[#(#contexts),*];
            const TRACKED_SETS: &'static [fugue_lifter_runtime::processor::TrackedSet] =
                &[#(#tracked),*];
            const VOLATILE_RANGES: &'static [fugue_lifter_runtime::processor::VolatileRange] =
                &[#(#volatile),*];
            const REGISTER_LANES: &'static [fugue_lifter_runtime::processor::RegisterLanes] =
                &[#(#lanes),*];
            const PROPERTIES: &'static [(&'static str, &'static str)] = &[#(#properties),*];
            const SEGMENT_OPS: &'static [fugue_lifter_runtime::processor::SegmentOp] = &[#(#segment_ops),*];
            const SEGMENTED_ADDRESS_SPACE: Option<fugue_lifter_runtime::processor::SegmentedAddressSpace> = #segmented_address_space;
            const DEFAULT_SYMBOLS: &'static [fugue_lifter_runtime::processor::DefaultSymbol] =
                &[#(#symbols),*];
        }
    }
}

pub(crate) struct FloatFormatAdaptor<'a> {
    format: &'a FloatFormat,
}

impl<'a> FloatFormatAdaptor<'a> {
    pub(crate) fn new(format: &'a FloatFormat) -> Self {
        Self { format }
    }

    pub(crate) fn float_format_tokens(&self) -> TokenStream {
        let format = self.format;
        let size = format.size;
        let sign_pos = format.sign_pos;
        let frac_pos = format.frac_pos;
        let frac_size = format.frac_size;
        let exp_pos = format.exp_pos;
        let exp_max = format.exp_max;
        let exp_size = format.exp_size;
        let bias = format.bias;
        let j_bit_implied = format.j_bit_implied;
        quote! {
            fugue_lifter_runtime::FloatFormat {
                size: #size,
                sign_pos: #sign_pos,
                frac_pos: #frac_pos,
                frac_size: #frac_size,
                exp_pos: #exp_pos,
                exp_max: #exp_max,
                exp_size: #exp_size,
                bias: #bias,
                j_bit_implied: #j_bit_implied,
            }
        }
    }
}

impl<'a> ProcessorAdaptor<'a, StorageLocation> {
    pub(crate) fn tokens(&self) -> TokenStream {
        match self.source {
            StorageLocation::Range { space, range } => {
                let space =
                    u8::try_from(space.index()).expect("address-space identifier fits in u8");
                let range = range.as_ref().map_or_else(
                    || quote! { None },
                    |range| {
                        let range = ProcessorAdaptor::new(range).tokens();
                        quote! { Some(#range) }
                    },
                );
                quote! {
                    fugue_lifter_runtime::processor::StorageLocation::Range {
                        space: #space,
                        range: #range,
                    }
                }
            }
            StorageLocation::StackRelative { range } => {
                let range = range.as_ref().map_or_else(
                    || quote! { None },
                    |range| {
                        let range = ProcessorAdaptor::new(range).tokens();
                        quote! { Some(#range) }
                    },
                );
                quote! { fugue_lifter_runtime::processor::StorageLocation::StackRelative { range: #range } }
            }
            StorageLocation::Register(register) => {
                let register = ConventionAdaptor::new(register).tokens();
                quote! { fugue_lifter_runtime::processor::StorageLocation::Register(#register) }
            }
        }
    }
}

impl<'a> ProcessorAdaptor<'a, SegmentedAddressSpace> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let address = self.source;
        let space =
            u8::try_from(address.space().index()).expect("address-space identifier fits in u8");
        let kind = match address.kind() {
            SegmentedAddressSpaceKind::Protected => {
                quote! { fugue_lifter_runtime::processor::SegmentedAddressSpaceKind::Protected }
            }
            SegmentedAddressSpaceKind::Real => {
                quote! { fugue_lifter_runtime::processor::SegmentedAddressSpaceKind::Real }
            }
        };
        quote! { fugue_lifter_runtime::processor::SegmentedAddressSpace::new(#space, #kind) }
    }
}

impl<'a> ProcessorAdaptor<'a, SegmentOp> {
    pub(crate) fn tokens(&self) -> TokenStream {
        let operation = self.source;
        let space =
            u8::try_from(operation.space().index()).expect("address-space identifier fits in u8");
        let user_op = operation.user_op();
        let user_op = user_op.as_str();
        let payload = ConventionAdaptor::new(operation.payload()).tokens();
        let far_pointer = operation.far_pointer();
        let constant_resolver = operation.constant_resolver().map_or_else(
            || quote! { None },
            |storage| {
                let storage = ConventionAdaptor::new(storage).tokens();
                quote! { Some(#storage) }
            },
        );
        quote! {
            fugue_lifter_runtime::processor::SegmentOp::new(#space, #user_op, #payload)
                .with_far_pointer(#far_pointer)
                .with_constant_resolver(#constant_resolver)
        }
    }
}
