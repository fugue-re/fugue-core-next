use fugue_bv::BitVec;
use smallvec::SmallVec;

use crate::analysis::AnalysisError;
use crate::engine::{AnalyserProvider, AnalysisContext};
use crate::extension;
use crate::il::common::{IlAnalyser, IlSourceSpan};
use crate::il::pcode::{PCodeIr, PCodeLocation, PCodeLocationId, PCodeOpcode};
use crate::ir::{
    Address, AddressRangeSet, FunctionId, Reference, ReferenceKind, ReferenceOrigin,
    ReferenceProperties, ReferenceProvenance,
};
use crate::project::{AnalysisPhase, ChangeKinds, Project};
use crate::storage::{SegmentMappingCache, SegmentMappingProvenance};

struct PCodeReferenceAnalyser {
    address_size: usize,
}

impl PCodeReferenceAnalyser {
    fn data_references<'a>(&self, pcode: &'a PCodeIr) -> impl Iterator<Item = Reference> + 'a {
        let address_size = self.address_size;
        pcode.graph().blocks().iter().flat_map(move |block| {
            let mut values = SmallVec::<[(PCodeLocationId, &PCodeLocation, BitVec); 8]>::new();
            let mut stored = None::<(PCodeLocationId, BitVec)>;
            let mut span = None::<IlSourceSpan>;

            (block.ops().start()..block.ops().end()).flat_map(move |index| {
                let mut references = SmallVec::<[Reference; 4]>::new();
                let Some(operation) = pcode.ops().get(index) else {
                    return references;
                };
                if !span.is_some_and(|span| span.contains_destination(index)) {
                    span = pcode.source_span_for(index);
                }
                let Some(span) = span else {
                    return references;
                };
                let source = span.address();
                let operands = pcode.op_operands_for(operation);
                let value =
                    |id: PCodeLocationId, values: &[(PCodeLocationId, &PCodeLocation, BitVec)]| {
                        let location = pcode.location(id)?;
                        if location.is_constant() {
                            Some(BitVec::from_u64(location.offset(), location.bits()))
                        } else {
                            values
                                .iter()
                                .find(|(tracked, _, _)| *tracked == id)
                                .map(|(_, _, value)| value.clone())
                        }
                    };

                let reads = match operation.opcode() {
                    PCodeOpcode::Branch | PCodeOpcode::CBranch | PCodeOpcode::Call => &[][..],
                    _ => operands,
                };
                let accesses = reads
                    .iter()
                    .map(|&id| (id, ReferenceProperties::READ))
                    .chain(
                        operation
                            .output()
                            .map(|id| (id, ReferenceProperties::WRITE)),
                    );
                for (id, properties) in accesses {
                    if let Some(location) =
                        pcode.location(id).filter(|location| location.is_memory())
                    {
                        references.push(
                            Reference::data(
                                source,
                                Address::new(source.space(), location.offset()),
                                properties,
                            )
                            .with_origin(ReferenceOrigin::Derived),
                        );
                    }
                }

                let mut result = None;
                match operation.opcode() {
                    PCodeOpcode::Load | PCodeOpcode::Store => {
                        let Some(&pointer) = operands.first() else {
                            return references;
                        };
                        let target = value(pointer, &values).and_then(|target| target.to_u64());
                        if let (Some(target), Some(space)) = (target, operation.address_space()) {
                            let properties = if operation.opcode() == PCodeOpcode::Load {
                                ReferenceProperties::READ
                            } else {
                                ReferenceProperties::WRITE
                            };
                            references.push(
                                Reference::data(source, Address::new(space, target), properties)
                                    .with_origin(ReferenceOrigin::Derived),
                            );
                        }
                        if operation.opcode() == PCodeOpcode::Load {
                            result = stored
                                .as_ref()
                                .filter(|(location, _)| *location == pointer)
                                .map(|(_, value)| value.clone());
                        } else {
                            stored = operands
                                .get(1)
                                .and_then(|&stored| value(stored, &values))
                                .map(|value| (pointer, value));
                        }
                    }
                    PCodeOpcode::Call | PCodeOpcode::ICall | PCodeOpcode::UserOp => {
                        values.clear();
                        stored = None;
                    }
                    opcode => {
                        if let Some(output) = operation.output().and_then(|id| pcode.location(id)) {
                            let mut inputs = SmallVec::<[BitVec; 2]>::new();
                            for &id in operands {
                                let Some(input) = value(id, &values) else {
                                    break;
                                };
                                inputs.push(input);
                            }
                            if inputs.len() == operands.len() {
                                result = opcode.evaluate(output.bits(), &inputs);
                            }
                        }
                    }
                }

                let Some(output_id) = operation.output() else {
                    return references;
                };
                let Some(output) = pcode.location(output_id) else {
                    return references;
                };
                if !values.is_empty() {
                    values.retain(|(_, location, _)| !location.overlaps(output));
                }
                if stored.as_ref().is_some_and(|(pointer, _)| {
                    pcode
                        .location(*pointer)
                        .is_none_or(|location| location.overlaps(output))
                }) {
                    stored = None;
                }
                if !(output.is_register() || output.is_unique()) {
                    return references;
                }
                let Some(result) = result else {
                    return references;
                };
                if output.is_register()
                    && usize::from(output.size()) == address_size
                    && let Some(target) = result.to_u64()
                    && !span
                        .destination()
                        .slice(pcode.ops())
                        .iter()
                        .any(|operation| {
                            matches!(operation.opcode(), PCodeOpcode::Call | PCodeOpcode::ICall)
                        })
                {
                    references.push(
                        Reference::data(
                            source,
                            Address::new(source.space(), target),
                            ReferenceProperties::empty(),
                        )
                        .with_origin(ReferenceOrigin::Derived),
                    );
                }
                values.push((output_id, output, result));
                references
            })
        })
    }
}

impl IlAnalyser for PCodeReferenceAnalyser {
    const NAME: &'static str = "pcode-references";
    type Input = PCodeIr;

    fn build(project: &Project) -> Result<Self, AnalysisError> {
        Ok(Self {
            address_size: project.language().address_size(),
        })
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::empty()
    }

    fn phase(&self) -> AnalysisPhase {
        AnalysisPhase::Derive
    }

    fn can_analyse(&self, _project: &Project) -> bool {
        true
    }

    fn analyse(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        function: FunctionId,
        pcode: &PCodeIr,
    ) -> Result<(), AnalysisError> {
        let project = &context.project;
        let mut coverage = AddressRangeSet::new();
        pcode.reference_coverage_into(&mut coverage);

        let segments = project.segments();
        let mut mapping_cache = SegmentMappingCache::new();
        let references = self
            .data_references(pcode)
            .filter(|reference| {
                if reference.is_read() || reference.is_write() {
                    return true;
                }
                let Some(target) = reference.target().address() else {
                    return false;
                };
                let Some(view) = mapping_cache.view_containing(segments, target) else {
                    return false;
                };
                // NOTE:
                // 1. When the image has section headers, they mark where real code and data live.
                //    An address-sized constant pointing into mapped memory that no section covers,
                //    such as ELF headers or padding between segments, is almost never a real
                //    pointer, so we drop it.
                // 2. When the image has no section headers (stripped, or a raw image), that test
                //    isn't available, so we accept any constant that points into mapped memory.
                if view.provenance() == SegmentMappingProvenance::Section {
                    return true;
                }
                segments.iter_views(target.space()).is_ok_and(|mut views| {
                    views.all(|view| view.provenance() != SegmentMappingProvenance::Section)
                })
            })
            .collect();

        context.updates.replace_derived_references(
            coverage,
            ReferenceKind::Data,
            ReferenceProvenance::Function(function),
            references,
        );
        Ok(())
    }

    fn produces(&self) -> ChangeKinds {
        ChangeKinds::REFERENCES
    }
}

extension::submit! {
    AnalyserProvider::for_il::<PCodeReferenceAnalyser>()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{IlBlock, IlBlockProperties, IlGraph, IlIndexRange, IlMetadata};
    use crate::il::pcode::{
        PCodeBuilder, PCodeLifterSpaceHandle, PCodeLocationProperties, PCodeOpSpec,
    };
    use crate::lifter::{Varnode, resolve_language};
    use crate::storage::segments::space::AddressSpaceId;

    fn analyser() -> PCodeReferenceAnalyser {
        PCodeReferenceAnalyser { address_size: 8 }
    }

    #[test]
    fn pcode_ir_derives_constant_data_references() {
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let data_space = AddressSpaceId::new(2);
        let data = 0x4000u64;
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 2).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            )],
            Vec::new(),
            Vec::new(),
        );
        let mut builder = PCodeBuilder::new(IlMetadata::new(FunctionId::default(), 0), graph);

        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            source,
            0,
            2,
        )]);
        let pointer = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                data,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let value = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                0,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Load).with_address_space(data_space),
                Some(value),
                [pointer],
            )
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Store).with_address_space(data_space),
                None,
                [pointer, value],
            )
            .unwrap();

        let ir = builder.build().unwrap();
        let references = analyser().data_references(&ir).collect::<Vec<_>>();

        assert_eq!(references.len(), 2);
        assert!(references[0].is_read());
        assert_eq!(references[0].from(), source);
        assert_eq!(
            references[0].target().address(),
            Some(Address::new(data_space, data))
        );
        assert!(references[0].origin().is_derived());
        assert!(references[1].is_write());
        assert_eq!(
            references[1].target().address(),
            Some(Address::new(data_space, data))
        );
    }

    #[test]
    fn pcode_ir_ignores_non_constant_data_references() {
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let data_space = AddressSpaceId::new(2);
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            )],
            Vec::new(),
            Vec::new(),
        );
        let mut builder = PCodeBuilder::new(IlMetadata::new(FunctionId::default(), 0), graph);

        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 1).unwrap(),
            source,
            0,
            1,
        )]);
        let pointer = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                0x20,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                0,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Load).with_address_space(data_space),
                Some(output),
                [pointer],
            )
            .unwrap();

        let ir = builder.build().unwrap();

        assert!(analyser().data_references(&ir).next().is_none());
    }

    #[test]
    fn data_references_from_constant_pointer() -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let default_space = language.default_space();
        let insn_address = Address::new(AddressSpaceId::from(0u16), 0x1000u64);
        let data_space = insn_address.space();
        let data_address = 0x4000u64;
        let register_value = Varnode::new(language.register_space(), 0, 8);
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = PCodeBuilder::new(
            metadata,
            IlGraph::new(
                vec![IlBlock::new(
                    IlIndexRange::new(0, 2)?,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                )],
                Vec::new(),
                Vec::new(),
            ),
        );
        {
            let mut emitter = builder.emitter();
            let pointer = emitter.intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(data_address, 8),
            ))?;
            let register =
                emitter.intern_location(PCodeLocation::from_varnode(language, &register_value))?;
            emitter.emit(
                PCodeOpSpec::new(PCodeOpcode::Load)
                    .with_immediate(u32::from(default_space))
                    .with_address_space(data_space),
                Some(register),
                [pointer],
            )?;
            emitter.emit(
                PCodeOpSpec::new(PCodeOpcode::Store)
                    .with_immediate(u32::from(default_space))
                    .with_address_space(data_space),
                None,
                [pointer, register],
            )?;
        }
        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            insn_address,
            0,
            2,
        )]);
        let ir = builder.build()?;
        let artefact_refs = analyser().data_references(&ir).collect::<Vec<_>>();

        assert_eq!(artefact_refs.len(), 2);
        assert_eq!(artefact_refs[0].from(), insn_address);
        assert_eq!(
            artefact_refs[0].target().address(),
            Some(Address::new(data_space, data_address))
        );
        assert!(artefact_refs[0].is_read());
        assert!(artefact_refs[0].origin().is_derived());
        assert_eq!(artefact_refs[1].from(), insn_address);
        assert!(artefact_refs[1].is_write());
        assert_eq!(
            artefact_refs[1].target().address(),
            Some(Address::new(data_space, data_address))
        );

        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = PCodeBuilder::new(metadata, IlGraph::default());
        {
            let mut emitter = builder.emitter();
            let pointer = emitter.intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.register_space(), 0x20, 8),
            ))?;
            let output = emitter.intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.register_space(), 0, 8),
            ))?;
            emitter.emit(
                PCodeOpSpec::new(PCodeOpcode::Load)
                    .with_immediate(u32::from(default_space))
                    .with_address_space(data_space),
                Some(output),
                [pointer],
            )?;
        }
        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 1).unwrap(),
            insn_address,
            0,
            1,
        )]);
        let ir = builder.build()?;
        assert!(analyser().data_references(&ir).next().is_none());

        Ok(())
    }
}
