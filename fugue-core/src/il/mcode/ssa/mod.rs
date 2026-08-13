use crate::il::common::{IlGraph, IlIndexRange, IlMetadata, IlParentSpan, IlSourceSpan, IlValueId};
use crate::il::mcode::{MCodeVar, MCodeVarId};

mod analysis;
mod builder;
mod format;
mod ir;
mod memory;
mod opcode;
mod operation;
mod optimise;
mod value;
mod verify;

pub use analysis::{MCodeSsaBlockArgInputs, MCodeSsaUse, MCodeSsaUses};
pub(crate) use builder::MCodeSsaBuilder;
pub use format::{MCodeSsaIrDisplay, MCodeSsaSourceDisplay};
pub use ir::MCodeSsaIr;
pub use memory::MCodeSsaMemoryDomain;
pub use opcode::MCodeSsaOpcode;
pub use operation::MCodeSsaOp;
pub(crate) use optimise::MCodeSsaOptimiser;
pub use value::{MCodeSsaBinding, MCodeSsaBlockArg, MCodeSsaValue, MCodeSsaVersion};

pub(crate) struct MCodeSsaBuilderContext {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    variables: Vec<MCodeVar>,
    aliased_variables: Vec<MCodeVarId>,
    values: Vec<MCodeSsaValue>,
    block_arguments: Vec<MCodeSsaBlockArg>,
    edge_arguments: Vec<IlIndexRange>,
    edge_argument_values: Vec<IlValueId>,
    operations: Vec<MCodeSsaOp>,
    value_operands: Vec<IlValueId>,
    memory_domains: Vec<MCodeSsaMemoryDomain>,
    constant_storage: Vec<u8>,
}

#[cfg(test)]
mod test;
