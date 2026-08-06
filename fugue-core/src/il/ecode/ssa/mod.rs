mod builder;
mod constants;
mod def_use;
mod evaluate;
mod format;
mod intervals;
mod ir;
mod liveness;
mod memory;
mod opcode;
mod operation;
mod optimise;
mod transform;
mod value;
mod verify;

pub(crate) use builder::ECodeSsaBuilder;
pub(crate) use constants::ECodeSsaConstantInterner;
pub use def_use::{ECodeSsaBlockArgumentInputs, ECodeSsaUse, ECodeSsaUses};
pub use format::{ECodeSsaIrDisplay, ECodeSsaSourceDisplay};
pub use intervals::ECodeSsaStridedIntervals;
pub use ir::ECodeSsaIr;
pub use liveness::ECodeSsaLiveness;
pub use memory::ECodeSsaMemoryDomain;
pub use opcode::ECodeSsaOpcode;
pub use operation::ECodeSsaOp;
pub(crate) use optimise::ECodeSsaOptimiser;
pub use transform::ECodeToSsa;
pub use value::{ECodeSsaBlockArg, ECodeSsaValue, ECodeSsaValueKind};

use crate::il::common::{IlGraph, IlIndexRange, IlMetadata, IlParentSpan, IlSourceSpan, IlValueId};

pub(crate) struct ECodeSsaBuilderContext {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    values: Vec<ECodeSsaValue>,
    block_arguments: Vec<ECodeSsaBlockArg>,
    edge_arguments: Vec<IlIndexRange>,
    edge_argument_values: Vec<IlValueId>,
    operations: Vec<ECodeSsaOp>,
    value_operands: Vec<IlValueId>,
    memory_domains: Vec<ECodeSsaMemoryDomain>,
    constant_storage: Vec<u8>,
}

#[cfg(test)]
mod test;
